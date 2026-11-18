"""Live runtime holder for the API: owns the UDP telemetry service and keystore.

The API never fabricates live telemetry. Before ``POST /api/v1/live/start`` the
runtime reports ``STOPPED`` / ``DISCONNECTED``; after start it reports what the
real collector, streaming pipeline and model registry produced.

The runtime also exposes the persisted 16-D behavioral vectors for read-only
inspection. Vector payloads are decrypted only when explicitly requested by id;
list responses contain metadata and ciphertext stays in the database.
"""

from __future__ import annotations

import hashlib
import json
import math
import shutil
import sqlite3
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from network_anomaly.behavioral.correlation import IPSpoofingSessionCorrelator
from network_anomaly.behavioral.similarity import BehavioralSimilarityCalculator
from network_anomaly.behavioral.vector import BehavioralVector, BehavioralVectorBuilder
from network_anomaly.crypto.key_manager import KeyManager, KeyStorageError
from network_anomaly.crypto.rotation import KeyRotationPolicy
from network_anomaly.ml.ood_gate import resolve_expected_ood_gate_sha256
from network_anomaly.streaming.realtime_inference import resolve_runtime_policy

DISCONNECTED = "DISCONNECTED"
CONNECTED = "CONNECTED"
EMPTY = "EMPTY"
ERROR = "ERROR"
DEMO = "DEMO"

_PLACEHOLDER_INFERENCE: Dict[str, Any] = {
    "inference_mode": "UNKNOWN",
    "ai_ready": False,
    "ready_count": 0,
    "validated_count": 0,
    "cross_source_validated_count": 0,
    "production_ready": False,
    "models": [],
    "ood_gate_status": "NOT_FITTED",
}


class LiveRuntime:
    """Thread-safe owner of a :class:`LiveTelemetryService` and its keystore."""

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        keystore_dir: Optional[Path] = None,
        *,
        runtime_mode: Optional[str] = None,
        require_ood_gate: Optional[bool] = None,
        expected_ood_gate_sha256: Optional[str] = None,
    ):
        self.db_path = db_path
        self.keystore_dir = Path(keystore_dir) if keystore_dir else None
        self.runtime_mode, self.require_ood_gate, self.runtime_policy_source = (
            resolve_runtime_policy(runtime_mode, require_ood_gate)
        )
        self.expected_ood_gate_sha256 = (
            expected_ood_gate_sha256.strip().lower()
            if isinstance(expected_ood_gate_sha256, str) and expected_ood_gate_sha256.strip()
            else expected_ood_gate_sha256
        )
        self._service = None
        self._key_manager: Optional[KeyManager] = None
        self._lock = threading.RLock()
        self._last_error: Optional[str] = None
        self._demo_mode = False
        self._active_policy: Optional[tuple[str, bool, Optional[str]]] = None
        self._temp_dir: Optional[Path] = None
        if self.keystore_dir is None:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="nf-sentinel-api-keystore-"))
            self.keystore_dir = self._temp_dir

    # ------------------------------------------------------------- helpers
    def _effective_start_policy(
        self,
        runtime_mode: Optional[str] = None,
        require_ood_gate: Optional[bool] = None,
        expected_ood_gate_sha256: Optional[str] = None,
    ) -> tuple[str, bool, Optional[str]]:
        if runtime_mode is not None:
            requested_mode, requested_require, _ = resolve_runtime_policy(
                runtime_mode, require_ood_gate
            )
            if self.runtime_mode == "deployment" and requested_mode != "deployment":
                raise ValueError(
                    "Cannot downgrade LiveRuntime from 'deployment' mode to 'research' mode"
                )
            eff_mode = requested_mode
            eff_require = requested_require
        else:
            eff_mode = self.runtime_mode
            if require_ood_gate is not None:
                if eff_mode == "deployment" and require_ood_gate is False:
                    raise ValueError(
                        "require_ood_gate cannot be False when runtime_mode='deployment'"
                    )
                eff_require = bool(require_ood_gate)
            else:
                eff_require = self.require_ood_gate

        eff_sha = self.expected_ood_gate_sha256
        if expected_ood_gate_sha256 is not None:
            norm_arg = (
                expected_ood_gate_sha256.strip().lower()
                if isinstance(expected_ood_gate_sha256, str)
                else expected_ood_gate_sha256
            )
            if (
                self.expected_ood_gate_sha256 is not None
                and norm_arg != self.expected_ood_gate_sha256
            ):
                raise ValueError(
                    "Cannot override configured expected_ood_gate_sha256 on LiveRuntime.start()"
                )
            eff_sha = norm_arg
        return eff_mode, eff_require, eff_sha

    @property
    def sqlite_path(self) -> Optional[Path]:
        if self.db_path in (None, ":memory:"):
            return None
        return Path(self.db_path)

    def key_manager(self) -> KeyManager:
        with self._lock:
            if self._service is not None:
                return self._service.orchestrator.key_manager
            if self._key_manager is None:
                self._key_manager = KeyManager(keystore_dir=self.keystore_dir)
            return self._key_manager

    def active_key_rotator(self) -> Optional[KeyRotationPolicy]:
        with self._lock:
            if self._service is not None:
                return self._service.orchestrator.key_rotator
            return None

    # ----------------------------------------------------------- lifecycle
    def start(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        demo_heuristics: bool = False,
        queue_capacity: int = 10_000,
        batch_size: int = 32,
        runtime_mode: Optional[str] = None,
        require_ood_gate: Optional[bool] = None,
        expected_ood_gate_sha256: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start the real UDP collector and processing worker."""
        eff_mode, eff_require, eff_sha = self._effective_start_policy(
            runtime_mode=runtime_mode,
            require_ood_gate=require_ood_gate,
            expected_ood_gate_sha256=expected_ood_gate_sha256,
        )
        requested_policy = (eff_mode, eff_require, eff_sha)
        with self._lock:
            if self._service is not None and self._service.is_running:
                return self.status()
            if self._service is not None and (
                demo_heuristics != self._demo_mode or requested_policy != self._active_policy
            ):
                # Mode or policy cannot change in place; discard the previous stopped
                # service and start a fresh one.
                self._service = None
            if self._service is None:
                from network_anomaly.streaming.live_service import LiveTelemetryService

                self._service = LiveTelemetryService(
                    host=host,
                    port=port,
                    db_path=self.sqlite_path,
                    keystore_dir=self.keystore_dir,
                    demo_heuristics=demo_heuristics,
                    runtime_mode=eff_mode,
                    require_ood_gate=eff_require,
                    expected_ood_gate_sha256=eff_sha,
                    queue_capacity=queue_capacity,
                    batch_size=batch_size,
                )
                self._demo_mode = demo_heuristics
                self._active_policy = requested_policy
            try:
                self._service.start()
                self._last_error = None
            except Exception as exc:  # bind/keystore failures are reported, not hidden
                self._last_error = f"{type(exc).__name__}: {exc}"
                raise
            return self.status()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if self._service is None:
                return self.status()
            try:
                self._service.stop()
            except Exception as exc:  # pragma: no cover - defensive
                self._last_error = f"{type(exc).__name__}: {exc}"
            return self.status()

    def shutdown(self) -> None:
        """Stop threads and remove a temporary keystore."""
        try:
            self.stop()
        finally:
            if self._temp_dir is not None:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
                self._temp_dir = None

    # -------------------------------------------------------------- status
    def _prestart_inference_status(self) -> Dict[str, Any]:
        info = dict(_PLACEHOLDER_INFERENCE)
        info["runtime_mode"] = self.runtime_mode
        info["runtime_policy_source"] = self.runtime_policy_source
        info["require_ood_gate"] = self.require_ood_gate
        try:
            resolved_sha, trust_source = resolve_expected_ood_gate_sha256(
                self.expected_ood_gate_sha256
            )
            info["expected_ood_gate_sha256_configured"] = bool(resolved_sha)
            if self.require_ood_gate and resolved_sha is None:
                info["ood_gate_trust_anchor"] = "missing_trusted_expected_sha256"
                info["ood_gate_status"] = "ERROR"
                info["ood_gate_error"] = (
                    "Trusted expected_ood_gate_sha256 (or NETFLOW_OOD_GATE_SHA256) is required "
                    "in deployment mode"
                )
                info["inference_mode"] = "UNAVAILABLE"
            else:
                info["ood_gate_trust_anchor"] = trust_source or "none"
                info["ood_gate_error"] = None
        except Exception as exc:
            info["expected_ood_gate_sha256_configured"] = False
            info["ood_gate_trust_anchor"] = "invalid_expected_sha256"
            info["ood_gate_status"] = "ERROR"
            info["ood_gate_error"] = f"{type(exc).__name__}: {exc}"
            info["inference_mode"] = "UNAVAILABLE"
        return info

    def status(self) -> Dict[str, Any]:
        with self._lock:
            service = self._service
            if service is None:
                return {
                    "mode": "STOPPED",
                    "running": False,
                    "data_status": ERROR if self._last_error else DISCONNECTED,
                    "bound_port": None,
                    "started_at_utc": None,
                    "collector": {},
                    "pipeline": {},
                    "metrics": {},
                    "inference": self._prestart_inference_status(),
                    "demo_mode": False,
                    "persistence_enabled": self.sqlite_path is not None,
                    "last_error": self._last_error,
                }
            payload = service.status()
        running = bool(payload.get("running"))
        processed = int(payload.get("metrics", {}).get("events_processed", 0))
        if not running:
            data_status = ERROR if self._last_error else DISCONNECTED
        elif self._demo_mode:
            data_status = DEMO
        elif processed > 0:
            data_status = CONNECTED
        else:
            data_status = EMPTY
        payload["data_status"] = data_status
        payload["demo_mode"] = self._demo_mode
        payload["persistence_enabled"] = self.sqlite_path is not None
        payload["last_error"] = self._last_error
        return payload

    def recent_results(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            if self._service is None:
                return []
            return self._service.recent_results(limit=limit)

    def recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        safe_limit = max(1, int(limit))
        live_items: List[Dict[str, Any]] = []
        with self._lock:
            if self._service is not None:
                live_items = self._service.recent_alerts(limit=safe_limit)
        persisted_items = self._read_persisted_alerts(limit=safe_limit)
        if not persisted_items:
            return live_items[:safe_limit]
        merged: Dict[str, Dict[str, Any]] = {}
        for item in persisted_items:
            aid = str(item.get("alert_id") or "")
            if aid:
                merged[aid] = item
        for item in live_items:
            aid = str(item.get("alert_id") or "")
            if aid:
                merged[aid] = item
        return sorted(
            merged.values(),
            key=lambda item: str(item.get("last_seen_utc") or ""),
            reverse=True,
        )[:safe_limit]

    def _read_persisted_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        connection = self._connect()
        if connection is None:
            return []
        try:
            if not self._table_exists(connection, "live_alerts"):
                return []
            rows = connection.execute(
                """
                SELECT alert_id, created_at_utc, entity_id, risk_score, risk_level,
                       trigger_reason, status, occurrence_count, first_seen_utc,
                       last_seen_utc, associated_event_ids, adaptive_key_rotated,
                       detection_latency_ms
                FROM live_alerts
                ORDER BY last_seen_utc DESC
                LIMIT ?;
                """,
                (max(1, int(limit)),),
            ).fetchall()
            items: List[Dict[str, Any]] = []
            for row in rows:
                try:
                    event_ids = json.loads(row["associated_event_ids"] or "[]")
                except Exception:
                    event_ids = []
                items.append(
                    {
                        "alert_id": row["alert_id"],
                        "created_at_utc": row["created_at_utc"],
                        "entity_id": row["entity_id"],
                        "risk_score": float(row["risk_score"]),
                        "risk_level": row["risk_level"],
                        "trigger_reason": row["trigger_reason"],
                        "status": row["status"],
                        "occurrence_count": int(row["occurrence_count"]),
                        "first_seen_utc": row["first_seen_utc"],
                        "last_seen_utc": row["last_seen_utc"],
                        "associated_event_ids": event_ids if isinstance(event_ids, list) else [],
                        "adaptive_key_rotated": bool(row["adaptive_key_rotated"]),
                        "detection_latency_ms": float(row["detection_latency_ms"]),
                    }
                )
            return items
        finally:
            connection.close()

    def entity_graph(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if self._service is None:
                return None
            return self._service.orchestrator.entity_graph.to_dict()

    # --------------------------------------------------------- behavioral
    def _connect(self) -> Optional[sqlite3.Connection]:
        path = self.sqlite_path
        if path is None:
            return None
        if not path.exists():
            return None
        connection = sqlite3.connect(str(path), timeout=15.0)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
        row = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?;", (table,)
        ).fetchone()
        return row is not None

    def list_behavioral_vectors(
        self, entity_id: Optional[str] = None, limit: int = 50
    ) -> Dict[str, Any]:
        connection = self._connect()
        if connection is None:
            return {
                "items": [],
                "total": 0,
                "data_status": DISCONNECTED,
                "reason": "live database is not a persistent file",
            }
        try:
            if not self._table_exists(connection, "behavioral_vectors"):
                return {
                    "items": [],
                    "total": 0,
                    "data_status": EMPTY,
                    "reason": "no behavioral vectors have been stored yet",
                }
            if entity_id:
                rows = connection.execute(
                    """
                    SELECT vector_id, entity_id, window_start, window_end, dimensions,
                           is_encrypted, key_id, created_at
                    FROM behavioral_vectors WHERE entity_id = ?
                    ORDER BY created_at DESC LIMIT ?;
                    """,
                    (entity_id, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT vector_id, entity_id, window_start, window_end, dimensions,
                           is_encrypted, key_id, created_at
                    FROM behavioral_vectors
                    ORDER BY created_at DESC LIMIT ?;
                    """,
                    (limit,),
                ).fetchall()
        finally:
            connection.close()
        items = [dict(row) for row in rows]
        for item in items:
            item["is_encrypted"] = bool(item["is_encrypted"])
        return {
            "items": items,
            "total": len(items),
            "data_status": CONNECTED if items else EMPTY,
        }

    def load_behavioral_vector(self, vector_id: str) -> Optional[Dict[str, Any]]:
        from network_anomaly.crypto.encrypted_storage import EncryptedStorageVault

        path = self.sqlite_path
        if path is None or not path.exists():
            return None
        vault = EncryptedStorageVault(self.key_manager(), path)
        connection = self._connect()
        if connection is None:
            return None
        try:
            if not self._table_exists(connection, "behavioral_vectors"):
                return None
            row = connection.execute(
                """
                SELECT vector_id, entity_id, window_start, window_end, dimensions,
                       is_encrypted, key_id, created_at
                FROM behavioral_vectors WHERE vector_id = ?;
                """,
                (vector_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return None

        features = vault.load_behavioral_vector(vector_id)
        if features is None:
            raise KeyStorageError(
                f"behavioral vector '{vector_id}' exists but could not be decrypted"
            )
        dimensions = int(row["dimensions"])
        names: Optional[List[str]] = None
        name_status = "UNKNOWN_DIMENSION"
        if dimensions == len(BehavioralVectorBuilder.FEATURE_NAMES):
            names = list(BehavioralVectorBuilder.FEATURE_NAMES)
            name_status = "CANONICAL_16D_ORDER"
        float_features = [float(value) for value in features]
        sha256 = hashlib.sha256(json.dumps(float_features).encode("ascii")).hexdigest()
        return {
            "vector_id": row["vector_id"],
            "entity_id": row["entity_id"],
            "window_start": row["window_start"],
            "window_end": row["window_end"],
            "dimensions": dimensions,
            "features": float_features,
            "feature_names": names,
            "feature_name_status": name_status,
            "sha256_hash": sha256,
            "is_encrypted_at_rest": bool(row["is_encrypted"]),
            "key_id": row["key_id"],
            "created_at": row["created_at"],
        }

    @staticmethod
    def _cosine(a: List[float], b: List[float]) -> Optional[float]:
        norm_a = math.sqrt(sum(value * value for value in a))
        norm_b = math.sqrt(sum(value * value for value in b))
        if norm_a <= 0.0 or norm_b <= 0.0:
            return None
        dot = sum(x * y for x, y in zip(a, b))
        return max(-1.0, min(1.0, dot / (norm_a * norm_b)))

    @staticmethod
    def _euclidean(a: List[float], b: List[float]) -> float:
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

    @staticmethod
    def _manhattan(a: List[float], b: List[float]) -> float:
        return sum(abs(x - y) for x, y in zip(a, b))

    def behavioral_similarity(self, vector_a_id: str, vector_b_id: str) -> Optional[Dict[str, Any]]:
        vector_a = self.load_behavioral_vector(vector_a_id)
        vector_b = self.load_behavioral_vector(vector_b_id)
        if vector_a is None or vector_b is None:
            return None
        if vector_a["dimensions"] != vector_b["dimensions"]:
            return {
                "vector_a": vector_a_id,
                "vector_b": vector_b_id,
                "comparable": False,
                "reason": "vectors have different dimensionality",
                "data_status": CONNECTED,
            }
        cosine = self._cosine(vector_a["features"], vector_b["features"])
        euclidean = self._euclidean(vector_a["features"], vector_b["features"])
        manhattan = self._manhattan(vector_a["features"], vector_b["features"])
        interpretation = None
        if cosine is not None:
            if cosine >= 0.95:
                interpretation = "NEAR_IDENTICAL"
            elif cosine >= 0.75:
                interpretation = "SIMILAR"
            else:
                interpretation = "DIVERGENT"
        return {
            "vector_a": vector_a_id,
            "vector_b": vector_b_id,
            "dimensions": vector_a["dimensions"],
            "cosine_similarity": None if cosine is None else round(cosine, 6),
            "euclidean_distance": round(euclidean, 6),
            "manhattan_distance": round(manhattan, 6),
            "interpretation": interpretation,
            "interpretation_semantics": (
                "display_thresholds_cosine_ge_0.95_near_identical_ge_0.75_similar_"
                "else_divergent_not_a_model_decision"
            ),
            "comparable": True,
            "data_status": CONNECTED,
        }

    def behavioral_correlation(
        self,
        vector_ids: Optional[List[str]] = None,
        match_threshold: float = BehavioralSimilarityCalculator.DEFAULT_MATCH_THRESHOLD,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Run IPSpoofingSessionCorrelator over decrypted stored behavioral vectors."""
        listing = self.list_behavioral_vectors(limit=limit)
        if listing["data_status"] in (DISCONNECTED, EMPTY):
            return {
                "data_status": listing["data_status"],
                "match_threshold": match_threshold,
                "total_vectors_evaluated": 0,
                "clusters": [],
                "reason": listing.get("reason"),
            }

        target_ids = vector_ids or [item["vector_id"] for item in listing["items"]]
        vectors: List[BehavioralVector] = []
        session_ip_map: Dict[str, str] = {}
        for vid in target_ids:
            detail = self.load_behavioral_vector(vid)
            if detail is None or detail["dimensions"] != len(BehavioralVectorBuilder.FEATURE_NAMES):
                continue
            bv = BehavioralVector(
                vector_id=detail["vector_id"],
                entity_key=detail["entity_id"],
                window_start=detail["window_start"],
                window_end=detail["window_end"],
                features=list(detail["features"]),
                feature_names=list(BehavioralVectorBuilder.FEATURE_NAMES),
                sha256_hash=detail.get("sha256_hash", ""),
            )
            vectors.append(bv)
            ent = str(detail["entity_id"])
            session_ip_map[bv.vector_id] = ent.split(":", 1)[1] if ":" in ent else ent

        if not vectors:
            return {
                "data_status": EMPTY,
                "match_threshold": match_threshold,
                "total_vectors_evaluated": 0,
                "clusters": [],
                "reason": "no 16-D behavioral vectors available for correlation",
            }

        correlator = IPSpoofingSessionCorrelator(match_threshold=match_threshold)
        clusters = correlator.correlate_sessions(vectors, session_ip_map=session_ip_map)
        return {
            "data_status": CONNECTED,
            "match_threshold": match_threshold,
            "total_vectors_evaluated": len(vectors),
            "clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "member_vector_ids": list(c.member_session_ids),
                    "average_similarity": c.average_similarity,
                    "ip_addresses_observed": list(c.ip_addresses_observed),
                }
                for c in clusters
            ],
            "reason": None,
        }

    def crypto_status(
        self,
        domain: str = "general",
        persisted_rotations: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Return active key metadata, storage protection status, and real rotation history."""
        try:
            km = self.key_manager()
        except KeyStorageError as exc:
            return {
                "active_key_id": "UNAVAILABLE",
                "algorithm": "AES-256-GCM",
                "rotation_interval_minutes": 30.0,
                "adaptive_risk_threshold": 85.0,
                "cooldown_seconds": 60,
                "max_rotations_per_hour": KeyRotationPolicy.DEFAULT_MAX_ROTATIONS_PER_HOUR,
                "rotations_this_hour": 0,
                "total_rotations": 0,
                "total_records_encrypted": 0,
                "master_key_fingerprint": None,
                "recent_rotations": [],
                "storage_protection_status": {
                    "error": str(exc),
                    "fail_closed": True,
                },
                "data_status": ERROR,
            }

        active_id, _ = km.get_active_key(domain=domain)
        km_meta = km.get_metadata(active_id)
        records_enc = km_meta.records_encrypted_count if km_meta else 0
        protection = km.storage_protection()

        # Public fingerprint over the protected master.key file bytes (never raw key material)
        master_fp: Optional[str] = None
        master_file = km.keystore_dir / "master.key"
        if master_file.exists():
            try:
                master_fp = hashlib.sha256(master_file.read_bytes()).hexdigest()[:16]
            except OSError:
                master_fp = None

        rotator = self.active_key_rotator()
        history_items: List[Dict[str, Any]] = []
        seen_ids: set[str] = set()
        if rotator is not None:
            for r in reversed(rotator.get_audit_history()):
                seen_ids.add(r.rotation_id)
                history_items.append(
                    {
                        "rotation_id": r.rotation_id,
                        "trigger": r.trigger.value,
                        "decision": r.decision.value,
                        "old_key_id": r.old_key_id,
                        "new_key_id": r.new_key_id,
                        "risk_score": r.risk_score,
                        "timestamp": r.timestamp,
                        "reason": r.reason,
                    }
                )
        for row in persisted_rotations or []:
            rid = str(row.get("rotation_id", ""))
            if rid and rid in seen_ids:
                continue
            history_items.append(
                {
                    "rotation_id": rid,
                    "trigger": row.get("triggered_by", "MANUAL_ADMIN"),
                    "decision": row.get("status", "EXECUTED"),
                    "old_key_id": row.get("old_key_id"),
                    "new_key_id": row.get("new_key_id"),
                    "risk_score": None,
                    "timestamp": row.get("created_at", ""),
                    "reason": row.get("reason", ""),
                }
            )
        history_items = history_items[:20]

        now_ts = datetime.now(timezone.utc).timestamp()
        rotations_this_hour = 0
        for item in history_items:
            ts_raw = item.get("timestamp")
            if not ts_raw:
                continue
            try:
                ts_val = datetime.fromisoformat(str(ts_raw)).timestamp()
                if now_ts - ts_val <= 3600.0 and item.get("decision") in (
                    "EXECUTED",
                    "SUCCESS",
                ):
                    rotations_this_hour += 1
            except ValueError:
                pass

        return {
            "active_key_id": active_id,
            "algorithm": "AES-256-GCM",
            "rotation_interval_minutes": 30.0,
            "adaptive_risk_threshold": 85.0,
            "cooldown_seconds": 60,
            "max_rotations_per_hour": KeyRotationPolicy.DEFAULT_MAX_ROTATIONS_PER_HOUR,
            "rotations_this_hour": rotations_this_hour,
            "total_rotations": len(km.list_keys()),
            "total_records_encrypted": records_enc,
            "master_key_fingerprint": master_fp,
            "recent_rotations": history_items,
            "storage_protection_status": protection,
            "data_status": CONNECTED,
        }
