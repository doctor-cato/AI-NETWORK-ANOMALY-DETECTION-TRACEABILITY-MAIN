"""Service layer implementing core business logic for the FastAPI application.

Reuses existing verified inference logic, manages SQLite transactions,
coordinates key rotation lifecycle with fail-safe cooldown and idempotency,
and powers unified chronological timeline queries.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from network_anomaly.api.db import DatabaseManager
from network_anomaly.api.errors import ModelNotReadyError
from network_anomaly.api.repositories import (
    EventRepository,
    EvidenceRepository,
    IdempotencyRepository,
    IncidentRepository,
    KeyMetadataRepository,
    RotationAuditRepository,
    SessionRepository,
    _utc_now_str,
)
from network_anomaly.api.schemas import (
    AnalyzeResponse,
    AnalyzeResultItem,
    HealthResponse,
    IncidentResponse,
    KeyMetadataResponse,
    KeyRotationResponse,
    PaginatedIncidentsResponse,
    PaginatedRotationAuditResponse,
    PaginatedTimelineResponse,
    RotationAuditItemResponse,
    TimelineItemResponse,
)
from network_anomaly.config import ARTIFACTS, PROJECT_ROOT

logger = logging.getLogger("network_anomaly.api.service")

# Minimum cooldown interval between key rotations (in seconds)
ROTATION_COOLDOWN_SECONDS = 1.0


class ApiService:
    """Coordinates business logic, repository calls, and ML inference."""

    def __init__(self, db: DatabaseManager):
        self.db = db
        self._ensure_initial_key()

    def _ensure_initial_key(self) -> None:
        """Seed initial encryption key metadata if none exists."""
        with self.db.transaction() as conn:
            active = KeyMetadataRepository.get_active_key(conn)
            if not active:
                KeyMetadataRepository.create_key(
                    conn,
                    {
                        "key_id": f"key_init_{uuid.uuid4().hex[:8]}",
                        "algorithm": "AES-256-GCM",
                        "version": 1,
                        "status": "ACTIVE",
                    },
                )

    def check_health(self) -> HealthResponse:
        """Inspect process, database, and ML artifact readiness.

        Strictly enforces that health NEVER claims model/data ready when artifacts are missing.
        """
        db_ready = self.db.is_healthy()

        # Readiness requires successful verification of both artifacts.
        preprocessor_ready = False
        model_ready = False
        verification_error = None
        for model_name in ("random_forest", "isolation_forest"):
            try:
                self._load_inference_pipeline(model_name)
                preprocessor_ready = True
                model_ready = True
                verification_error = None
                break
            except (FileNotFoundError, ValueError, RuntimeError) as exc:
                logger.warning("Artifact readiness verification failed for %s: %s", model_name, exc)
                verification_error = "artifact verification failed"

        # Overall status is degraded if either db or artifacts are missing
        status = "healthy" if (db_ready and model_ready and preprocessor_ready) else "degraded"

        git_commit = "unknown"
        try:
            import subprocess

            res = subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                stderr=subprocess.DEVNULL,
                text=True,
                cwd=PROJECT_ROOT,
            )
            git_commit = res.strip()
        except Exception:
            pass

        return HealthResponse(
            status=status,
            process_alive=True,
            model_ready=model_ready,
            preprocessor_ready=preprocessor_ready,
            db_ready=db_ready,
            version="0.1.0",
            git_commit=git_commit,
            timestamp=_utc_now_str(),
            details={
                "db_backend": "sqlite",
                "db_path": str(self.db.db_path),
                "artifacts_dir_exists": ARTIFACTS.exists(),
                "model_artifact_found": model_ready,
                "preprocessor_artifact_found": preprocessor_ready,
                "artifact_verification_error": verification_error,
            },
        )

    def ingest_events(
        self,
        events: List[Dict[str, Any]],
        session_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Tuple[int, List[str], Optional[str]]:
        """Ingest a batch of flow events atomically into SQLite."""
        endpoint = "/api/v1/ingest"

        with self.db.transaction() as conn:
            # Check idempotency
            if idempotency_key:
                cached = IdempotencyRepository.get_record(conn, idempotency_key, endpoint)
                if cached:
                    body = cached["response_body"]
                    return body["ingested_count"], body["event_ids"], body.get("session_id")

            # Assign or create session
            eff_session_id = session_id or (
                events[0].get("session_id") if events and events[0].get("session_id") else None
            )
            if not eff_session_id:
                eff_session_id = f"sess_{uuid.uuid4().hex[:12]}"

            # Prepare events with common session_id if missing
            prepared = []
            for evt in events:
                e_copy = dict(evt)
                if not e_copy.get("session_id"):
                    e_copy["session_id"] = eff_session_id
                prepared.append(e_copy)

            event_ids = EventRepository.insert_batch(conn, prepared)

            # Update session record
            src_ip = events[0].get("source_ip") if events else None
            dst_ip = events[0].get("dest_ip") if events else None
            SessionRepository.create_or_update(
                conn,
                {
                    "session_id": eff_session_id,
                    "event_count": len(events),
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                },
            )

            result_tuple = (len(event_ids), event_ids, eff_session_id)

            if idempotency_key:
                IdempotencyRepository.save_record(
                    conn,
                    idempotency_key,
                    endpoint,
                    200,
                    {
                        "status": "ok",
                        "ingested_count": len(event_ids),
                        "event_ids": event_ids,
                        "session_id": eff_session_id,
                    },
                )

            return result_tuple

    def _resolve_artifact_paths(
        self, model_name: str
    ) -> Tuple[Path, Optional[Path], Optional[Path], Optional[Path]]:
        """Resolve model and preprocessor artifact paths and companion manifests."""
        norm_name = (model_name or "random_forest").lower()
        if "isolation" in norm_name:
            model_path = ARTIFACTS / "models" / "isolation_forest" / "isolation_forest.joblib"
            model_manifest = PROJECT_ROOT / "reports" / "models" / "isolation_forest_manifest.json"
        else:
            rf_path = ARTIFACTS / "models" / "random_forest" / "random_forest_baseline.joblib"
            model_path = rf_path if rf_path.is_file() else ARTIFACTS / "model.joblib"
            model_manifest = PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json"

        prep_path = ARTIFACTS / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
        preprocessor_path = prep_path if prep_path.is_file() else ARTIFACTS / "preprocessor.joblib"
        prep_manifest = (
            PROJECT_ROOT
            / "reports"
            / "preprocessing"
            / "nf_unsw_nb15_v3_preprocessing_manifest.json"
        )

        return (
            model_path,
            preprocessor_path if preprocessor_path.is_file() else None,
            model_manifest if model_manifest.is_file() else None,
            prep_manifest if prep_manifest.is_file() else None,
        )

    def _load_inference_pipeline(self, model_name: str) -> Any:
        """Instantiate verified InferencePipeline fail-closed."""
        from network_anomaly.inference.predict import InferencePipeline

        (
            model_path,
            prep_path,
            model_manifest,
            prep_manifest,
        ) = self._resolve_artifact_paths(model_name)

        if not model_path.is_file():
            raise FileNotFoundError(
                f"Verified model artifact not found for '{model_name}' at '{model_path}'"
            )

        return InferencePipeline.from_artifacts(
            model_artifact_path=model_path,
            preprocessor_artifact_path=prep_path,
            model_manifest_path=model_manifest,
            preprocessor_manifest_path=prep_manifest,
        )

    def analyze_flows(
        self,
        events: List[Dict[str, Any]],
        model_name: str = "random_forest",
        threshold: float = 0.5,
        create_incidents: bool = True,
        allow_heuristic_fallback: bool = False,
    ) -> AnalyzeResponse:
        """Run anomaly detection inference on provided flow records.

        Enforces fail-closed behavior: raises ModelNotReadyError (HTTP 503) if
        verified model artifacts are unavailable or inference fails and
        allow_heuristic_fallback is False.
        """
        health = self.check_health()
        now = _utc_now_str()

        # Check if production ML pipeline artifacts are present
        if not (health.model_ready and health.preprocessor_ready):
            if not allow_heuristic_fallback:
                raise ModelNotReadyError(
                    "Verified ML model or preprocessor artifacts are not ready, "
                    "and heuristic fallback is disabled (fail-closed)."
                )
            results, inference_mode, model_sha256, prep_sha256, run_id = (
                self._analyze_with_heuristic(events, threshold=threshold)
            )
            model_ready = False
        else:
            try:
                results, inference_mode, model_sha256, prep_sha256, run_id = (
                    self._analyze_with_verified_pipeline(
                        events, model_name=model_name, threshold=threshold
                    )
                )
                model_ready = True
            except Exception as ex:
                if not allow_heuristic_fallback:
                    logger.error(
                        "Verified inference pipeline failed and fallback is disabled: %s",
                        ex,
                        exc_info=True,
                    )
                    raise ModelNotReadyError(
                        f"Verified inference pipeline failed: {ex}. Heuristic fallback is disabled."
                    ) from ex
                logger.warning("Pipeline inference failed, falling back to heuristic: %s", ex)
                results, inference_mode, model_sha256, prep_sha256, run_id = (
                    self._analyze_with_heuristic(events, threshold=threshold)
                )
                model_ready = False

        # Optionally persist incidents and evidence for detected anomalies
        anomalies_count = 0
        with self.db.transaction() as conn:
            for item in results:
                if item.is_anomaly:
                    anomalies_count += 1
                    if create_incidents:
                        severity = "HIGH" if item.anomaly_score >= 0.8 else "MEDIUM"
                        inc = IncidentRepository.create(
                            conn,
                            {
                                "title": f"Network Anomaly Alert ({item.model_used})",
                                "severity": severity,
                                "status": "OPEN",
                                "anomaly_score": item.anomaly_score,
                                "attack_type": item.attack_type or "Behavioral Anomaly",
                                "description": (
                                    "Automated alert detected with anomaly score "
                                    f"{item.anomaly_score:.3f}"
                                ),
                                "event_id": item.event_id,
                            },
                        )
                        inc_id = inc["incident_id"]
                        item.incident_created = True
                        item.incident_id = inc_id

                        # Record evidence reference
                        EvidenceRepository.create(
                            conn,
                            {
                                "incident_id": inc_id,
                                "artifact_name": item.model_used,
                                "artifact_sha256": item.model_sha256 or "live_inference",
                                "evidence_type": (
                                    "model_prediction" if model_ready else "heuristic_fallback"
                                ),
                                "details": {
                                    "anomaly_score": item.anomaly_score,
                                    "threshold": threshold,
                                    "model_ready": model_ready,
                                    "inference_mode": item.inference_mode,
                                    "run_id": item.run_id,
                                },
                            },
                        )

        return AnalyzeResponse(
            model_ready=model_ready,
            count=len(results),
            anomalies_detected=anomalies_count,
            results=results,
            timestamp=now,
            inference_mode=inference_mode,
            model_sha256=model_sha256,
            preprocessor_sha256=prep_sha256,
            run_id=run_id,
        )

    def _analyze_with_verified_pipeline(
        self,
        events: List[Dict[str, Any]],
        model_name: str,
        threshold: float,
    ) -> Tuple[List[AnalyzeResultItem], str, Optional[str], Optional[str], Optional[str]]:
        """Execute inference using loaded verified artifacts."""
        pipeline = self._load_inference_pipeline(model_name)

        df_rows = []
        for e in events:
            row = dict(e.get("features", {}))
            df_rows.append(row)

        df = pd.DataFrame(df_rows)
        preds_df = pipeline.predict(df)

        model_sha256 = pipeline.model_metadata.get("model_artifact_sha256")
        prep_sha256 = pipeline.preprocessor_metadata.get("artifact_sha256")
        batch_run_id = (
            preds_df["run_id"].iloc[0]
            if ("run_id" in preds_df.columns and len(preds_df) > 0)
            else None
        )

        items: List[AnalyzeResultItem] = []
        for idx in range(len(preds_df)):
            row = preds_df.iloc[idx]
            raw_pred = row.get("prediction", 0)

            # Determine anomaly score and probability
            score = 0.0
            if "probability_Attack" in preds_df.columns:
                score = float(row["probability_Attack"])
            elif "probability_1" in preds_df.columns:
                score = float(row["probability_1"])
            elif "anomaly_score" in preds_df.columns:
                val = float(row["anomaly_score"])
                score = max(0.0, min(1.0, val))
            elif "decision_score" in preds_df.columns:
                val = float(row["decision_score"])
                score = 1.0 / (1.0 + np.exp(-val))
            else:
                score = float(raw_pred == 1 or raw_pred == -1)

            is_anom = bool(score >= threshold or raw_pred == 1)
            pred_binary = 1 if is_anom else 0

            items.append(
                AnalyzeResultItem(
                    index=idx,
                    event_id=events[idx].get("event_id"),
                    is_anomaly=is_anom,
                    anomaly_score=round(score, 4),
                    prediction=pred_binary,
                    attack_type="Network Anomaly" if is_anom else None,
                    model_used=model_name,
                    incident_created=False,
                    inference_mode="verified_model",
                    model_sha256=model_sha256,
                    preprocessor_sha256=prep_sha256,
                    run_id=batch_run_id,
                )
            )

        return items, "verified_model", model_sha256, prep_sha256, batch_run_id

    def _analyze_with_heuristic(
        self,
        events: List[Dict[str, Any]],
        threshold: float,
    ) -> Tuple[List[AnalyzeResultItem], str, Optional[str], Optional[str], Optional[str]]:
        """Fallback rule-based heuristic when model artifacts are absent."""
        items: List[AnalyzeResultItem] = []
        for idx, e in enumerate(events):
            feat = e.get("features", {})
            # Simple flow behavior anomaly heuristic for lab/uninitialized testing
            in_bytes = float(feat.get("IN_BYTES", 0) or 0)
            out_bytes = float(feat.get("OUT_BYTES", 0) or 0)
            in_pkts = float(feat.get("IN_PKTS", 0) or 0)
            out_pkts = float(feat.get("OUT_PKTS", 0) or 0)

            # Detect abnormal asymmetric throughput or extreme packet count
            score = 0.1
            if (
                in_bytes > 1_000_000
                or (in_pkts > 1000 and out_pkts == 0)
                or (in_bytes > 100_000 and out_bytes == 0)
            ):
                score = 0.85
            elif in_bytes > 100_000:
                score = 0.65

            is_anom = score >= threshold
            items.append(
                AnalyzeResultItem(
                    index=idx,
                    event_id=e.get("event_id"),
                    is_anomaly=is_anom,
                    anomaly_score=round(score, 3),
                    prediction=1 if is_anom else 0,
                    attack_type="Suspected High-Volume Flooding" if is_anom else None,
                    model_used="heuristic_baseline_artifact_missing",
                    incident_created=False,
                    inference_mode="heuristic_fallback",
                    model_sha256=None,
                    preprocessor_sha256=None,
                    run_id=None,
                )
            )
        return items, "heuristic_fallback", None, None, None

    def rotate_key(
        self,
        triggered_by: str = "operator",
        dry_run: bool = True,
        reason: Optional[str] = "Policy rotation",
        idempotency_key: Optional[str] = None,
    ) -> KeyRotationResponse:
        """Execute key rotation lifecycle audit with cooldown enforcement and idempotency.

        NOTE: Operates on Audit Trail Metadata only. In production environments,
        this operation must be guarded by API key / RBAC authentication and integrated
        with an external Key Management Service (KMS).
        """
        endpoint = "/api/v1/rotation"
        now = _utc_now_str()

        # Idempotency check
        if idempotency_key:
            with self.db.transaction() as conn:
                cached = IdempotencyRepository.get_record(conn, idempotency_key, endpoint)
                if cached:
                    b = cached["response_body"]
                    return KeyRotationResponse(
                        rotation_id=b["rotation_id"],
                        status=b["status"],
                        dry_run=b["dry_run"],
                        old_key_id=b.get("old_key_id"),
                        new_key_id=b["new_key_id"],
                        created_at=b["created_at"],
                        message=b["message"],
                    )

        # Check cooldown against last rotation
        cooldown_violated = False
        last_key_id = ""
        with self.db.transaction() as conn:
            last = RotationAuditRepository.get_last_rotation(conn)
            if last and last["status"] == "SUCCESS":
                try:
                    last_time = datetime.fromisoformat(last["created_at"])
                    elapsed = (datetime.now(timezone.utc) - last_time).total_seconds()
                    if elapsed < ROTATION_COOLDOWN_SECONDS:
                        cooldown_violated = True
                        last_key_id = last.get("new_key_id") or ""
                except (ValueError, TypeError):
                    pass

        if cooldown_violated:
            rot_id = f"rot_blocked_{uuid.uuid4().hex[:8]}"
            with self.db.transaction() as conn:
                RotationAuditRepository.log_rotation(
                    conn,
                    {
                        "rotation_id": rot_id,
                        "triggered_by": triggered_by,
                        "old_key_id": last_key_id,
                        "new_key_id": last_key_id,
                        "dry_run": dry_run,
                        "status": "BLOCKED_COOLDOWN",
                        "reason": (
                            "Rate limited: rotation cooldown period "
                            f"({ROTATION_COOLDOWN_SECONDS}s) not met"
                        ),
                    },
                )
            raise ValueError(
                "Rotation rejected: minimum cooldown interval "
                f"({ROTATION_COOLDOWN_SECONDS}s) has not elapsed."
            )

        with self.db.transaction() as conn:
            # Get current active key
            active = KeyMetadataRepository.get_active_key(conn)
            old_key_id = active["key_id"] if active else None
            next_version = (active["version"] + 1) if active else 1

            new_key_id = f"key_v{next_version}_{uuid.uuid4().hex[:8]}"

            # Retire old key and register new key
            if old_key_id:
                KeyMetadataRepository.retire_key(conn, old_key_id, now)

            KeyMetadataRepository.create_key(
                conn,
                {
                    "key_id": new_key_id,
                    "algorithm": "AES-256-GCM",
                    "version": next_version,
                    "status": "ACTIVE",
                    "created_at": now,
                },
            )

            # Record audit
            rot_id = f"rot_{uuid.uuid4().hex[:12]}"
            RotationAuditRepository.log_rotation(
                conn,
                {
                    "rotation_id": rot_id,
                    "triggered_by": triggered_by,
                    "old_key_id": old_key_id,
                    "new_key_id": new_key_id,
                    "dry_run": dry_run,
                    "status": "SUCCESS",
                    "reason": reason,
                    "created_at": now,
                },
            )

            sim_mode = "dry-run simulation" if dry_run else "active"
            resp = KeyRotationResponse(
                rotation_id=rot_id,
                status="SUCCESS",
                dry_run=dry_run,
                old_key_id=old_key_id,
                new_key_id=new_key_id,
                created_at=now,
                message=f"Key successfully rotated to version {next_version} ({sim_mode}).",
            )

            if idempotency_key:
                IdempotencyRepository.save_record(
                    conn, idempotency_key, endpoint, 200, resp.model_dump()
                )

            return resp

    def get_timeline(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> PaginatedTimelineResponse:
        """Construct chronologically ordered timeline across events, incidents, and rotations."""
        items: List[TimelineItemResponse] = []

        with self.db.transaction() as conn:
            # 1. Flow events
            events = EventRepository.list_events(conn, limit=limit, offset=0)
            for e in events:
                src = e.get("source_ip") or "unknown"
                dst = e.get("dest_ip") or "unknown"
                items.append(
                    TimelineItemResponse(
                        id=e["event_id"],
                        event_type="flow_event",
                        timestamp=e["timestamp"],
                        summary=f"Flow telemetry ({src} -> {dst})",
                        details={
                            "protocol": e.get("protocol"),
                            "session_id": e.get("session_id"),
                        },
                    )
                )

            # 2. Incidents
            incidents = IncidentRepository.list_incidents(conn, limit=limit, offset=0)
            for inc in incidents:
                items.append(
                    TimelineItemResponse(
                        id=inc["incident_id"],
                        event_type="incident",
                        timestamp=inc["created_at"],
                        severity=inc["severity"],
                        summary=f"[{inc['severity']}] {inc['title']}",
                        details={
                            "anomaly_score": inc["anomaly_score"],
                            "status": inc["status"],
                            "attack_type": inc.get("attack_type"),
                        },
                    )
                )

            # 3. Key Rotations
            rotations = RotationAuditRepository.list_rotations(conn, limit=limit, offset=0)
            for r in rotations:
                items.append(
                    TimelineItemResponse(
                        id=r["rotation_id"],
                        event_type="key_rotation",
                        timestamp=r["created_at"],
                        summary=f"Key rotation triggered by {r['triggered_by']} ({r['status']})",
                        details={
                            "old_key_id": r.get("old_key_id"),
                            "new_key_id": r["new_key_id"],
                            "dry_run": bool(r["dry_run"]),
                        },
                    )
                )

        # Sort all timeline items chronologically descending
        items.sort(key=lambda x: x.timestamp, reverse=True)
        total = len(items)
        sliced = items[offset : offset + limit]
        has_more = (offset + limit) < total

        return PaginatedTimelineResponse(
            items=sliced,
            total=total,
            limit=limit,
            offset=offset,
            has_more=has_more,
        )

    def list_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> PaginatedIncidentsResponse:
        """List incidents with filtering and pagination."""
        with self.db.transaction() as conn:
            total = IncidentRepository.count(conn, severity=severity, status=status)
            rows = IncidentRepository.list_incidents(
                conn, limit=limit, offset=offset, severity=severity, status=status
            )
            items = [IncidentResponse.model_validate(r) for r in rows]
            has_more = (offset + limit) < total

        return PaginatedIncidentsResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            has_more=has_more,
        )

    def list_rotation_audits(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> PaginatedRotationAuditResponse:
        """List rotation audits with pagination."""
        with self.db.transaction() as conn:
            total = RotationAuditRepository.count(conn)
            rows = RotationAuditRepository.list_rotations(conn, limit=limit, offset=offset)
            items = [
                RotationAuditItemResponse(
                    rotation_id=r["rotation_id"],
                    triggered_by=r["triggered_by"],
                    old_key_id=r.get("old_key_id"),
                    new_key_id=r["new_key_id"],
                    dry_run=bool(r["dry_run"]),
                    status=r["status"],
                    reason=r.get("reason"),
                    created_at=r["created_at"],
                )
                for r in rows
            ]
            has_more = (offset + limit) < total

        return PaginatedRotationAuditResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            has_more=has_more,
        )

    def list_keys(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> List[KeyMetadataResponse]:
        """List all key metadata without secret key material."""
        with self.db.transaction() as conn:
            rows = KeyMetadataRepository.list_keys(conn, limit=limit, offset=offset)
            return [KeyMetadataResponse.model_validate(r) for r in rows]
