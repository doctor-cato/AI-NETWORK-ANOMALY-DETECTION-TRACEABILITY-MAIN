"""Integrated Live Orchestrator connecting Ingestion, AI, Behavioral Vectors, Risk, and Trace Engines.

Implements Issue #135 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import collections
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from network_anomaly.api.db import DatabaseManager
from network_anomaly.behavioral.sessionizer import EventSessionizer
from network_anomaly.behavioral.vector import (
    BehavioralVector,
    BehavioralVectorBuilder,
    EntityBaselineProfiler,
)
from network_anomaly.canonical.event import CanonicalSecurityEvent
from network_anomaly.crypto.encrypted_storage import EncryptedStorageVault
from network_anomaly.crypto.key_manager import KeyManager
from network_anomaly.crypto.rotation import KeyRotationPolicy
from network_anomaly.risk.scoring import RiskScorer
from network_anomaly.streaming.alert_manager import LiveAlertManager, LiveSecurityAlert
from network_anomaly.streaming.feature_extractor import RealtimeFeatureExtractor
from network_anomaly.streaming.realtime_inference import (
    LiveInferenceDecision,
    RealtimeInferenceEngine,
)
from network_anomaly.trace.graph import EntityRelationshipGraph
from network_anomaly.trace.timeline import AttackTimelineReconstructor


@dataclass
class LiveProcessingResult:
    event_id: str
    entity_id: str
    is_ml_flow: bool
    inference_decision: Optional[LiveInferenceDecision] = None
    risk_score: float = 0.0
    risk_level: str = "LOW"
    alert_generated: Optional[LiveSecurityAlert] = None
    behavioral_vector: Optional[BehavioralVector] = None
    behavioral_vector_id: Optional[str] = None
    behavioral_vector_encrypted: bool = False
    timeline_updated: bool = False
    key_rotated: bool = False
    feature_status: str = "NOT_MODEL_READY"
    missing_features: List[str] = field(default_factory=list)
    provenance: Dict[str, str] = field(default_factory=dict)
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    attack_type: Optional[str] = None
    predicted_attack_category: Optional[str] = None
    attack_category_confidence: Optional[float] = None

    def to_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "event_id": self.event_id,
            "entity_id": self.entity_id,
            "is_ml_flow": self.is_ml_flow,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "timeline_updated": self.timeline_updated,
            "key_rotated": self.key_rotated,
            "feature_status": self.feature_status,
            "missing_features": list(self.missing_features),
            "provenance": dict(self.provenance),
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "attack_type": self.attack_type,
            "predicted_attack_category": self.predicted_attack_category,
            "attack_category_confidence": self.attack_category_confidence,
            "behavioral_vector_id": self.behavioral_vector_id,
            "behavioral_vector_encrypted": self.behavioral_vector_encrypted,
        }
        if self.behavioral_vector is not None:
            payload["behavioral_vector"] = self.behavioral_vector.to_dict()
        if self.inference_decision is not None:
            payload["inference"] = self.inference_decision.to_dict()
        if self.alert_generated is not None:
            payload["alert"] = self.alert_generated.to_dict()
        return payload


class LiveSystemOrchestrator:
    """Central real-time coordinator linking streaming telemetry, AI models, crypto, and attack tracing."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        max_active_entities: int = 5_000,
        keystore_dir: Optional[Path] = None,
        inference_engine: Optional[RealtimeInferenceEngine] = None,
        demo_heuristics: bool = False,
        runtime_mode: Optional[str] = None,
        require_ood_gate: Optional[bool] = None,
        expected_ood_gate_sha256: Optional[str] = None,
        encrypt_at_rest: bool = True,
    ):
        self.max_active_entities = max_active_entities
        self.encrypt_at_rest = bool(encrypt_at_rest)

        # Subsystems
        self.feature_extractor = RealtimeFeatureExtractor()
        if inference_engine is not None:
            if runtime_mode is not None:
                norm_mode = str(runtime_mode).strip().lower()
                engine_mode = getattr(inference_engine, "runtime_mode", None)
                if engine_mode != norm_mode:
                    raise ValueError(
                        f"inference_engine.runtime_mode ({engine_mode!r}) does not match "
                        f"requested runtime_mode ({norm_mode!r})"
                    )
            if require_ood_gate is not None and hasattr(inference_engine, "require_ood_gate"):
                if bool(inference_engine.require_ood_gate) != bool(require_ood_gate):
                    raise ValueError(
                        "inference_engine.require_ood_gate does not match requested require_ood_gate"
                    )
            if expected_ood_gate_sha256 is not None and hasattr(
                inference_engine, "expected_ood_gate_sha256"
            ):
                req_sha = expected_ood_gate_sha256.strip().lower()
                eng_sha = getattr(inference_engine, "expected_ood_gate_sha256", None)
                if (eng_sha or "").strip().lower() != req_sha:
                    raise ValueError(
                        "inference_engine.expected_ood_gate_sha256 does not match requested "
                        "expected_ood_gate_sha256"
                    )
            self.inference_engine = inference_engine
        else:
            self.inference_engine = RealtimeInferenceEngine(
                demo_heuristics=demo_heuristics,
                runtime_mode=runtime_mode,
                require_ood_gate=require_ood_gate,
                expected_ood_gate_sha256=expected_ood_gate_sha256,
            )
        self.key_manager = KeyManager(keystore_dir=keystore_dir)
        self.key_rotator = KeyRotationPolicy(
            key_manager=self.key_manager,
            db_path=Path(db_path) if db_path else None,
            adaptive_risk_threshold=85.0,
        )
        self.risk_scorer = RiskScorer()
        self.alert_manager = LiveAlertManager(
            db_path=db_path,
            risk_scorer=self.risk_scorer,
            key_rotator=self.key_rotator,
        )
        self.sessionizer = EventSessionizer()
        self.vector_builder = BehavioralVectorBuilder()
        self.baseline_profiler = EntityBaselineProfiler()
        self.entity_graph = EntityRelationshipGraph()
        self.timeline_reconstructor = AttackTimelineReconstructor()
        self.vault: Optional[EncryptedStorageVault] = (
            EncryptedStorageVault(self.key_manager, Path(db_path)) if db_path else None
        )
        self._db_manager: Optional[DatabaseManager] = (
            DatabaseManager(Path(db_path)) if db_path else None
        )

        # Bounded LRU-style entity eviction tracking for zero-leak memory stability
        self._entity_access_times: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._entity_events: Dict[str, List[CanonicalSecurityEvent]] = {}
        self.total_processed_events = 0

    def _prepare_entity_and_vector(
        self, event: CanonicalSecurityEvent
    ) -> Tuple[str, Optional[BehavioralVector]]:
        """Update bounded entity tracking, sessionize, and build behavioral vector."""
        now = time.time()
        entity = event.entity_id or f"host:{event.source_ip or 'unknown'}"

        if entity in self._entity_access_times:
            self._entity_access_times.move_to_end(entity)
        self._entity_access_times[entity] = now

        if len(self._entity_access_times) > self.max_active_entities:
            oldest_entity, _ = self._entity_access_times.popitem(last=False)
            self.entity_graph.evict_entity(oldest_entity)
            if oldest_entity in self._entity_events:
                del self._entity_events[oldest_entity]

        self._entity_events.setdefault(entity, []).append(event)
        if len(self._entity_events[entity]) > 100:
            self._entity_events[entity] = self._entity_events[entity][-100:]

        self.entity_graph.add_event(event)

        b_vec: Optional[BehavioralVector] = None
        sessions = self.sessionizer.sessionize(self._entity_events[entity])
        if sessions:
            latest_session = sessions[-1]
            session_events = [
                ev
                for ev in self._entity_events[entity]
                if latest_session.start_time <= ev.event_timestamp <= latest_session.end_time
            ]
            b_vec = self.vector_builder.build_vector(latest_session, events=session_events)
        return entity, b_vec

    @staticmethod
    def _build_unified_event_record(
        event: CanonicalSecurityEvent,
        entity: str,
        feat_res: Any,
        risk_assess: Any,
    ) -> Dict[str, Any]:
        payload = event.model_dump(mode="json")
        payload["risk_score"] = risk_assess.score
        payload["risk_level"] = risk_assess.severity.value
        payload["feature_status"] = feat_res.status
        return {
            "event_id": event.event_id,
            "schema_version": event.schema_version,
            "event_timestamp": event.event_timestamp.isoformat(),
            "event_kind": event.event_kind.value,
            "source_id": event.source_id,
            "entity_id": entity,
            "source_ip": event.source_ip,
            "dest_ip": event.dest_ip,
            "source_port": event.source_port,
            "dest_port": event.dest_port,
            "protocol": event.protocol,
            "is_ml_complete": feat_res.is_ml_ready,
            "validation_status": event.validation_status.value,
            "raw_provenance": event.raw_provenance.model_dump(mode="json"),
            "payload_json": payload,
        }

    @staticmethod
    def _build_processing_result(
        event: CanonicalSecurityEvent,
        entity: str,
        feat_res: Any,
        inf_dec: Optional[LiveInferenceDecision],
        risk_assess: Any,
        alert: Optional[LiveSecurityAlert],
        b_vec: Optional[BehavioralVector],
        vector_id: Optional[str],
        vector_encrypted: bool,
    ) -> LiveProcessingResult:
        pred_cat = inf_dec.predicted_attack_category if inf_dec else None
        pred_conf = inf_dec.attack_category_confidence if inf_dec else None
        attack_type = event.attack_category if event.attack_category is not None else pred_cat
        return LiveProcessingResult(
            event_id=event.event_id,
            entity_id=entity,
            is_ml_flow=feat_res.is_ml_ready,
            inference_decision=inf_dec,
            risk_score=risk_assess.score,
            risk_level=risk_assess.severity.value,
            alert_generated=alert,
            behavioral_vector=b_vec,
            behavioral_vector_id=vector_id,
            behavioral_vector_encrypted=vector_encrypted,
            timeline_updated=risk_assess.score >= 60.0,
            key_rotated=alert.adaptive_key_rotated if alert else False,
            feature_status=feat_res.status,
            missing_features=list(feat_res.missing_features),
            provenance={
                "source_id": event.source_id,
                "source_file": event.raw_provenance.source_file,
                "adapter_name": event.raw_provenance.adapter_name,
                "source_checksum": event.raw_provenance.source_checksum or "",
            },
            timestamp=event.event_timestamp.isoformat(),
            source_ip=event.source_ip,
            dest_ip=event.dest_ip,
            dest_port=event.dest_port,
            attack_type=attack_type,
            predicted_attack_category=pred_cat,
            attack_category_confidence=pred_conf,
        )

    def _compute_baseline_deviation(self, b_vec: Optional[BehavioralVector]) -> Optional[float]:
        """Score behavioral vector deviation against entity baseline and update sliding window."""
        if b_vec is None:
            return None
        dev_info = self.baseline_profiler.score_deviation(b_vec)
        self.baseline_profiler.update(b_vec)
        if dev_info.get("has_baseline"):
            return float(dev_info.get("deviation_score", 0.0))
        return None

    def process_event(self, event: CanonicalSecurityEvent) -> LiveProcessingResult:
        """Process a single incoming security event through the complete live telemetry stack."""
        self.total_processed_events += 1
        entity, b_vec = self._prepare_entity_and_vector(event)
        baseline_dev = self._compute_baseline_deviation(b_vec)

        feat_res = self.feature_extractor.extract(event)
        inf_dec: Optional[LiveInferenceDecision] = None

        if feat_res.is_ml_ready and feat_res.feature_dict:
            inf_dec = self.inference_engine.infer_event(
                event=event,
                feature_dict=feat_res.feature_dict,
                feature_vector=feat_res.feature_vector,
            )

        risk_assess, alert = self.alert_manager.process_event_risk(
            event,
            inf_dec,
            behavioral_vector=b_vec,
            baseline_deviation_score=baseline_dev,
        )

        vector_id: Optional[str] = None
        vector_encrypted = False
        if self.vault is not None and b_vec is not None and b_vec.features is not None:
            vector_id = self.vault.store_behavioral_vector(
                entity_id=b_vec.entity_key,
                window_start=b_vec.window_start,
                window_end=b_vec.window_end,
                vector=list(b_vec.features),
                encrypt=self.encrypt_at_rest,
            )
            vector_encrypted = self.encrypt_at_rest

        if self._db_manager is not None:
            self._db_manager.insert_unified_security_event(
                self._build_unified_event_record(event, entity, feat_res, risk_assess)
            )

        return self._build_processing_result(
            event,
            entity,
            feat_res,
            inf_dec,
            risk_assess,
            alert,
            b_vec,
            vector_id,
            vector_encrypted,
        )

    def process_batch(self, events: List[CanonicalSecurityEvent]) -> List[LiveProcessingResult]:
        """Process a stream batch with vectorized ML inference and batched DB persistence."""
        if not events:
            return []

        entities: List[str] = []
        b_vecs: List[Optional[BehavioralVector]] = []
        baseline_devs: List[Optional[float]] = []
        feat_results: List[Any] = []
        ml_indices: List[int] = []
        ml_events: List[CanonicalSecurityEvent] = []
        ml_feature_dicts: List[Dict[str, float]] = []

        for idx, event in enumerate(events):
            self.total_processed_events += 1
            entity, b_vec = self._prepare_entity_and_vector(event)
            baseline_devs.append(self._compute_baseline_deviation(b_vec))
            feat_res = self.feature_extractor.extract(event)
            entities.append(entity)
            b_vecs.append(b_vec)
            feat_results.append(feat_res)
            if feat_res.is_ml_ready and feat_res.feature_dict:
                ml_indices.append(idx)
                ml_events.append(event)
                ml_feature_dicts.append(feat_res.feature_dict)

        decisions_by_idx: Dict[int, LiveInferenceDecision] = {}
        if ml_events:
            ml_decisions = self.inference_engine.infer_batch(ml_events, ml_feature_dicts)
            for orig_idx, dec in zip(ml_indices, ml_decisions):
                decisions_by_idx[orig_idx] = dec

        results: List[LiveProcessingResult] = []
        alerts_to_persist: List[LiveSecurityAlert] = []
        bv_items: List[Dict[str, Any]] = []
        bv_result_indices: List[int] = []
        db_event_records: List[Dict[str, Any]] = []

        for idx, event in enumerate(events):
            entity = entities[idx]
            b_vec = b_vecs[idx]
            feat_res = feat_results[idx]
            inf_dec = decisions_by_idx.get(idx)

            risk_assess, alert = self.alert_manager.process_event_risk(
                event,
                inf_dec,
                behavioral_vector=b_vec,
                baseline_deviation_score=baseline_devs[idx],
                persist=False,
            )
            if alert is not None:
                alerts_to_persist.append(alert)

            vector_encrypted = False
            if self.vault is not None and b_vec is not None and b_vec.features is not None:
                bv_items.append(
                    {
                        "entity_id": b_vec.entity_key,
                        "window_start": b_vec.window_start,
                        "window_end": b_vec.window_end,
                        "vector": list(b_vec.features),
                    }
                )
                bv_result_indices.append(idx)
                vector_encrypted = self.encrypt_at_rest

            if self._db_manager is not None:
                db_event_records.append(
                    self._build_unified_event_record(event, entity, feat_res, risk_assess)
                )

            results.append(
                self._build_processing_result(
                    event,
                    entity,
                    feat_res,
                    inf_dec,
                    risk_assess,
                    alert,
                    b_vec,
                    None,
                    vector_encrypted,
                )
            )

        if self.vault is not None and bv_items:
            vector_ids = self.vault.store_behavioral_vectors_batch(
                bv_items, encrypt=self.encrypt_at_rest
            )
            for res_idx, vec_id in zip(bv_result_indices, vector_ids):
                results[res_idx].behavioral_vector_id = vec_id

        if alerts_to_persist:
            self.alert_manager.persist_alerts_batch(alerts_to_persist)

        if self._db_manager is not None and db_event_records:
            self._db_manager.insert_unified_security_events_batch(db_event_records)

        return results
