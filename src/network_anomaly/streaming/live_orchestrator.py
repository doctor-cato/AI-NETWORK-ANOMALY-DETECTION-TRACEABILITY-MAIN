"""Integrated Live Orchestrator connecting Ingestion, AI, Behavioral Vectors, Risk, and Trace Engines.

Implements Issue #135 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import collections
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from network_anomaly.behavioral.sessionizer import EventSessionizer
from network_anomaly.behavioral.vector import BehavioralVector, BehavioralVectorBuilder
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
    ):
        self.max_active_entities = max_active_entities

        # Subsystems
        self.feature_extractor = RealtimeFeatureExtractor()
        self.inference_engine = inference_engine or RealtimeInferenceEngine(
            demo_heuristics=demo_heuristics
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
        self.entity_graph = EntityRelationshipGraph()
        self.timeline_reconstructor = AttackTimelineReconstructor()
        self.vault: Optional[EncryptedStorageVault] = (
            EncryptedStorageVault(self.key_manager, Path(db_path)) if db_path else None
        )

        # Bounded LRU-style entity eviction tracking for zero-leak memory stability
        self._entity_access_times: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._entity_events: Dict[str, List[CanonicalSecurityEvent]] = {}
        self.total_processed_events = 0

    def process_event(self, event: CanonicalSecurityEvent) -> LiveProcessingResult:
        """Process a single incoming security event through the complete live telemetry stack."""
        self.total_processed_events += 1
        now = time.time()
        entity = event.entity_id or f"host:{event.source_ip or 'unknown'}"

        # 1. Update bounded LRU entity tracker
        if entity in self._entity_access_times:
            self._entity_access_times.move_to_end(entity)
        self._entity_access_times[entity] = now

        if len(self._entity_access_times) > self.max_active_entities:
            oldest_entity, _ = self._entity_access_times.popitem(last=False)
            # Evict inactive entity from graph to bound memory consumption
            if oldest_entity in self.entity_graph.nodes:
                del self.entity_graph.nodes[oldest_entity]
            if oldest_entity in self._entity_events:
                del self._entity_events[oldest_entity]

        # 2. Behavioral Sessionization Event Buffer
        self._entity_events.setdefault(entity, []).append(event)
        if len(self._entity_events[entity]) > 100:  # Cap history per entity
            self._entity_events[entity] = self._entity_events[entity][-100:]

        # 3. Entity Relationship Graph Update
        self.entity_graph.add_event(event)

        # 4. Feature Extraction & Zero-Imputation Rejection
        feat_res = self.feature_extractor.extract(event)
        inf_dec: Optional[LiveInferenceDecision] = None

        if feat_res.is_ml_ready and feat_res.feature_dict:
            # 5. Real-time Multi-Model AI Inference
            inf_dec = self.inference_engine.infer_event(
                event=event,
                feature_dict=feat_res.feature_dict,
                feature_vector=feat_res.feature_vector,
            )

        # 6. Multi-Criteria Risk Scoring & Live Alert Management
        risk_assess, alert = self.alert_manager.process_event_risk(event, inf_dec)

        # 7. Attack Timeline Reconstruction
        timeline_updated = False
        if risk_assess.score >= 60.0:
            timeline_updated = True

        # 8. Behavioral Vector computation if session is active
        b_vec: Optional[BehavioralVector] = None
        vector_id: Optional[str] = None
        vector_encrypted = False
        sessions = self.sessionizer.sessionize(self._entity_events[entity])
        if sessions:
            b_vec = self.vector_builder.build_vector(sessions[-1])
            if self.vault is not None and b_vec.features is not None:
                vector_id = self.vault.store_behavioral_vector(
                    entity_id=b_vec.entity_key,
                    window_start=b_vec.window_start,
                    window_end=b_vec.window_end,
                    vector=list(b_vec.features),
                    encrypt=True,
                )
                vector_encrypted = True

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
            timeline_updated=timeline_updated,
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
            attack_type=event.attack_category,
        )

    def process_batch(self, events: List[CanonicalSecurityEvent]) -> List[LiveProcessingResult]:
        """Process a stream batch through the pipeline."""
        return [self.process_event(ev) for ev in events]
