"""Real-time Risk Engine Integration and Deduplicated Live Alert Management.

Implements Issue #134 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from network_anomaly.canonical.event import CanonicalSecurityEvent
from network_anomaly.crypto.rotation import KeyRotationPolicy, RotationDecision
from network_anomaly.risk.scoring import RiskScoreOutput, RiskScorer, SeverityLevel
from network_anomaly.streaming.realtime_inference import LiveInferenceDecision


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class LiveSecurityAlert:
    alert_id: str
    created_at_utc: str
    entity_id: str
    risk_score: float
    risk_level: str
    trigger_reason: str
    status: AlertStatus
    occurrence_count: int
    first_seen_utc: str
    last_seen_utc: str
    associated_event_ids: List[str]
    adaptive_key_rotated: bool = False
    detection_latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class LiveAlertManager:
    """Manages real-time risk scoring, adaptive rotation triggers, and deduplicated persistent alerts."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        dedup_window_sec: float = 60.0,
        risk_threshold_alert: float = 70.0,
        risk_scorer: Optional[RiskScorer] = None,
        key_rotator: Optional[KeyRotationPolicy] = None,
    ):
        self.dedup_window_sec = dedup_window_sec
        self.risk_threshold_alert = risk_threshold_alert
        self.risk_scorer = risk_scorer or RiskScorer()
        self.key_rotator = key_rotator
        self.db_path = db_path

        # In-memory deduplication cache: entity_id -> (alert_id, last_seen_epoch)
        self._dedup_cache: Dict[str, Tuple[str, float]] = {}
        self._active_alerts: Dict[str, LiveSecurityAlert] = {}

        if self.db_path:
            self._init_sqlite()

    def _init_sqlite(self) -> None:
        if not self.db_path:
            return
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS live_alerts (
                    alert_id TEXT PRIMARY KEY,
                    created_at_utc TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    trigger_reason TEXT NOT NULL,
                    status TEXT NOT NULL,
                    occurrence_count INTEGER NOT NULL,
                    first_seen_utc TEXT NOT NULL,
                    last_seen_utc TEXT NOT NULL,
                    associated_event_ids TEXT NOT NULL,
                    adaptive_key_rotated INTEGER NOT NULL,
                    detection_latency_ms REAL NOT NULL
                )
                """
            )
            conn.commit()

    def process_event_risk(
        self,
        event: CanonicalSecurityEvent,
        inference_decision: Optional[LiveInferenceDecision] = None,
    ) -> Tuple[RiskScoreOutput, Optional[LiveSecurityAlert]]:
        """Compute multi-criteria risk score and generate deduplicated alert if threshold exceeded."""
        now = time.time()
        start_t = time.perf_counter()

        ai_prob = inference_decision.ensemble_score if inference_decision else 0.0
        is_ood = inference_decision.is_ood if inference_decision else False
        
        # Calculate contextual behavioral anomaly and auth failure indicators
        beh_score = 0.90 if (event.flow_metrics and event.flow_metrics.bytes_out > 50_000) else (
            0.60 if (event.flow_metrics and event.flow_metrics.bytes_out > 10_000) else 0.0
        )
        auth_fails = 4 if (event.auth_data and event.auth_data.auth_result == "FAILURE") else (
            2 if (event.dest_port in (22, 445) and event.flow_metrics and event.flow_metrics.bytes_out > 20_000) else 0
        )

        # 1. Compute multi-criteria risk score
        risk_assess = self.risk_scorer.compute_risk(
            ai_probability=ai_prob,
            behavioral_anomaly_score=beh_score,
            dest_port=event.dest_port,
            auth_failure_count=auth_fails,
            is_ood=is_ood,
            known_attack_type=event.attack_category,
        )

        alert: Optional[LiveSecurityAlert] = None

        # 2. Check alert threshold
        if risk_assess.score >= self.risk_threshold_alert:
            entity = event.entity_id or f"host:{event.source_ip or 'unknown'}"
            trigger_reason = "; ".join(risk_assess.justification) or "High Risk Score"
            now_iso = datetime.now(timezone.utc).isoformat()
            latency_ms = round((time.perf_counter() - start_t) * 1000.0, 3)

            # Check deduplication window
            if entity in self._dedup_cache:
                existing_alert_id, last_seen = self._dedup_cache[entity]
                if now - last_seen <= self.dedup_window_sec and existing_alert_id in self._active_alerts:
                    # Deduplicate into existing alert
                    curr = self._active_alerts[existing_alert_id]
                    curr.occurrence_count += 1
                    curr.last_seen_utc = now_iso
                    curr.risk_score = max(curr.risk_score, risk_assess.score)
                    if event.event_id not in curr.associated_event_ids:
                        curr.associated_event_ids.append(event.event_id)
                    self._dedup_cache[entity] = (existing_alert_id, now)
                    self._persist_alert(curr)
                    return risk_assess, curr

            # Trigger Adaptive Key Rotation if Critical (Risk >= 85.0)
            key_rotated = False
            if risk_assess.score >= 85.0 and self.key_rotator:
                decision, _ = self.key_rotator.evaluate_adaptive_rotation(
                    risk_score=risk_assess.score,
                    context={"event_id": event.event_id},
                )
                key_rotated = (decision == RotationDecision.EXECUTED)

            # Create new Alert
            new_alert_id = f"alert-{uuid.uuid4().hex[:12]}"
            new_alert = LiveSecurityAlert(
                alert_id=new_alert_id,
                created_at_utc=now_iso,
                entity_id=entity,
                risk_score=risk_assess.score,
                risk_level=risk_assess.severity.value,
                trigger_reason=trigger_reason,
                status=AlertStatus.NEW,
                occurrence_count=1,
                first_seen_utc=now_iso,
                last_seen_utc=now_iso,
                associated_event_ids=[event.event_id],
                adaptive_key_rotated=key_rotated,
                detection_latency_ms=latency_ms,
            )

            self._active_alerts[new_alert_id] = new_alert
            self._dedup_cache[entity] = (new_alert_id, now)
            self._persist_alert(new_alert)
            alert = new_alert

        return risk_assess, alert

    def _persist_alert(self, alert: LiveSecurityAlert) -> None:
        if not self.db_path:
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO live_alerts (
                        alert_id, created_at_utc, entity_id, risk_score, risk_level,
                        trigger_reason, status, occurrence_count, first_seen_utc, last_seen_utc,
                        associated_event_ids, adaptive_key_rotated, detection_latency_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.alert_id,
                        alert.created_at_utc,
                        alert.entity_id,
                        alert.risk_score,
                        alert.risk_level,
                        alert.trigger_reason,
                        alert.status.value,
                        alert.occurrence_count,
                        alert.first_seen_utc,
                        alert.last_seen_utc,
                        json.dumps(alert.associated_event_ids),
                        1 if alert.adaptive_key_rotated else 0,
                        alert.detection_latency_ms,
                    ),
                )
                conn.commit()
        except Exception:
            pass

    def list_alerts(self, limit: int = 50) -> List[LiveSecurityAlert]:
        """List active alerts in descending order of creation."""
        return sorted(list(self._active_alerts.values()), key=lambda a: a.last_seen_utc, reverse=True)[:limit]
