"""Real-time Risk Engine Integration and Deduplicated Live Alert Management.

Implements Issue #134 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from network_anomaly.canonical.event import CanonicalSecurityEvent
from network_anomaly.crypto.rotation import KeyRotationPolicy, RotationDecision
from network_anomaly.risk.scoring import RiskScoreOutput, RiskScorer, SeverityLevel
from network_anomaly.streaming.realtime_inference import LiveInferenceDecision

logger = logging.getLogger(__name__)

_SEVERITY_ORDER: Dict[str, int] = {
    SeverityLevel.LOW.value: 0,
    SeverityLevel.MEDIUM.value: 1,
    SeverityLevel.HIGH.value: 2,
    SeverityLevel.CRITICAL.value: 3,
}


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
    predicted_attack_category: Optional[str] = None
    attack_category_confidence: Optional[float] = None

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
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute("""
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
                        detection_latency_ms REAL NOT NULL,
                        predicted_attack_category TEXT,
                        attack_category_confidence REAL
                    )
                    """)
                existing_cols = {
                    row[1] for row in conn.execute("PRAGMA table_info(live_alerts)").fetchall()
                }
                if "predicted_attack_category" not in existing_cols:
                    conn.execute(
                        "ALTER TABLE live_alerts ADD COLUMN predicted_attack_category TEXT"
                    )
                if "attack_category_confidence" not in existing_cols:
                    conn.execute(
                        "ALTER TABLE live_alerts ADD COLUMN attack_category_confidence REAL"
                    )
                self._load_existing_alerts(conn)

    def _load_existing_alerts(self, conn: sqlite3.Connection) -> None:
        try:
            rows = conn.execute("""
                SELECT alert_id, created_at_utc, entity_id, risk_score, risk_level,
                       trigger_reason, status, occurrence_count, first_seen_utc,
                       last_seen_utc, associated_event_ids, adaptive_key_rotated,
                       detection_latency_ms, predicted_attack_category,
                       attack_category_confidence
                FROM live_alerts
                ORDER BY last_seen_utc DESC
                LIMIT 200
                """).fetchall()
        except Exception:
            return
        now_epoch = time.time()
        for row in rows:
            try:
                status_val = AlertStatus(str(row[6]))
            except ValueError:
                status_val = AlertStatus.NEW
            try:
                ev_ids = json.loads(row[10]) if row[10] else []
            except Exception:
                ev_ids = []
            if not isinstance(ev_ids, list):
                ev_ids = []
            alert = LiveSecurityAlert(
                alert_id=str(row[0]),
                created_at_utc=str(row[1]),
                entity_id=str(row[2]),
                risk_score=float(row[3]),
                risk_level=str(row[4]),
                trigger_reason=str(row[5]),
                status=status_val,
                occurrence_count=int(row[7]),
                first_seen_utc=str(row[8]),
                last_seen_utc=str(row[9]),
                associated_event_ids=[str(item) for item in ev_ids][-200:],
                adaptive_key_rotated=bool(row[11]),
                detection_latency_ms=float(row[12]),
                predicted_attack_category=str(row[13]) if row[13] is not None else None,
                attack_category_confidence=float(row[14]) if row[14] is not None else None,
            )
            self._active_alerts[alert.alert_id] = alert
            try:
                parsed_dt = datetime.fromisoformat(alert.last_seen_utc)
                if parsed_dt.tzinfo is None:
                    parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
                last_seen_epoch = parsed_dt.timestamp()
            except ValueError:
                last_seen_epoch = 0.0
            if (
                now_epoch - last_seen_epoch <= self.dedup_window_sec
                and alert.entity_id not in self._dedup_cache
            ):
                self._dedup_cache[alert.entity_id] = (alert.alert_id, last_seen_epoch)

    def process_event_risk(
        self,
        event: CanonicalSecurityEvent,
        inference_decision: Optional[LiveInferenceDecision] = None,
        behavioral_vector: Optional[Any] = None,
        baseline_deviation_score: Optional[float] = None,
        persist: bool = True,
    ) -> Tuple[RiskScoreOutput, Optional[LiveSecurityAlert]]:
        """Compute multi-criteria risk score and generate deduplicated alert if threshold exceeded."""
        now = time.time()
        start_t = time.perf_counter()

        ai_prob = inference_decision.ensemble_score if inference_decision else 0.0
        is_ood = inference_decision.is_ood if inference_decision else False

        # Calculate contextual behavioral anomaly and auth failure indicators
        beh_score = (
            0.90
            if (event.flow_metrics and event.flow_metrics.bytes_out > 50_000)
            else (0.60 if (event.flow_metrics and event.flow_metrics.bytes_out > 10_000) else 0.0)
        )
        auth_fails = (
            4
            if (event.auth_data and event.auth_data.auth_result == "FAILURE")
            else (
                2
                if (
                    event.dest_port in (22, 445)
                    and event.flow_metrics
                    and event.flow_metrics.bytes_out > 20_000
                )
                else 0
            )
        )

        if behavioral_vector is not None:
            named_features = getattr(behavioral_vector, "named_features", None)
            if not isinstance(named_features, Mapping):
                feat_names = getattr(behavioral_vector, "feature_names", None)
                feat_vals = getattr(behavioral_vector, "features", None)
                if feat_names and feat_vals and len(feat_names) == len(feat_vals):
                    named_features = dict(zip(feat_names, feat_vals))
                else:
                    named_features = None
            if isinstance(named_features, Mapping):
                dns_int = float(named_features.get("dns_intensity", 0) or 0)
                port_div = float(
                    named_features.get("unique_ports_norm")
                    or named_features.get("log_dest_port_diversity")
                    or 0
                )
                pkt_activity = float(
                    named_features.get("log_pkts_out")
                    or named_features.get("log_pkts_per_sec")
                    or 0
                )
                auth_ratio = float(named_features.get("auth_failure_ratio", 0) or 0)
                if dns_int > 0.25 or port_div > 0.25 or pkt_activity > 0.55:
                    beh_score = max(
                        beh_score,
                        min(
                            1.0,
                            0.45 + 0.30 * dns_int + 0.25 * port_div + 0.15 * pkt_activity,
                        ),
                    )
                if auth_ratio >= 0.5:
                    auth_fails = max(auth_fails, 4)

        if baseline_deviation_score is not None and math.isfinite(baseline_deviation_score):
            beh_score = max(beh_score, min(1.0, max(0.0, float(baseline_deviation_score))))

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
            pred_cat = (
                getattr(inference_decision, "predicted_attack_category", None)
                if inference_decision
                else None
            )
            cat_conf = (
                getattr(inference_decision, "attack_category_confidence", None)
                if inference_decision
                else None
            )

            # Check deduplication window
            if entity in self._dedup_cache:
                existing_alert_id, last_seen = self._dedup_cache[entity]
                if (
                    now - last_seen <= self.dedup_window_sec
                    and existing_alert_id in self._active_alerts
                ):
                    # Deduplicate into existing alert
                    curr = self._active_alerts[existing_alert_id]
                    curr.occurrence_count += 1
                    curr.last_seen_utc = now_iso
                    if risk_assess.score > curr.risk_score:
                        curr.risk_score = risk_assess.score
                    if _SEVERITY_ORDER.get(risk_assess.severity.value, -1) > _SEVERITY_ORDER.get(
                        curr.risk_level, -1
                    ):
                        curr.risk_level = risk_assess.severity.value
                    if pred_cat is not None:
                        curr.predicted_attack_category = pred_cat
                        curr.attack_category_confidence = cat_conf
                    if event.event_id not in curr.associated_event_ids:
                        curr.associated_event_ids.append(event.event_id)
                        if len(curr.associated_event_ids) > 200:
                            curr.associated_event_ids = curr.associated_event_ids[-200:]
                    if (
                        risk_assess.trigger_adaptive_rotation
                        and not curr.adaptive_key_rotated
                        and self.key_rotator
                    ):
                        decision, _ = self.key_rotator.evaluate_adaptive_rotation(
                            risk_score=risk_assess.score,
                            context={"event_id": event.event_id, "alert_id": curr.alert_id},
                        )
                        if decision == RotationDecision.EXECUTED:
                            curr.adaptive_key_rotated = True
                    self._dedup_cache[entity] = (existing_alert_id, now)
                    if persist:
                        self._persist_alert(curr)
                    return risk_assess, curr

            # Trigger Adaptive Key Rotation if RiskScorer authorizes it (fail-closed on OOD/NaN)
            key_rotated = False
            if risk_assess.trigger_adaptive_rotation and self.key_rotator:
                decision, _ = self.key_rotator.evaluate_adaptive_rotation(
                    risk_score=risk_assess.score,
                    context={"event_id": event.event_id},
                )
                key_rotated = decision == RotationDecision.EXECUTED

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
                predicted_attack_category=pred_cat,
                attack_category_confidence=cat_conf,
            )

            self._active_alerts[new_alert_id] = new_alert
            self._dedup_cache[entity] = (new_alert_id, now)
            self._enforce_cache_bounds()
            if persist:
                self._persist_alert(new_alert)
            alert = new_alert

        return risk_assess, alert

    def _enforce_cache_bounds(self) -> None:
        if len(self._active_alerts) > 2_000:
            excess = len(self._active_alerts) - 2_000
            oldest_ids = sorted(
                self._active_alerts.keys(),
                key=lambda aid: self._active_alerts[aid].last_seen_utc,
            )[:excess]
            for aid in oldest_ids:
                self._active_alerts.pop(aid, None)
        if len(self._dedup_cache) > 5_000:
            excess = len(self._dedup_cache) - 5_000
            oldest_entities = sorted(
                self._dedup_cache.keys(),
                key=lambda ent: self._dedup_cache[ent][1],
            )[:excess]
            for ent in oldest_entities:
                self._dedup_cache.pop(ent, None)

    @staticmethod
    def _alert_row(alert: LiveSecurityAlert) -> Tuple[Any, ...]:
        return (
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
            alert.predicted_attack_category,
            alert.attack_category_confidence,
        )

    def _persist_alert(self, alert: LiveSecurityAlert) -> None:
        if not self.db_path:
            return
        try:
            with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
                with conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO live_alerts (
                            alert_id, created_at_utc, entity_id, risk_score, risk_level,
                            trigger_reason, status, occurrence_count, first_seen_utc, last_seen_utc,
                            associated_event_ids, adaptive_key_rotated, detection_latency_ms,
                            predicted_attack_category, attack_category_confidence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        self._alert_row(alert),
                    )
        except Exception as exc:
            logger.warning("Failed to persist live alert %s: %s", alert.alert_id, exc)

    def persist_alerts_batch(self, alerts: Sequence[LiveSecurityAlert]) -> None:
        """Persist a batch of alerts in a single SQLite transaction."""
        if not self.db_path or not alerts:
            return
        deduped = {alert.alert_id: alert for alert in alerts}
        rows = [self._alert_row(alert) for alert in deduped.values()]
        try:
            with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
                with conn:
                    conn.executemany(
                        """
                        INSERT OR REPLACE INTO live_alerts (
                            alert_id, created_at_utc, entity_id, risk_score, risk_level,
                            trigger_reason, status, occurrence_count, first_seen_utc, last_seen_utc,
                            associated_event_ids, adaptive_key_rotated, detection_latency_ms,
                            predicted_attack_category, attack_category_confidence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        rows,
                    )
        except Exception as exc:
            logger.warning("Failed to persist batch of %d live alerts: %s", len(rows), exc)

    def list_alerts(self, limit: int = 50) -> List[LiveSecurityAlert]:
        """List active alerts in descending order of creation."""
        return sorted(
            list(self._active_alerts.values()), key=lambda a: a.last_seen_utc, reverse=True
        )[:limit]
