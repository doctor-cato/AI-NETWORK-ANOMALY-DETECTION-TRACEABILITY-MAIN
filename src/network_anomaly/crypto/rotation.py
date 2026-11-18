"""Fixed and adaptive key rotation with cooldown and rate limiting.

Implements Issues #120, #121, #122 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .key_manager import KeyManager


class RotationTrigger(str, Enum):
    FIXED_SCHEDULE = "FIXED_SCHEDULE"
    ADAPTIVE_RISK = "ADAPTIVE_RISK"
    MANUAL_ADMIN = "MANUAL_ADMIN"


class RotationDecision(str, Enum):
    EXECUTED = "EXECUTED"
    REJECTED_COOLDOWN = "REJECTED_COOLDOWN"
    REJECTED_RATE_LIMIT = "REJECTED_RATE_LIMIT"
    SKIPPED_BELOW_THRESHOLD = "SKIPPED_BELOW_THRESHOLD"
    FAILED_ERROR = "FAILED_ERROR"


@dataclass
class RotationAuditRecord:
    rotation_id: str
    trigger: RotationTrigger
    decision: RotationDecision
    domain: str
    old_key_id: Optional[str]
    new_key_id: Optional[str]
    risk_score: Optional[float]
    reason: str
    timestamp: str


class KeyRotationPolicy:
    """Enforces rotation rules: fixed 30-min schedule, risk-based adaptive, cooldown, rate-limit."""

    DEFAULT_FIXED_INTERVAL_SECONDS = 1800  # 30 minutes
    DEFAULT_COOLDOWN_SECONDS = 60  # 1 minute between consecutive rotations
    DEFAULT_MAX_ROTATIONS_PER_HOUR = 10  # Max 10 rotations per hour
    DEFAULT_ADAPTIVE_RISK_THRESHOLD = 85.0  # High risk threshold triggers rotation

    def __init__(
        self,
        key_manager: KeyManager,
        db_path: Optional[Path] = None,
        fixed_interval_seconds: int = DEFAULT_FIXED_INTERVAL_SECONDS,
        cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS,
        max_rotations_per_hour: int = DEFAULT_MAX_ROTATIONS_PER_HOUR,
        adaptive_risk_threshold: float = DEFAULT_ADAPTIVE_RISK_THRESHOLD,
        clock_fn: Optional[Callable[[], datetime]] = None,
    ):
        self.key_manager = key_manager
        self.db_path = db_path
        self.fixed_interval_seconds = fixed_interval_seconds
        self.cooldown_seconds = cooldown_seconds
        self.max_rotations_per_hour = max_rotations_per_hour
        self.adaptive_risk_threshold = adaptive_risk_threshold
        self.clock_fn: Callable[[], datetime] = clock_fn or (lambda: datetime.now(timezone.utc))

        # Audit trail & rate limiter (backed by SQLite when db_path is configured)
        self._history: List[RotationAuditRecord] = []
        self._last_rotation_time: Dict[str, float] = {}
        self._load_persisted_state()

    def _now_dt(self) -> datetime:
        now_dt = self.clock_fn()
        if now_dt.tzinfo is None:
            return now_dt.replace(tzinfo=timezone.utc)
        return now_dt.astimezone(timezone.utc)

    def _infer_domain(self, rotation_id: str, key_id: Optional[str]) -> str:
        if key_id:
            meta = self.key_manager.get_metadata(key_id)
            if meta and getattr(meta, "domain", None):
                return str(meta.domain)
        if rotation_id.startswith("rot-") and "-" in rotation_id[4:]:
            return rotation_id[4:].rsplit("-", 1)[0]
        return "general"

    def _load_persisted_state(self) -> None:
        if not self.db_path or not self.db_path.exists():
            return
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT rotation_id, triggered_by, old_key_id, new_key_id, status, reason, created_at
                FROM rotation_audit
                ORDER BY created_at ASC;
                """).fetchall()
            conn.close()
        except Exception:
            return

        for row in rows:
            try:
                trigger = RotationTrigger(row["triggered_by"])
                decision = RotationDecision(row["status"])
            except ValueError:
                continue
            new_kid = row["new_key_id"] or None
            old_kid = row["old_key_id"] or None
            domain = self._infer_domain(row["rotation_id"], new_kid or old_kid)
            rec = RotationAuditRecord(
                rotation_id=row["rotation_id"],
                trigger=trigger,
                decision=decision,
                domain=domain,
                old_key_id=old_kid,
                new_key_id=new_kid,
                risk_score=None,
                reason=row["reason"] or "",
                timestamp=row["created_at"],
            )
            self._history.append(rec)
            if decision == RotationDecision.EXECUTED:
                ts_val = datetime.fromisoformat(row["created_at"]).timestamp()
                prev = self._last_rotation_time.get(domain, 0.0)
                if ts_val > prev:
                    self._last_rotation_time[domain] = ts_val

    def can_rotate(self, domain: str = "general") -> Tuple[bool, Optional[RotationDecision], str]:
        """Check if rotation is permitted by cooldown and rate-limit guardrails."""
        now = self._now_dt().timestamp()
        last_time = self._last_rotation_time.get(domain, 0.0)

        # 1. Check Cooldown
        elapsed = now - last_time
        if elapsed < self.cooldown_seconds:
            remaining = int(self.cooldown_seconds - elapsed)
            return (
                False,
                RotationDecision.REJECTED_COOLDOWN,
                f"Rotation cooldown active: wait {remaining}s",
            )

        # 2. Check Rate Limit (rotations in past 3600 seconds)
        one_hour_ago = now - 3600.0
        recent_count = sum(
            1
            for rec in self._history
            if rec.domain == domain
            and rec.decision == RotationDecision.EXECUTED
            and datetime.fromisoformat(rec.timestamp).timestamp() >= one_hour_ago
        )

        if recent_count >= self.max_rotations_per_hour:
            return (
                False,
                RotationDecision.REJECTED_RATE_LIMIT,
                f"Rate limit reached ({recent_count}/{self.max_rotations_per_hour} per hour)",
            )

        return True, None, "Rotation permitted"

    def execute_rotation(
        self,
        trigger: RotationTrigger,
        domain: str = "general",
        risk_score: Optional[float] = None,
        reason: str = "",
    ) -> Tuple[RotationDecision, Optional[str]]:
        """Execute key rotation if permitted by policy, or record rejection."""
        now_dt = self._now_dt()
        rot_id = f"rot-{domain}-{now_dt.strftime('%Y%m%d%H%M%S%f')}"

        permitted, decision, msg = self.can_rotate(domain=domain)
        if not permitted:
            rec = RotationAuditRecord(
                rotation_id=rot_id,
                trigger=trigger,
                decision=decision,
                domain=domain,
                old_key_id=self.key_manager._active_key_ids.get(domain),
                new_key_id=None,
                risk_score=risk_score,
                reason=msg,
                timestamp=now_dt.isoformat(),
            )
            self._history.append(rec)
            self._persist_audit_record(rec)
            return decision, msg

        # Execute rotation
        old_key_id = self.key_manager._active_key_ids.get(domain)
        try:
            new_km = self.key_manager.generate_key(domain=domain)
            self._last_rotation_time[domain] = now_dt.timestamp()

            rec = RotationAuditRecord(
                rotation_id=rot_id,
                trigger=trigger,
                decision=RotationDecision.EXECUTED,
                domain=domain,
                old_key_id=old_key_id,
                new_key_id=new_km.key_id,
                risk_score=risk_score,
                reason=reason or f"Triggered by {trigger.value}",
                timestamp=now_dt.isoformat(),
            )
            self._history.append(rec)
            self._persist_audit_record(rec)
            return RotationDecision.EXECUTED, new_km.key_id
        except Exception as e:
            rec = RotationAuditRecord(
                rotation_id=rot_id,
                trigger=trigger,
                decision=RotationDecision.FAILED_ERROR,
                domain=domain,
                old_key_id=old_key_id,
                new_key_id=None,
                risk_score=risk_score,
                reason=f"Rotation failed: {e}",
                timestamp=now_dt.isoformat(),
            )
            self._history.append(rec)
            self._persist_audit_record(rec)
            return RotationDecision.FAILED_ERROR, str(e)

    def evaluate_adaptive_rotation(
        self,
        risk_score: float,
        domain: str = "general",
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RotationDecision, Optional[str]]:
        """Evaluate adaptive rotation triggered by high risk anomaly."""
        if risk_score < self.adaptive_risk_threshold:
            return (
                RotationDecision.SKIPPED_BELOW_THRESHOLD,
                f"Risk score {risk_score:.1f} < threshold {self.adaptive_risk_threshold:.1f}",
            )

        reason = f"High Risk Anomaly Detected (Risk Score={risk_score:.1f} >= {self.adaptive_risk_threshold:.1f})"
        if context:
            reason += f" | Event: {context.get('event_id', 'unknown')}"

        return self.execute_rotation(
            trigger=RotationTrigger.ADAPTIVE_RISK,
            domain=domain,
            risk_score=risk_score,
            reason=reason,
        )

    def check_fixed_schedule(
        self, domain: str = "general"
    ) -> Tuple[RotationDecision, Optional[str]]:
        """Check if 30-minute interval has elapsed for fixed schedule rotation."""
        active_id = self.key_manager._active_key_ids.get(domain)
        if not active_id:
            return self.execute_rotation(
                trigger=RotationTrigger.FIXED_SCHEDULE,
                domain=domain,
                reason="Initial key generation",
            )

        km = self.key_manager.get_metadata(active_id)
        if not km:
            return self.execute_rotation(
                trigger=RotationTrigger.FIXED_SCHEDULE,
                domain=domain,
                reason="Missing active metadata",
            )

        created = datetime.fromisoformat(km.created_at)
        elapsed = (self._now_dt() - created).total_seconds()

        if elapsed >= self.fixed_interval_seconds:
            return self.execute_rotation(
                trigger=RotationTrigger.FIXED_SCHEDULE,
                domain=domain,
                reason=f"Fixed 30-min schedule expired (elapsed {int(elapsed)}s)",
            )
        return (
            RotationDecision.SKIPPED_BELOW_THRESHOLD,
            f"Schedule active: elapsed {int(elapsed)}s < {self.fixed_interval_seconds}s",
        )

    def _persist_audit_record(self, record: RotationAuditRecord) -> None:
        """Persist audit record into SQLite rotation_audit table if db is provided."""
        if not self.db_path or not self.db_path.exists():
            return
        try:
            conn = sqlite3.connect(str(self.db_path))
            with conn:
                conn.execute(
                    """
                    INSERT INTO rotation_audit (
                        rotation_id, triggered_by, old_key_id, new_key_id, dry_run, status, reason, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        record.rotation_id,
                        record.trigger.value,
                        record.old_key_id,
                        record.new_key_id or "",
                        0,  # real rotation
                        record.decision.value,
                        record.reason,
                        record.timestamp,
                    ),
                )
            conn.close()
        except Exception:
            pass

    def get_audit_history(self) -> List[RotationAuditRecord]:
        return list(self._history)
