"""Multi-source Data Quality Validation and Rejection Gate.

Implements Issue #91 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from network_anomaly.canonical.event import CanonicalSecurityEvent


@dataclass
class QualityMetrics:
    total_records: int = 0
    valid_records: int = 0
    duplicate_records: int = 0
    label_conflict_records: int = 0
    missing_required_fields: int = 0
    out_of_order_timestamps: int = 0
    pass_rate_pct: float = 0.0


@dataclass
class QualityReport:
    source_id: str
    status: str  # PASS, FAIL, SKIPPED
    input_sha256: str
    evaluated_at_utc: str
    metrics: QualityMetrics
    violations: List[str] = field(default_factory=list)
    rejection_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "status": self.status,
            "input_sha256": self.input_sha256,
            "evaluated_at_utc": self.evaluated_at_utc,
            "metrics": asdict(self.metrics),
            "violations": self.violations[:50],  # Cap output size for safety
            "rejection_reason": self.rejection_reason,
        }


class MultiSourceQualityGate:
    """Rigorous data quality validation gate with fail-closed rejection semantics."""

    def __init__(
        self,
        max_missing_rate: float = 0.05,
        max_duplicate_rate: float = 0.02,
        allow_label_conflicts: bool = False,
        allow_degraded: bool = False,
    ):
        self.max_missing_rate = max_missing_rate
        self.max_duplicate_rate = max_duplicate_rate
        self.allow_label_conflicts = allow_label_conflicts
        self.allow_degraded = allow_degraded

    def evaluate_events(
        self,
        events: List[CanonicalSecurityEvent],
        source_id: str,
        input_bytes_or_content: Optional[bytes] = None,
    ) -> QualityReport:
        """Evaluate canonical security events against quality thresholds."""
        if not events:
            return QualityReport(
                source_id=source_id,
                status="SKIPPED",
                input_sha256="0" * 64,
                evaluated_at_utc=datetime.now(timezone.utc).isoformat(),
                metrics=QualityMetrics(),
                violations=["No events provided for evaluation."],
            )

        # Compute SHA-256 of input content if provided, else hash event IDs
        if input_bytes_or_content:
            input_hash = hashlib.sha256(input_bytes_or_content).hexdigest()
        else:
            hasher = hashlib.sha256()
            for ev in events:
                hasher.update(ev.event_id.encode("utf-8"))
            input_hash = hasher.hexdigest()

        metrics = QualityMetrics(total_records=len(events))
        seen_keys: Dict[Tuple, Optional[str]] = {}  # 5-tuple key -> label
        violations: List[str] = []
        last_ts = None

        for idx, ev in enumerate(events):
            # 1. Required fields check
            if not ev.source_ip or ev.source_ip == "0.0.0.0":
                metrics.missing_required_fields += 1
                violations.append(f"Row {idx + 1}: Missing or invalid source_ip ({ev.source_ip})")

            # 2. Timestamp ordering
            if last_ts and ev.event_timestamp < last_ts:
                # Flag timestamp reversal if more than 60s backwards
                if (last_ts - ev.event_timestamp).total_seconds() > 60.0:
                    metrics.out_of_order_timestamps += 1
                    violations.append(
                        f"Row {idx + 1}: Non-monotonic timestamp inversion ({ev.event_timestamp} < {last_ts})"
                    )
            last_ts = ev.event_timestamp

            # 3. Duplicate and Label Conflict Detection
            proxy_key = (
                ev.source_ip,
                ev.dest_ip,
                ev.source_port,
                ev.dest_port,
                ev.protocol,
                int(ev.event_timestamp.timestamp()),
            )
            ev_label = ev.attack_category

            if proxy_key in seen_keys:
                metrics.duplicate_records += 1
                prior_label = seen_keys[proxy_key]
                if prior_label and ev_label and prior_label != ev_label:
                    metrics.label_conflict_records += 1
                    violations.append(
                        f"Row {idx + 1}: Label conflict on proxy key {proxy_key}: '{prior_label}' vs '{ev_label}'"
                    )
                else:
                    violations.append(f"Row {idx + 1}: Duplicate event proxy key {proxy_key}")
            else:
                seen_keys[proxy_key] = ev_label

        metrics.valid_records = metrics.total_records - (
            metrics.missing_required_fields
            + metrics.duplicate_records
            + metrics.label_conflict_records
        )
        metrics.pass_rate_pct = round(
            max(0.0, (metrics.valid_records / metrics.total_records) * 100.0), 2
        )

        # Check rejection thresholds
        rejection_reasons = []
        missing_rate = metrics.missing_required_fields / metrics.total_records
        duplicate_rate = metrics.duplicate_records / metrics.total_records

        if missing_rate > self.max_missing_rate:
            rejection_reasons.append(
                f"Missing field rate {missing_rate:.3f} exceeds threshold {self.max_missing_rate}"
            )

        if duplicate_rate > self.max_duplicate_rate:
            rejection_reasons.append(
                f"Duplicate rate {duplicate_rate:.3f} exceeds threshold {self.max_duplicate_rate}"
            )

        if metrics.label_conflict_records > 0 and not self.allow_label_conflicts:
            rejection_reasons.append(
                f"Detected {metrics.label_conflict_records} severe label conflicts on identical keys"
            )

        status = "PASS"
        rejection_msg = None
        if rejection_reasons:
            if self.allow_degraded:
                status = "PASS_DEGRADED"
                rejection_msg = "; ".join(rejection_reasons) + " (Degraded mode permitted)"
            else:
                status = "FAIL"
                rejection_msg = "; ".join(rejection_reasons)

        return QualityReport(
            source_id=source_id,
            status=status,
            input_sha256=input_hash,
            evaluated_at_utc=datetime.now(timezone.utc).isoformat(),
            metrics=metrics,
            violations=violations,
            rejection_reason=rejection_msg,
        )


def export_quality_report(report: QualityReport, output_path: Path) -> None:
    """Save quality report JSON to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)
