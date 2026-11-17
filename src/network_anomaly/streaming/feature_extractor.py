"""Real-time feature extraction with a strict, zero-imputation contract.

The extractor converts a :class:`CanonicalSecurityEvent` into the canonical v2
18-feature flow vector (`canonical-flow-v2-18`) only when every required base
field or full 18-feature mapping is genuinely present and finite:

* ``event.ml_features`` is accepted as-is when all 18 canonical features are
  present and finite.
* When ``ml_features`` is absent, all 18 features are deterministically derived
  ONLY when all 6 base observed flow fields (``duration_ms``, ``bytes_in``,
  ``bytes_out``, ``pkts_in``, ``pkts_out``, ``protocol``) are genuinely present.
* If any required base field is missing or non-finite, the event is marked
  ``NOT_MODEL_READY`` and routed to trace-only handling without silent imputation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from network_anomaly.canonical.event import CanonicalSecurityEvent, EventKind, ValidationStatus
from network_anomaly.canonical.feature_contract import get_flow_feature_contract_v2
from network_anomaly.data.v2_schema import (
    compute_flow_features_from_base,
    parse_protocol_number,
)


@dataclass
class ExtractionResult:
    event_id: str
    is_ml_ready: bool
    status: str = "NOT_MODEL_READY"
    feature_vector: Optional[np.ndarray] = None
    feature_dict: Optional[Dict[str, float]] = None
    rejection_reason: Optional[str] = None
    missing_features: List[str] = field(default_factory=list)
    mapped_feature_count: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "event_id": self.event_id,
            "is_ml_ready": self.is_ml_ready,
            "status": self.status,
            "rejection_reason": self.rejection_reason,
            "missing_features": list(self.missing_features),
            "mapped_feature_count": self.mapped_feature_count,
        }


def derive_flow_features(event: CanonicalSecurityEvent) -> Dict[str, float]:
    """Derive canonical v2 features strictly when all 6 base observed fields exist."""
    metrics = event.flow_metrics
    if metrics is None or not event.protocol:
        return {}
    required_attrs = (
        metrics.duration_ms,
        metrics.bytes_in,
        metrics.bytes_out,
        metrics.pkts_in,
        metrics.pkts_out,
    )
    if any(v is None for v in required_attrs):
        return {}
    try:
        proto_num = parse_protocol_number(event.protocol)
        return compute_flow_features_from_base(
            duration_ms=float(metrics.duration_ms),  # type: ignore[arg-type]
            bytes_in=float(metrics.bytes_in),  # type: ignore[arg-type]
            bytes_out=float(metrics.bytes_out),  # type: ignore[arg-type]
            pkts_in=float(metrics.pkts_in),  # type: ignore[arg-type]
            pkts_out=float(metrics.pkts_out),  # type: ignore[arg-type]
            protocol_num=proto_num,
        )
    except (ValueError, TypeError):
        return {}


class RealtimeFeatureExtractor:
    """Extracts the exact 18 canonical v2 features or rejects the event explicitly."""

    def __init__(self) -> None:
        self.contract = get_flow_feature_contract_v2()
        self.total_extracted: int = 0
        self.total_ml_ready: int = 0
        self.total_rejected_to_trace: int = 0
        self.total_not_model_ready: int = 0

    def extract(self, event: CanonicalSecurityEvent) -> ExtractionResult:
        """Extract a valid 18-feature v2 vector, or explain precisely why not."""
        self.total_extracted += 1

        if event.event_kind != EventKind.FLOW:
            self.total_rejected_to_trace += 1
            return ExtractionResult(
                event_id=event.event_id,
                is_ml_ready=False,
                status="ROUTE_ONLY",
                rejection_reason=f"NON_FLOW_EVENT_KIND:{event.event_kind.value.upper()}",
            )

        candidate: Dict[str, float] = {}
        if event.ml_features:
            candidate.update({str(k): float(v) for k, v in event.ml_features.items()})
        derived = derive_flow_features(event)
        for name, value in derived.items():
            candidate.setdefault(name, value)

        is_complete, missing = self.contract.validate_features(candidate)
        if not is_complete:
            self.total_not_model_ready += 1
            self.total_rejected_to_trace += 1
            event.is_ml_complete = False
            event.validation_status = ValidationStatus.FEATURE_INCOMPLETE
            return ExtractionResult(
                event_id=event.event_id,
                is_ml_ready=False,
                status="NOT_MODEL_READY",
                rejection_reason=(
                    f"FEATURE_CONTRACT_INCOMPLETE: {len(missing)} of "
                    f"{len(self.contract.feature_names)} features missing or non-finite"
                ),
                missing_features=missing,
                mapped_feature_count=len(candidate),
            )

        vector = np.asarray(
            [float(candidate[name]) for name in self.contract.feature_names], dtype=np.float64
        )
        self.total_ml_ready += 1
        event.is_ml_complete = True
        return ExtractionResult(
            event_id=event.event_id,
            is_ml_ready=True,
            status="MODEL_READY",
            feature_vector=vector,
            feature_dict={name: float(candidate[name]) for name in self.contract.feature_names},
            mapped_feature_count=len(self.contract.feature_names),
        )

    def extract_batch(
        self, events: List[CanonicalSecurityEvent]
    ) -> Tuple[List[ExtractionResult], List[CanonicalSecurityEvent]]:
        """Batch extract: returns extraction results and the route-only event list."""
        results: List[ExtractionResult] = []
        route_only_events: List[CanonicalSecurityEvent] = []

        for ev in events:
            res = self.extract(ev)
            results.append(res)
            if not res.is_ml_ready:
                if res.status != "ROUTE_ONLY":
                    ev.validation_status = ValidationStatus.FEATURE_INCOMPLETE
                    if res.rejection_reason and res.rejection_reason not in ev.validation_errors:
                        ev.validation_errors.append(res.rejection_reason)
                route_only_events.append(ev)

        return results, route_only_events
