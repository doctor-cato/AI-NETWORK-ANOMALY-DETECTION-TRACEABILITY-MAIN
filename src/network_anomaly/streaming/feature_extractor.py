"""Real-time feature extraction with a strict, zero-imputation contract.

The extractor converts a :class:`CanonicalSecurityEvent` into the canonical 47
feature vector only when every contract feature is genuinely present in the
event. It never fills missing values:

* ``event.ml_features`` is the authoritative carrier of model-space features.
  A complete, finite 47-field mapping is accepted as-is.
* A partial mapping is *not* padded. The event is marked
  ``NOT_MODEL_READY`` and routed to trace-only handling with the exact list of
  missing features.
* When ``ml_features`` is absent, only fields that map one-to-one from decoded
  flow metrics are derived. With a standard NetFlow v9 template that yields a
  handful of the 47 features, so the event is (correctly) rejected for ML.

No constant, median, or zero imputation happens here. Imputation, if any, is
owned by the frozen train-fitted preprocessor downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from network_anomaly.canonical.event import CanonicalSecurityEvent, EventKind, ValidationStatus
from network_anomaly.canonical.feature_contract import get_baseline_47_feature_contract

# Features that a decoded flow record can legitimately supply one-to-one.
# L4 ports, IP addresses and timestamps are trace metadata, NOT model features.
FLOW_METRIC_FEATURE_MAP: Dict[str, str] = {
    "IN_BYTES": "bytes_in",
    "IN_PKTS": "pkts_in",
    "OUT_BYTES": "bytes_out",
    "OUT_PKTS": "pkts_out",
    "TCP_FLAGS": "tcp_flags",
    "FLOW_DURATION_MILLISECONDS": "duration_ms",
}

PROTOCOL_NUMBERS = {"TCP": 6.0, "UDP": 17.0, "ICMP": 1.0, "ICMPV6": 58.0}


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
    """Derive only the contract features that the event genuinely carries."""
    derived: Dict[str, float] = {}
    metrics = event.flow_metrics
    if metrics is not None:
        for feature_name, metric_attr in FLOW_METRIC_FEATURE_MAP.items():
            value = getattr(metrics, metric_attr)
            if value is not None:
                derived[feature_name] = float(value)
    if event.protocol and "PROTOCOL" not in derived:
        protocol_number = PROTOCOL_NUMBERS.get(event.protocol.upper())
        if protocol_number is not None:
            derived["PROTOCOL"] = protocol_number
    return derived


class RealtimeFeatureExtractor:
    """Extracts the exact 47 baseline features or rejects the event explicitly."""

    def __init__(self) -> None:
        self.contract = get_baseline_47_feature_contract()
        self.total_extracted: int = 0
        self.total_ml_ready: int = 0
        self.total_rejected_to_trace: int = 0
        self.total_not_model_ready: int = 0

    def extract(self, event: CanonicalSecurityEvent) -> ExtractionResult:
        """Extract a valid 47-feature vector, or explain precisely why not."""
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
