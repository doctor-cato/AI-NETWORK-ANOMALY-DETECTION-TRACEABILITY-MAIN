"""Real-Time Feature Extraction and Missing-Feature Rejection Gate.

Implements Issue #132 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from network_anomaly.canonical.event import CanonicalSecurityEvent, EventKind, ValidationStatus
from network_anomaly.canonical.feature_contract import get_baseline_47_feature_contract


@dataclass
class ExtractionResult:
    event_id: str
    is_ml_ready: bool
    feature_vector: Optional[np.ndarray] = None
    feature_dict: Optional[Dict[str, float]] = None
    rejection_reason: Optional[str] = None
    missing_features: List[str] = field(default_factory=list)


class RealtimeFeatureExtractor:
    """Extracts exactly 47 baseline features with zero silent imputation and fail-closed rejection."""

    def __init__(self):
        self.contract = get_baseline_47_feature_contract()
        self.total_extracted: int = 0
        self.total_ml_ready: int = 0
        self.total_rejected_to_trace: int = 0

    def extract(self, event: CanonicalSecurityEvent) -> ExtractionResult:
        """Extract feature vector or reject to route_only trace pipeline."""
        self.total_extracted += 1

        # Non-flow events are intrinsically route_only
        if event.event_kind != EventKind.FLOW:
            self.total_rejected_to_trace += 1
            return ExtractionResult(
                event_id=event.event_id,
                is_ml_ready=False,
                rejection_reason=f"NON_FLOW_EVENT_KIND:{event.event_kind.value.upper()}",
            )

        # If event already has ml_features attached
        if event.ml_features and event.is_ml_complete:
            is_valid, missing = self.contract.validate_features(event.ml_features)
            if is_valid:
                vec = np.array(
                    [float(event.ml_features[k]) for k in self.contract.feature_names],
                    dtype=np.float64,
                )
                self.total_ml_ready += 1
                return ExtractionResult(
                    event_id=event.event_id,
                    is_ml_ready=True,
                    feature_vector=vec,
                    feature_dict=event.ml_features,
                )

        # Attempt to synthesize from flow_metrics if available
        synth_features: Dict[str, float] = {}
        if event.flow_metrics:
            fm = event.flow_metrics
            synth_features["FLOW_DURATION_MILLISECONDS"] = float(fm.duration_ms)
            synth_features["IN_BYTES"] = float(fm.bytes_in)
            synth_features["OUT_BYTES"] = float(fm.bytes_out)
            synth_features["IN_PKTS"] = float(fm.pkts_in)
            synth_features["OUT_PKTS"] = float(fm.pkts_out)
            synth_features["TCP_FLAGS"] = float(fm.tcp_flags)
            synth_features["L4_SRC_PORT"] = float(event.source_port or 0)
            synth_features["L4_DST_PORT"] = float(event.dest_port or 0)
            synth_features["PROTOCOL"] = (
                6.0 if event.protocol == "TCP" else (17.0 if event.protocol == "UDP" else 0.0)
            )

        # Check completeness against all 47 features
        is_complete, missing = self.contract.validate_features(synth_features)

        if not is_complete:
            # STRICT ZERO-IMPUTATION: Never inject 0/median
            self.total_rejected_to_trace += 1
            return ExtractionResult(
                event_id=event.event_id,
                is_ml_ready=False,
                rejection_reason=f"INCOMPLETE_NPROBE_FEATURES: missing {len(missing)} of 47",
                missing_features=missing,
            )

        vec = np.array([synth_features[k] for k in self.contract.feature_names], dtype=np.float64)
        self.total_ml_ready += 1
        return ExtractionResult(
            event_id=event.event_id,
            is_ml_ready=True,
            feature_vector=vec,
            feature_dict=synth_features,
        )

    def extract_batch(
        self, events: List[CanonicalSecurityEvent]
    ) -> Tuple[List[ExtractionResult], List[CanonicalSecurityEvent]]:
        """Batch extract: returns extraction results and the list of route_only events."""
        results: List[ExtractionResult] = []
        route_only_events: List[CanonicalSecurityEvent] = []

        for ev in events:
            res = self.extract(ev)
            results.append(res)
            if not res.is_ml_ready:
                ev.is_ml_complete = False
                ev.validation_status = ValidationStatus.FEATURE_INCOMPLETE
                if res.rejection_reason:
                    ev.validation_errors.append(res.rejection_reason)
                route_only_events.append(ev)

        return results, route_only_events
