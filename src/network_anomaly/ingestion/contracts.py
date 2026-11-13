"""M6 Integration Contracts for FastAPI (#30), Streamlit (#16), Trace (#24), and Risk (#32)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from network_anomaly.ingestion.gate import GateDecision
from network_anomaly.ingestion.schemas import (
    CanonicalNetworkEvent,
    InferenceEligibility,
    ValidationStatus,
)


@dataclass
class APIIngestResponse:
    """Standardized response contract for FastAPI /api/v1/ingest and /analyze endpoints (Issue #30)."""

    source_id: str
    schema_version: str
    validation_status: str
    eligibility_status: str
    can_proceed_to_ml: bool
    total_records: int
    predictions_count: int
    predictions: List[Dict[str, Any]] = field(default_factory=list)
    abstention_reasons: List[str] = field(default_factory=list)
    ood_warnings: List[str] = field(default_factory=list)
    trace_route_eligible: bool = True
    risk_route_eligible: bool = True
    model_provenance: Optional[Dict[str, Any]] = None
    accepted_indices: List[int] = field(default_factory=list)
    rejected_indices: List[int] = field(default_factory=list)
    abstained_indices: List[int] = field(default_factory=list)
    accepted_count: int = 0
    rejected_count: int = 0
    abstained_count: int = 0
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "schema_version": self.schema_version,
            "validation_status": self.validation_status,
            "eligibility_status": self.eligibility_status,
            "can_proceed_to_ml": self.can_proceed_to_ml,
            "total_records": self.total_records,
            "predictions_count": self.predictions_count,
            "predictions": self.predictions,
            "abstention_reasons": self.abstention_reasons,
            "ood_warnings": self.ood_warnings,
            "trace_route_eligible": self.trace_route_eligible,
            "risk_route_eligible": self.risk_route_eligible,
            "model_provenance": self.model_provenance,
            "accepted_indices": self.accepted_indices,
            "rejected_indices": self.rejected_indices,
            "abstained_indices": self.abstained_indices,
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "abstained_count": self.abstained_count,
            "timestamp_utc": self.timestamp_utc,
        }


@dataclass
class DashboardViewModel:
    """View model contract for Streamlit UI status presentation (Issue #16)."""

    source_id: str
    source_name: str
    tier_badge: (
        str  # "PARSEABLE", "SCHEMA_COMPATIBLE", "SEMANTICALLY_COMPATIBLE", "MODEL_VALIDATED"
    )
    eligibility_badge: str  # "READY", "ABSTAINED", "FEATURE_INCOMPATIBLE", etc.
    badge_color: str  # "green", "blue", "yellow", "red"
    summary_message: str
    detailed_reasons: List[str] = field(default_factory=list)
    ood_warnings: List[str] = field(default_factory=list)
    predictions_available: bool = False
    trace_available: bool = True
    risk_available: bool = True


@dataclass
class TraceEngineContract:
    """Payload contract for Trace Engine graph correlation (Issue #24)."""

    source_id: str
    event_id: str
    raw_record_id: Optional[str]
    ipv4_src_addr: str
    l4_src_port: int
    ipv4_dst_addr: str
    l4_dst_port: int
    protocol: int
    in_bytes: int
    in_pkts: int
    flow_duration_ms: float
    timestamp: Optional[Any]
    trace_metadata: Dict[str, Any] = field(default_factory=dict)
    has_ml_prediction: bool = False
    ml_prediction_label: Optional[int] = None
    ml_confidence_score: Optional[float] = None


@dataclass
class RiskEngineContract:
    """Payload contract for Risk Engine risk calibration (Issue #32)."""

    source_id: str
    event_id: str
    validation_status: str
    eligibility_status: str
    has_ml_prediction: bool
    ml_anomaly_score: Optional[float] = None
    is_ood: bool = False
    ood_severity: str = "NONE"  # "NONE", "WARNING", "HIGH"
    heuristic_flags: List[str] = field(default_factory=list)
    signature_alerts: List[Dict[str, Any]] = field(default_factory=list)
    volume_metrics: Dict[str, Any] = field(default_factory=dict)


def create_api_response(
    events: List[CanonicalNetworkEvent],
    decision: GateDecision,
    predictions: Optional[List[Dict[str, Any]]] = None,
    model_provenance: Optional[Dict[str, Any]] = None,
) -> APIIngestResponse:
    """Construct unified APIIngestResponse from gate decision and optional predictions."""
    preds = predictions or []
    eff_source = events[0].metadata.source_id if events else "unknown"
    eff_ver = events[0].metadata.schema_version if events else "1.0.0"

    acc_indices = decision.accepted_indices
    rej_indices = decision.rejected_indices
    abs_indices = decision.abstained_indices

    return APIIngestResponse(
        source_id=eff_source,
        schema_version=eff_ver,
        validation_status=decision.validation_status.value,
        eligibility_status=decision.eligibility_status.value,
        can_proceed_to_ml=decision.can_proceed_to_ml,
        total_records=len(events),
        predictions_count=len(preds),
        predictions=preds,
        abstention_reasons=decision.abstention_reasons,
        ood_warnings=decision.warning_flags,
        trace_route_eligible=decision.route_to_trace_engine,
        risk_route_eligible=decision.route_to_risk_engine,
        model_provenance=model_provenance,
        accepted_indices=acc_indices,
        rejected_indices=rej_indices,
        abstained_indices=abs_indices,
        accepted_count=len(acc_indices),
        rejected_count=len(rej_indices),
        abstained_count=len(abs_indices),
    )


def create_dashboard_view_model(decision: GateDecision, source_name: str) -> DashboardViewModel:
    """Build dashboard presentation model from gate decision."""
    tier = decision.validation_status.value
    eligibility = decision.eligibility_status.value

    if decision.can_proceed_to_ml and tier == ValidationStatus.MODEL_VALIDATED.value:
        badge_color = "green"
        summary = "Model Validated: Full 47-feature inference active with quantitative benchmark."
    elif decision.can_proceed_to_ml:
        badge_color = "blue"
        summary = "Compatible: Full 47-feature inference active (domain validation unverified)."
    elif tier == ValidationStatus.SEMANTICALLY_COMPATIBLE.value:
        badge_color = "yellow"
        summary = "Semantically Compatible: Awaiting empirical benchmark validation."
    elif eligibility == InferenceEligibility.FEATURE_INCOMPATIBLE.value:
        badge_color = "yellow"
        summary = "Telemetry Only: Lacks 47 micro-features. Routed to Trace and Risk engines."
    elif eligibility == InferenceEligibility.ABSTAINED.value:
        badge_color = "orange"
        summary = "Abstained: Out-of-distribution values detected. Inference suppressed for safety."
    else:
        badge_color = "red"
        summary = f"Rejected: {eligibility}."

    return DashboardViewModel(
        source_id=(
            decision.compatibility_report.source_id if decision.compatibility_report else "unknown"
        ),
        source_name=source_name,
        tier_badge=tier,
        eligibility_badge=eligibility,
        badge_color=badge_color,
        summary_message=summary,
        detailed_reasons=decision.abstention_reasons,
        ood_warnings=decision.warning_flags,
        predictions_available=decision.can_proceed_to_ml,
        trace_available=decision.route_to_trace_engine,
        risk_available=decision.route_to_risk_engine,
    )


def route_to_trace_engine(
    event: CanonicalNetworkEvent, prediction_info: Optional[Dict[str, Any]] = None
) -> TraceEngineContract:
    """Format canonical event for consumption by Trace Engine (Issue #24)."""
    p_info = prediction_info or {}
    return TraceEngineContract(
        source_id=event.metadata.source_id,
        event_id=event.metadata.event_id,
        raw_record_id=event.metadata.raw_record_id,
        ipv4_src_addr=event.network_5tuple.ipv4_src_addr,
        l4_src_port=event.network_5tuple.l4_src_port,
        ipv4_dst_addr=event.network_5tuple.ipv4_dst_addr,
        l4_dst_port=event.network_5tuple.l4_dst_port,
        protocol=event.network_5tuple.protocol,
        in_bytes=event.metrics.in_bytes,
        in_pkts=event.metrics.in_pkts,
        flow_duration_ms=event.metrics.flow_duration_ms,
        timestamp=event.trace_metadata.get(
            "FLOW_START_MILLISECONDS",
            event.trace_metadata.get("timestamp", event.trace_metadata.get("start")),
        ),
        trace_metadata=event.trace_metadata,
        has_ml_prediction="prediction" in p_info,
        ml_prediction_label=p_info.get("prediction"),
        ml_confidence_score=p_info.get("confidence"),
    )


def route_to_risk_engine(
    event: CanonicalNetworkEvent,
    decision: GateDecision,
    prediction_info: Optional[Dict[str, Any]] = None,
) -> RiskEngineContract:
    """Format canonical event for consumption by Risk Engine (Issue #32)."""
    p_info = prediction_info or {}
    has_ml = "prediction" in p_info and decision.can_proceed_to_ml
    is_ood = len(event.ood_warnings) > 0 or (
        decision.ood_report is not None and decision.ood_report.has_ood_warning
    )

    alerts = []
    if "alert" in event.trace_metadata and event.trace_metadata["alert"]:
        alerts.append(event.trace_metadata["alert"])

    return RiskEngineContract(
        source_id=event.metadata.source_id,
        event_id=event.metadata.event_id,
        validation_status=decision.validation_status.value,
        eligibility_status=decision.eligibility_status.value,
        has_ml_prediction=has_ml,
        ml_anomaly_score=p_info.get("anomaly_score", p_info.get("confidence")),
        is_ood=is_ood,
        ood_severity="WARNING" if is_ood else "NONE",
        heuristic_flags=event.ood_warnings,
        signature_alerts=alerts,
        volume_metrics={
            "in_bytes": event.metrics.in_bytes,
            "in_pkts": event.metrics.in_pkts,
            "out_bytes": event.metrics.out_bytes,
            "out_pkts": event.metrics.out_pkts,
            "duration_ms": event.metrics.flow_duration_ms,
        },
    )
