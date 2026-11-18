"""Pydantic schemas for FastAPI contracts, requests, responses, and validation.

All schemas enforce strict typing, data boundary validation, and fail-safe serialization.
Sensitive secret materials are strictly excluded from all schemas.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CANONICAL_MODEL_KEYS: Tuple[str, ...] = (
    "random_forest",
    "xgboost",
    "isolation_forest",
    "autoencoder",
)

MODEL_ALIAS_MAP: Dict[str, str] = {
    "random_forest": "random_forest",
    "randomforest": "random_forest",
    "random_forest_baseline": "random_forest",
    "rf": "random_forest",
    "xgboost": "xgboost",
    "xgb": "xgboost",
    "xgboost_baseline": "xgboost",
    "isolation_forest": "isolation_forest",
    "isolationforest": "isolation_forest",
    "if": "isolation_forest",
    "iforest": "isolation_forest",
    "autoencoder": "autoencoder",
    "ae": "autoencoder",
    "mlp_autoencoder": "autoencoder",
}


def canonicalize_model_name(model_name: Optional[str]) -> str:
    """Normalize an API or CLI model selector onto the strict 4-model allowlist."""
    if model_name is None:
        return "random_forest"
    if not isinstance(model_name, str):
        raise ValueError(
            f"Unsupported model_name type {type(model_name).__name__!r}. "
            f"Allowed models: {', '.join(CANONICAL_MODEL_KEYS)}."
        )
    stripped = model_name.strip()
    if not stripped:
        raise ValueError(
            "model_name cannot be empty or whitespace. "
            f"Allowed models: {', '.join(CANONICAL_MODEL_KEYS)}."
        )
    normalized = re.sub(r"[\s\-]+", "_", stripped.lower())
    canonical = MODEL_ALIAS_MAP.get(normalized)
    if canonical is None:
        raise ValueError(
            f"Unsupported model_name {model_name!r}. "
            f"Allowed models: {', '.join(CANONICAL_MODEL_KEYS)}."
        )
    return canonical


def _require_finite_float(value: Any, field_name: str) -> float:
    """Reject booleans, NaN, and +/-Inf for scalar numeric score fields."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a finite real number")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ValueError(f"{field_name} must be finite (NaN/Inf rejected)")
    return numeric


class HealthResponse(BaseModel):
    """Schema for health and readiness checks."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="Overall status: 'healthy' or 'degraded'")
    process_alive: bool = Field(
        True, description="Indicates if the API server process is responding"
    )
    model_ready: bool = Field(
        ..., description="Indicates if ML model artifact is loaded and verified"
    )
    preprocessor_ready: bool = Field(
        ..., description="Indicates if preprocessor artifact is loaded and verified"
    )
    db_ready: bool = Field(..., description="Indicates if SQLite persistence layer is operational")
    version: str = Field(..., description="Package version")
    git_commit: str = Field("unknown", description="Git commit SHA")
    timestamp: str = Field(..., description="Current ISO 8601 UTC timestamp")
    details: Dict[str, Any] = Field(
        default_factory=dict, description="Component diagnostics details"
    )


class FlowEventInput(BaseModel):
    """Input representation of a network flow event."""

    model_config = ConfigDict(extra="allow")

    event_id: Optional[str] = Field(None, description="Client-supplied or auto-generated event ID")
    session_id: Optional[str] = Field(None, description="Optional associated session ID")
    timestamp: Optional[str] = Field(None, description="ISO 8601 event timestamp")
    source_ip: Optional[str] = Field(None, description="Source IPv4 address")
    dest_ip: Optional[str] = Field(None, description="Destination IPv4 address")
    source_port: Optional[int] = Field(None, ge=0, le=65535, description="Source L4 port")
    dest_port: Optional[int] = Field(None, ge=0, le=65535, description="Destination L4 port")
    protocol: Optional[Union[str, int]] = Field(None, description="L4 transport protocol")
    features: Dict[str, Any] = Field(
        default_factory=dict, description="Baseline ML features or raw telemetry"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict, description="Trace and operational metadata"
    )


class FlowEventResponse(BaseModel):
    """Output representation of a stored network flow event."""

    model_config = ConfigDict(from_attributes=True)

    event_id: str
    session_id: Optional[str] = None
    timestamp: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    features: Dict[str, Any] = Field(default_factory=dict)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    created_at: str


class IngestBatchRequest(BaseModel):
    """Request payload for ingesting one or more events."""

    model_config = ConfigDict(extra="forbid")

    events: List[FlowEventInput] = Field(
        ..., min_length=1, max_length=1000, description="Batch of flow events"
    )
    session_id: Optional[str] = Field(None, description="Optional common session ID for batch")
    idempotency_key: Optional[str] = Field(
        None, description="Unique key for deduplicating ingestion"
    )


class IngestResponse(BaseModel):
    """Response returned upon successful ingestion."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field("ok", description="Status confirmation")
    ingested_count: int = Field(..., ge=0, description="Total events successfully persisted")
    event_ids: List[str] = Field(default_factory=list, description="IDs of persisted events")
    session_id: Optional[str] = Field(None, description="Session ID assigned or associated")


class AnalyzeRequest(BaseModel):
    """Request payload for anomaly detection inference."""

    model_config = ConfigDict(extra="allow")

    events: List[Dict[str, Any]] = Field(
        ..., min_length=1, description="List of flow records to analyze"
    )
    model_name: str = Field(
        default="random_forest",
        description=(
            "Canonical model family ('random_forest', 'xgboost', 'isolation_forest', "
            "or 'autoencoder') or supported alias"
        ),
    )
    threshold: Optional[float] = Field(
        0.5,
        ge=0.0,
        le=1.0,
        description="Decision threshold for explicitly enabled heuristic fallback only",
    )
    create_incidents: bool = Field(
        True, description="Whether to automatically create incident records for high anomalies"
    )
    allow_heuristic_fallback: bool = Field(
        False,
        description=(
            "Whether to allow heuristic fallback when verified model "
            "artifacts are unavailable or inference fails"
        ),
    )

    @field_validator("model_name", mode="before")
    @classmethod
    def validate_model_name(cls, v: Any) -> str:
        return canonicalize_model_name(v)


class AnalyzeResultItem(BaseModel):
    """Single inference result row preserving model-specific anomaly score semantics."""

    model_config = ConfigDict(extra="forbid")

    index: int = Field(..., ge=0, description="Row index in input batch")
    event_id: Optional[str] = Field(None, description="Associated event ID if provided")
    is_anomaly: bool = Field(
        ..., description="True when the active inference mode predicts anomaly"
    )
    anomaly_score: float = Field(
        ...,
        description=(
            "Unclamped raw model anomaly score or supervised attack probability "
            "(matching raw_anomaly_score; never clamped into [0, 1] for unsupervised models)"
        ),
    )
    raw_anomaly_score: Optional[float] = Field(
        default=None,
        description=(
            "Exact finite raw model anomaly/reconstruction score or supervised attack "
            "probability without clamping or heuristic scaling"
        ),
    )
    normalized_anomaly_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Calibrated UI-friendly [0, 1] anomaly score when a valid Train/Validation "
            "calibration contract exists (or attack probability for supervised classifiers); "
            "null otherwise"
        ),
    )
    attack_probability: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Attack class probability emitted by supervised probabilistic models; "
            "null for unsupervised or heuristic models"
        ),
    )
    probabilities: Optional[Dict[str, float]] = Field(
        None,
        description="Per-class probabilities (e.g. {'Benign': p0, 'Attack': p1}) when emitted by the model",
    )
    score_type: str = Field(
        default="anomaly_score",
        description=(
            "Semantic score type: 'attack_probability', 'isolation_forest_anomaly_score', "
            "'reconstruction_error_mse', or 'heuristic_rule_score'"
        ),
    )
    score_direction: str = Field(
        default="higher_is_more_anomalous",
        description="Ordering direction of anomaly_score and raw_anomaly_score",
    )
    decision_threshold: Optional[float] = Field(
        default=None,
        description="Frozen Validation-calibrated or classifier decision threshold used for prediction",
    )
    prediction: int = Field(..., description="Binary prediction: 0 (Normal), 1 (Anomaly)")
    attack_type: Optional[str] = Field(None, description="Inferred or classified attack category")
    model_used: str = Field(..., description="Canonical model identifier used for analysis")
    incident_created: bool = Field(
        False, description="Whether an incident was persisted for this flow"
    )
    incident_id: Optional[str] = Field(None, description="Generated incident ID if created")
    inference_mode: str = Field(
        "verified_model",
        description="Inference execution mode: 'verified_model' or 'heuristic_fallback'",
    )
    model_sha256: Optional[str] = Field(
        None, description="SHA-256 digest of the verified model artifact"
    )
    preprocessor_sha256: Optional[str] = Field(
        None, description="SHA-256 digest of the verified preprocessor artifact"
    )
    run_id: Optional[str] = Field(
        None, description="Unique traceable run identifier for the inference execution"
    )

    @field_validator("anomaly_score", mode="before")
    @classmethod
    def validate_anomaly_score_finite(cls, v: Any) -> float:
        return _require_finite_float(v, "anomaly_score")

    @field_validator("raw_anomaly_score", "decision_threshold", mode="before")
    @classmethod
    def validate_optional_score_finite(cls, v: Any, info: Any) -> Optional[float]:
        if v is None:
            return None
        return _require_finite_float(v, info.field_name)

    @field_validator("normalized_anomaly_score", "attack_probability", mode="before")
    @classmethod
    def validate_unit_interval_score(cls, v: Any, info: Any) -> Optional[float]:
        if v is None:
            return None
        return _require_finite_float(v, info.field_name)

    @model_validator(mode="after")
    def populate_raw_score_default(self) -> AnalyzeResultItem:
        if self.raw_anomaly_score is None:
            self.raw_anomaly_score = self.anomaly_score
        return self


class AnalyzeResponse(BaseModel):
    """Response returned from analysis inference."""

    model_config = ConfigDict(extra="forbid")

    model_ready: bool = Field(..., description="Whether verified production model was used")
    count: int = Field(..., ge=0, description="Number of analyzed items")
    anomalies_detected: int = Field(
        ..., ge=0, description="Number of items classified as anomalous"
    )
    results: List[AnalyzeResultItem] = Field(default_factory=list)
    anomaly_scores: List[float] = Field(
        default_factory=list,
        description="Batch-level unclamped anomaly scores aligned with results order",
    )
    probabilities: Optional[List[Dict[str, float]]] = Field(
        None,
        description="Batch-level per-item class probabilities aligned with results order when emitted",
    )
    timestamp: str = Field(...)
    inference_mode: str = Field(
        "verified_model",
        description="Overall inference execution mode: 'verified_model' or 'heuristic_fallback'",
    )
    model_sha256: Optional[str] = Field(
        None, description="SHA-256 digest of the verified model artifact used"
    )
    preprocessor_sha256: Optional[str] = Field(
        None, description="SHA-256 digest of the verified preprocessor artifact used"
    )
    run_id: Optional[str] = Field(
        None, description="Unique traceable run identifier for this analysis batch"
    )

    @field_validator("anomaly_scores", mode="before")
    @classmethod
    def validate_anomaly_scores_finite(cls, v: Any) -> List[float]:
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("anomaly_scores must be a list of finite real numbers")
        return [_require_finite_float(item, "anomaly_scores item") for item in v]


class IncidentCreateRequest(BaseModel):
    """Payload to create an incident alert."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=3, max_length=200)
    severity: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    attack_type: Optional[str] = None
    description: Optional[str] = ""
    event_id: Optional[str] = None
    session_id: Optional[str] = None
    evidence_id: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"Severity must be one of {allowed}")
        return v.upper()


class IncidentUpdateRequest(BaseModel):
    """Payload to update an incident."""

    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(None, min_length=3, max_length=200)
    severity: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"Severity must be one of {allowed}")
        return v.upper()

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        allowed = {"OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"}
        if v.upper() not in allowed:
            raise ValueError(f"Status must be one of {allowed}")
        return v.upper()


class IncidentResponse(BaseModel):
    """Representation of an incident alert."""

    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    title: str
    severity: str
    status: str
    anomaly_score: float
    attack_type: Optional[str] = None
    description: Optional[str] = None
    event_id: Optional[str] = None
    session_id: Optional[str] = None
    evidence_id: Optional[str] = None
    created_at: str
    updated_at: str


class PaginatedIncidentsResponse(BaseModel):
    """Paginated collection of incidents."""

    model_config = ConfigDict(extra="forbid")

    items: List[IncidentResponse]
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1)
    offset: int = Field(..., ge=0)
    has_more: bool


class TimelineItemResponse(BaseModel):
    """Unified timeline entry combining events, alerts, and key rotations."""

    model_config = ConfigDict(extra="forbid")

    id: str
    event_type: str = Field(..., description="'flow_event', 'incident', or 'key_rotation'")
    timestamp: str
    severity: Optional[str] = None
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)


class PaginatedTimelineResponse(BaseModel):
    """Paginated collection of timeline items."""

    model_config = ConfigDict(extra="forbid")

    items: List[TimelineItemResponse]
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1)
    offset: int = Field(..., ge=0)
    has_more: bool


class KeyRotationRequest(BaseModel):
    """Request payload for triggering key rotation."""

    model_config = ConfigDict(extra="forbid")

    triggered_by: str = Field("operator", min_length=1, max_length=100)
    dry_run: bool = Field(
        True, description="If True, performs policy simulation without OS impacts"
    )
    reason: Optional[str] = Field("Manual or policy rotation", max_length=500)
    idempotency_key: Optional[str] = Field(None, max_length=128)


class KeyRotationResponse(BaseModel):
    """Response returned upon key rotation action."""

    model_config = ConfigDict(extra="forbid")

    rotation_id: str
    status: str
    dry_run: bool
    old_key_id: Optional[str] = None
    new_key_id: str
    created_at: str
    message: str


class KeyMetadataResponse(BaseModel):
    """Non-sensitive metadata description of an encryption key."""

    model_config = ConfigDict(from_attributes=True)

    key_id: str
    algorithm: str
    version: int
    status: str
    created_at: str
    retired_at: Optional[str] = None


class RotationAuditItemResponse(BaseModel):
    """Audit trail record of a key rotation."""

    model_config = ConfigDict(from_attributes=True)

    rotation_id: str
    triggered_by: str
    old_key_id: Optional[str] = None
    new_key_id: str
    dry_run: bool
    status: str
    reason: Optional[str] = None
    created_at: str


class PaginatedRotationAuditResponse(BaseModel):
    """Paginated collection of rotation audit records."""

    model_config = ConfigDict(extra="forbid")

    items: List[RotationAuditItemResponse]
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1)
    offset: int = Field(..., ge=0)
    has_more: bool


class ErrorDetailResponse(BaseModel):
    """Safe, sanitized error schema that never leaks secrets or internal stacks."""

    model_config = ConfigDict(extra="forbid")

    error: str = Field(..., description="High-level error classification")
    detail: str = Field(..., description="Safe description of the validation or business failure")
    status_code: int = Field(..., ge=400, le=599)


# ---------------------------------------------------------------------------
# Desktop M6 CSV Inspection, Batch Inference, Evaluation & Export Schemas
# ---------------------------------------------------------------------------


class ModelStatusItem(BaseModel):
    """Readiness and provenance status for one of the 4 canonical M6 models."""

    model_config = ConfigDict(extra="forbid")

    model_key: str
    display_name: str
    model_type: str
    ready: bool
    status: str
    artifact_path: Optional[str] = None
    manifest_path: Optional[str] = None
    artifact_sha256: Optional[str] = None
    run_id: Optional[str] = None
    decision_threshold: Optional[float] = None
    score_semantics: Optional[str] = None
    reason: Optional[str] = None
    artifact_verified: bool = False
    in_domain_evaluated: bool = False
    cross_source_validated: bool = False
    deployment_tier: str = "RESEARCH_ONLY"


class CsvInspectRequest(BaseModel):
    """Request to validate and preview a local NetFlow CSV file."""

    model_config = ConfigDict(extra="forbid")

    file_path: str = Field(..., min_length=1)
    preview_limit: int = Field(default=20, ge=1, le=200)


class OodSummarySchema(BaseModel):
    """Summary of Out-of-Distribution protocol invariants and telemetry drift."""

    model_config = ConfigDict(extra="forbid")

    total_rows: int = Field(..., ge=0)
    has_ood_warning: bool
    hard_violation_count: int = Field(..., ge=0)
    shortcut_shift_count: int = Field(..., ge=0)
    zero_ttl_count: int = Field(..., ge=0)
    affected_rows_count: int = Field(..., ge=0)
    shortcut_drift_ratio: float = Field(..., ge=0.0, le=1.0)
    zero_ttl_ratio: float = Field(..., ge=0.0, le=1.0)
    abstention_rate: float = Field(..., ge=0.0, le=1.0)
    prediction_coverage: float = Field(..., ge=0.0, le=1.0)
    ood_flags: List[str] = Field(default_factory=list)
    hard_violation_indices: List[int] = Field(default_factory=list)
    zero_ttl_indices: List[int] = Field(default_factory=list)
    out_of_range_details: Dict[str, int] = Field(default_factory=dict)


class CompatibilityGateSummarySchema(BaseModel):
    """Feature compatibility and inference eligibility gate decision (#46)."""

    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(default="source:flow-v2-unverified")
    provenance_verified: bool = Field(default=False)
    model_key: str
    model_identifier: Optional[str] = None
    eligible: bool
    eligibility_status: str
    compatibility_status: str
    reasons: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    missing_features: List[str] = Field(default_factory=list)


class BehavioralTopItem(BaseModel):
    """Descriptive frequency entry for non-ML NetFlow behavioral statistics (#28)."""

    model_config = ConfigDict(extra="forbid")

    key: str
    count: int = Field(..., ge=0)
    share: float = Field(..., ge=0.0, le=1.0)


class BehavioralSummarySchema(BaseModel):
    """Pure descriptive statistics derived solely from NetFlow metadata (#28)."""

    model_config = ConfigDict(extra="forbid")

    total_flows: int = Field(..., ge=0)
    unique_src_ips: int = Field(..., ge=0)
    unique_dst_ips: int = Field(..., ge=0)
    unique_src_ports: int = Field(..., ge=0)
    unique_dst_ports: int = Field(..., ge=0)
    time_window_start_ms: Optional[int] = None
    time_window_end_ms: Optional[int] = None
    duration_ms: Optional[int] = None
    top_src_ips: List[BehavioralTopItem] = Field(default_factory=list)
    top_dst_ips: List[BehavioralTopItem] = Field(default_factory=list)
    top_dst_ports: List[BehavioralTopItem] = Field(default_factory=list)
    protocol_counts: List[BehavioralTopItem] = Field(default_factory=list)
    excluded_from_ml_features: List[str] = Field(default_factory=list)
    non_attribution_notice: str


class CsvInspectResponse(BaseModel):
    """Validated CSV contract inspection and preview response."""

    model_config = ConfigDict(extra="forbid")

    file_path: str
    file_name: str
    file_sha256: str
    file_size_bytes: int = Field(..., ge=0)
    row_count: int = Field(..., ge=0)
    column_count: int = Field(..., ge=0)
    ml_feature_count: int = Field(..., ge=0)
    ml_features_valid: bool
    missing_ml_features: List[str] = Field(default_factory=list)
    target_columns_excluded: List[str] = Field(default_factory=list)
    trace_metadata_excluded: List[str] = Field(default_factory=list)
    other_extra_columns_excluded: List[str] = Field(default_factory=list)
    non_finite_feature_cells: int = Field(default=0, ge=0)
    ood_report: OodSummarySchema
    behavioral_summary: BehavioralSummarySchema
    models_status: List[ModelStatusItem] = Field(default_factory=list)
    preview_columns: List[str] = Field(default_factory=list)
    preview_rows: List[Dict[str, Any]] = Field(default_factory=list)


class CsvAnalyzeRequest(BaseModel):
    """Request to run verified ML batch inference on a local NetFlow CSV."""

    model_config = ConfigDict(extra="forbid")

    file_path: str = Field(..., min_length=1)
    model_name: str = Field(default="random_forest")
    create_incidents: bool = Field(default=False)
    batch_size: int = Field(default=500, ge=1, le=5000)
    include_timeline: bool = Field(default=True)
    allow_research_only: bool = Field(default=True)

    @field_validator("model_name")
    @classmethod
    def _validate_model_name(cls, v: str) -> str:
        return canonicalize_model_name(v)


class CsvFlowPredictionItem(BaseModel):
    """Row-aligned CSV prediction item preserving row_id, OOD flag, and deterministic risk."""

    model_config = ConfigDict(extra="forbid")

    row_id: Union[int, str]
    row_index: int = Field(..., ge=0)
    predicted_label: Optional[int] = Field(default=None, ge=0, le=1)
    predicted_class: str
    attack_probability: Optional[float] = None
    raw_anomaly_score: Optional[float] = None
    normalized_anomaly_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    decision_threshold: Optional[float] = None
    score_type: str
    score_direction: str
    risk_score: Optional[float] = None
    risk_level: str
    is_ood_flagged: bool = False
    ood_kind: Optional[Literal["ZERO_TTL_DRIFT", "PHYSICAL_INVARIANT", "COMBINED_OOD"]] = None
    ood_reason: Optional[str] = None
    flow_start_ms: Optional[int] = None
    flow_end_ms: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    flow_duration_ms: Optional[int] = None
    min_ttl: Optional[float] = None

    @field_validator(
        "attack_probability",
        "raw_anomaly_score",
        "normalized_anomaly_score",
        "decision_threshold",
        "risk_score",
        "min_ttl",
    )
    @classmethod
    def _validate_optional_finite(cls, v: Optional[float], info: Any) -> Optional[float]:
        if v is None:
            return None
        return _require_finite_float(v, info.field_name)


class CsvTimelineItem(BaseModel):
    """Deterministic forensic timeline event ordered by (flow_start_ms asc, row_id asc) (#24)."""

    model_config = ConfigDict(extra="forbid")

    sequence_index: int = Field(..., ge=0)
    row_id: Union[int, str]
    flow_start_ms: Optional[int] = None
    flow_end_ms: Optional[int] = None
    timestamp_iso: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    predicted_class: str
    risk_score: Optional[float] = None
    risk_level: str
    is_ood_flagged: bool = False
    evidence_summary: str


class CsvAnalyzeResponse(BaseModel):
    """Full verified inference, OOD, gate, behavioral summary, and timeline response."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    analyzed_at_utc: str
    file_path: str
    file_sha256: str
    model_key: str
    model_type: str
    run_id: Optional[str] = None
    model_sha256: Optional[str] = None
    preprocessor_sha256: Optional[str] = None
    inference_mode: str
    total_rows: int = Field(..., ge=0)
    evaluated_rows: int = Field(default=0, ge=0)
    abstained_rows: int = Field(default=0, ge=0)
    prediction_coverage: float = Field(default=1.0, ge=0.0, le=1.0)
    benign_count: int = Field(..., ge=0)
    attack_count: int = Field(..., ge=0)
    ood_flagged_count: int = Field(..., ge=0)
    abstained_risk_count: int = Field(..., ge=0)
    decision_threshold: Optional[float] = None
    score_type: str
    score_direction: str
    compatibility_gate: CompatibilityGateSummarySchema
    ood_report: OodSummarySchema
    behavioral_summary: BehavioralSummarySchema
    security_notice: str
    results: List[CsvFlowPredictionItem]
    timeline: List[CsvTimelineItem] = Field(default_factory=list)


class CsvEvaluateRequest(BaseModel):
    """Evaluate model predictions against a separate Ground Truth CSV file."""

    model_config = ConfigDict(extra="forbid")

    labels_path: str = Field(..., min_length=1)
    predictions: List[CsvFlowPredictionItem] = Field(..., min_length=1)


class AttackBreakdownRow(BaseModel):
    """Per-attack detection breakdown when ground-truth Attack categories exist."""

    model_config = ConfigDict(extra="forbid")

    attack_category: str
    total_count: int = Field(..., ge=0)
    tp_count: int = Field(..., ge=0)
    fn_count: int = Field(..., ge=0)
    detection_rate: float


class CsvEvaluateResponse(BaseModel):
    """Confusion matrix, primary metrics, and per-attack breakdown against Ground Truth."""

    model_config = ConfigDict(extra="forbid")

    labels_path: str
    labels_sha256: str
    total_prediction_rows: int = Field(default=0, ge=0)
    matched_label_rows: int = Field(default=0, ge=0)
    matched_rows: int = Field(..., ge=0)
    evaluated_rows: int = Field(default=0, ge=0)
    unmatched_rows: int = Field(..., ge=0)
    abstained_rows: int = Field(default=0, ge=0)
    label_match_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    prediction_coverage: float = Field(default=1.0, ge=0.0, le=1.0)
    accuracy: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    true_negative_rate: float
    confusion_matrix: Dict[str, int]
    attack_breakdown: List[AttackBreakdownRow] = Field(default_factory=list)
    scientific_notice: str


class CsvExportRequest(BaseModel):
    """Export row-aligned predictions CSV and companion provenance JSON."""

    model_config = ConfigDict(extra="forbid")

    output_path: str = Field(..., min_length=1)
    analysis_id: Optional[str] = None
    source_csv_path: Optional[str] = None
    model_key: str
    model_type: str
    run_id: Optional[str] = None
    model_sha256: Optional[str] = None
    preprocessor_sha256: Optional[str] = None
    results: List[CsvFlowPredictionItem] = Field(..., min_length=1)
    evaluation: Optional[CsvEvaluateResponse] = None


class CsvExportResponse(BaseModel):
    """Provenance confirmation of exported CSV and metadata JSON files."""

    model_config = ConfigDict(extra="forbid")

    csv_path: str
    metadata_path: str
    csv_sha256: str
    metadata_sha256: str
    rows_exported: int = Field(..., ge=0)
    exported_at_utc: str


# ---------------------------------------------------------------------------
# C8 / Issue #27: Adaptive Security Response Simulation / Dry-Run Schemas
# ---------------------------------------------------------------------------

RESPONSE_ACTIONS = frozenset({"NO_ACTION", "MONITOR", "INVESTIGATE", "ISOLATE_RECOMMENDED"})
RESPONSE_SEVERITIES = frozenset({"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})


class ResponseFlowRecommendationItem(BaseModel):
    """Deterministic dry-run response recommendation for a single analyzed network flow."""

    model_config = ConfigDict(extra="forbid")

    row_id: Union[int, str]
    row_index: int = Field(..., ge=0)
    predicted_class: str
    is_ood_flagged: bool
    risk_score: Optional[float] = None
    risk_level: str
    action: str
    severity: str
    action_status: str = "RECOMMENDED"
    simulation_status: str = "SIMULATED"
    executed: bool = False
    execution_status: str = "NOT_EXECUTED"
    containment_allowed: bool = False
    reason: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flow_start_ms: Optional[int] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("action")
    @classmethod
    def _validate_action(cls, v: str) -> str:
        norm = v.strip().upper()
        if norm not in RESPONSE_ACTIONS:
            raise ValueError(
                f"Response action must be one of {sorted(RESPONSE_ACTIONS)}, got {v!r}"
            )
        return norm

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        norm = v.strip().upper()
        if norm not in RESPONSE_SEVERITIES:
            raise ValueError(
                f"Response severity must be one of {sorted(RESPONSE_SEVERITIES)}, got {v!r}"
            )
        return norm

    @field_validator("executed")
    @classmethod
    def _enforce_dry_run_not_executed(cls, v: bool) -> bool:
        if v is not False:
            raise ValueError("Dry-run recommendations cannot claim executed=True.")
        return False

    @model_validator(mode="after")
    def _enforce_ood_no_containment_invariant(self) -> "ResponseFlowRecommendationItem":
        if (
            self.is_ood_flagged
            or self.predicted_class == "ABSTAINED_OOD"
            or self.risk_level == "ABSTAINED_OOD"
        ) and (self.action == "ISOLATE_RECOMMENDED" or self.containment_allowed):
            raise ValueError(
                "Invariant violation: ABSTAINED_OOD flows must never receive containment recommendations."
            )
        return self


class AdaptiveKeyRotationSimulation(BaseModel):
    """Simulated adaptive key rotation evaluation without creating or modifying real keys."""

    model_config = ConfigDict(extra="forbid")

    decision: str
    recommended: bool
    would_rotate: bool
    simulation_status: str = "SIMULATED"
    executed: bool = False
    key_material_generated: bool = False
    real_key_modified: bool = False
    keyring_status: str = "DEFERRED_PRODUCTION_KEYRING"
    active_key_id: Optional[str] = None
    active_key_version: Optional[int] = None
    simulated_next_version: Optional[int] = None
    cooldown_seconds: float = Field(..., ge=0.0)
    cooldown_remaining_seconds: float = Field(default=0.0, ge=0.0)
    trigger_metrics: Dict[str, Any] = Field(default_factory=dict)
    reason: str

    @field_validator("executed", "key_material_generated", "real_key_modified")
    @classmethod
    def _enforce_no_real_crypto_mutation(cls, v: bool, info: Any) -> bool:
        if v is not False:
            raise ValueError(
                f"{info.field_name} must remain False in dry-run key rotation simulation."
            )
        return False


MAX_SECURITY_SIMULATE_RESULTS: int = 10_000


class SecurityResponseSimulateRequest(BaseModel):
    """Request to run deterministic Issue #27 adaptive response simulation / dry-run."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: Optional[str] = None
    triggered_by: str = Field("operator", min_length=1, max_length=100)
    dry_run: bool = Field(
        True,
        description="Must remain True; automatic OS firewall/key execution is disabled in v0.6.0.",
    )
    source_csv_path: Optional[str] = None
    model_key: Optional[str] = None
    model_type: Optional[str] = None
    run_id: Optional[str] = None
    model_sha256: Optional[str] = None
    preprocessor_sha256: Optional[str] = None
    inference_mode: Optional[str] = None
    compatibility_gate: Optional[CompatibilityGateSummarySchema] = None
    results: Optional[List[CsvFlowPredictionItem]] = Field(
        default=None,
        max_length=MAX_SECURITY_SIMULATE_RESULTS,
    )

    @field_validator("dry_run")
    @classmethod
    def _require_dry_run_true(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError(
                "Only dry_run=True is permitted in NetFlow Sentinel v0.6.0; live response execution is disabled and DEFERRED."
            )
        return True

    @model_validator(mode="after")
    def _require_analysis_or_results(self) -> "SecurityResponseSimulateRequest":
        if not self.analysis_id and not self.results:
            raise ValueError("Provide either 'analysis_id' or non-empty 'results' to simulate.")
        return self


class SecurityResponseSimulationResponse(BaseModel):
    """Full Issue #27 dry-run policy simulation output with clear simulated vs executed state."""

    model_config = ConfigDict(extra="forbid")

    simulation_id: str
    created_at_utc: str
    analysis_id: Optional[str] = None
    source_csv_path: Optional[str] = None
    source_csv_sha256: Optional[str] = None
    model_key: str
    model_type: str
    run_id: Optional[str] = None
    model_sha256: Optional[str] = None
    preprocessor_sha256: Optional[str] = None
    triggered_by: str
    provenance_verification: str
    execution_mode: str = "DRY_RUN_SIMULATION"
    action_status: str = "SIMULATED"
    recommendation_status: str = "RECOMMENDED"
    execution_status: str = "NOT_EXECUTED"
    executed: bool = False
    os_firewall_touched: bool = False
    real_key_rotated: bool = False
    overall_recommendation: str
    overall_severity: str
    total_flows: int = Field(..., ge=0)
    evaluated_flows: int = Field(..., ge=0)
    ood_abstained_flows: int = Field(..., ge=0)
    action_counts: Dict[str, int]
    key_rotation_simulation: AdaptiveKeyRotationSimulation
    policy_summary: str
    security_notice: str
    deferred_capabilities: List[str]
    provenance: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[ResponseFlowRecommendationItem]


class SecuritySimulationHistoryItem(BaseModel):
    """Persisted Issue #27 simulation history entry stored in SQLite."""

    model_config = ConfigDict(extra="forbid")

    simulation_id: str
    created_at_utc: str
    analysis_id: Optional[str] = None
    source_csv_path: Optional[str] = None
    source_csv_sha256: Optional[str] = None
    model_key: str
    model_type: str
    run_id: Optional[str] = None
    triggered_by: str
    provenance_verification: str
    execution_mode: str
    action_status: str
    recommendation_status: str
    execution_status: str
    executed: bool = False
    os_firewall_touched: bool = False
    real_key_rotated: bool = False
    overall_recommendation: str
    overall_severity: str
    total_flows: int = Field(..., ge=0)
    evaluated_flows: int = Field(..., ge=0)
    ood_abstained_flows: int = Field(..., ge=0)
    action_counts: Dict[str, int]
    key_rotation_simulation: AdaptiveKeyRotationSimulation
    policy_summary: str


class PaginatedSecuritySimulationsResponse(BaseModel):
    """Paginated list of SQLite-persisted dry-run response simulations."""

    model_config = ConfigDict(extra="forbid")

    items: List[SecuritySimulationHistoryItem]
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1)
    offset: int = Field(..., ge=0)
    has_more: bool


class SecuritySimulationExportRequest(BaseModel):
    """Export an Issue #27 dry-run simulation evidence bundle as JSON + metadata."""

    model_config = ConfigDict(extra="forbid")

    output_path: str = Field(..., min_length=1)
    simulation_id: str = Field(..., min_length=1)


class SecuritySimulationExportResponse(BaseModel):
    """Provenance confirmation of exported Issue #27 simulation JSON and metadata."""

    model_config = ConfigDict(extra="forbid")

    simulation_id: str
    json_path: str
    metadata_path: str
    json_sha256: str
    metadata_sha256: str
    exported_at_utc: str


# ============================================================================
# NetFlow Sentinel v2.0 Trace & Crypto API Schemas (Issue #115)
# ============================================================================


class TimelineStageItem(BaseModel):
    stage_id: str
    phase: str
    timestamp: str
    source_entity: str
    target_entity: str
    title: str
    description: str
    confidence: float
    is_observed: bool
    evidence_ids: List[str] = Field(default_factory=list)
    indicators: Dict[str, Any] = Field(default_factory=dict)


class TraceTimelineResponse(BaseModel):
    timeline_id: str
    campaign_name: str
    overall_confidence: float
    start_time: str
    end_time: str
    entities_involved: List[str]
    total_stages: int
    stages: List[TimelineStageItem]
    available_campaigns: List[str] = Field(default_factory=list)
    data_status: str = "OK"
    provenance: Dict[str, Any] = Field(default_factory=dict)


class EntityGraphNodeItem(BaseModel):
    node_id: str
    kind: str
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class EntityGraphEdgeItem(BaseModel):
    edge_id: str
    source_id: str
    target_id: str
    relation_type: str
    confidence: float
    is_observed: bool
    evidence_id: Optional[str] = None


class TraceGraphResponse(BaseModel):
    node_count: int
    edge_count: int
    nodes: List[EntityGraphNodeItem]
    edges: List[EntityGraphEdgeItem]
    data_status: str = "OK"
    provenance: Dict[str, Any] = Field(default_factory=dict)


class GenerateInvestigationReportRequest(BaseModel):
    incident_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    severity: str = "HIGH"
    root_cause_summary: str = Field(..., min_length=1)
    events: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_records: List[Dict[str, Any]] = Field(default_factory=list)


class InvestigationReportResponse(BaseModel):
    report_id: str
    incident_id: str
    title: str
    generated_at: str
    severity: str
    root_cause_summary: str
    artifact_hash: str
    timeline: TraceTimelineResponse
    evidence_provenance: List[Dict[str, Any]]
    recommended_actions: List[str]
    markdown_content: str


class CryptoStatusResponse(BaseModel):
    active_key_id: str
    algorithm: str
    rotation_interval_minutes: float
    adaptive_risk_threshold: float
    cooldown_seconds: int
    max_rotations_per_hour: int = 10
    rotations_this_hour: int = 0
    total_rotations: int
    total_records_encrypted: int
    master_key_fingerprint: Optional[str] = None
    recent_rotations: List[Dict[str, Any]]
    storage_protection_status: Dict[str, Any] = Field(default_factory=dict)
    data_status: str = "CONNECTED"


class LiveStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(default="127.0.0.1", min_length=1, max_length=128)
    port: int = Field(default=0, ge=0, le=65535)
    demo_heuristics: bool = False
    queue_capacity: int = Field(default=10_000, ge=1, le=500_000)
    batch_size: int = Field(default=32, ge=1, le=2048)


class LiveStatusResponse(BaseModel):
    mode: str
    running: bool
    data_status: str
    bound_port: Optional[int] = None
    started_at_utc: Optional[str] = None
    collector: Dict[str, Any] = Field(default_factory=dict)
    pipeline: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    inference: Dict[str, Any] = Field(default_factory=dict)
    alerts_buffered: int = 0
    demo_mode: bool = False
    persistence_enabled: bool = False
    last_error: Optional[str] = None


class LiveResultsResponse(BaseModel):
    data_status: str
    total: int
    items: List[Dict[str, Any]] = Field(default_factory=list)


class LiveAlertsResponse(BaseModel):
    data_status: str
    total: int
    items: List[Dict[str, Any]] = Field(default_factory=list)


class BehavioralVectorListItem(BaseModel):
    vector_id: str
    entity_id: str
    window_start: str
    window_end: str
    dimensions: int
    is_encrypted: bool
    key_id: Optional[str] = None
    created_at: str


class BehavioralVectorListResponse(BaseModel):
    data_status: str
    total: int
    items: List[BehavioralVectorListItem] = Field(default_factory=list)
    reason: Optional[str] = None


class BehavioralVectorDetailResponse(BaseModel):
    vector_id: str
    entity_id: str
    window_start: str
    window_end: str
    dimensions: int
    features: List[float]
    feature_names: Optional[List[str]] = None
    feature_name_status: str
    sha256_hash: Optional[str] = None
    is_encrypted_at_rest: bool
    key_id: Optional[str] = None
    created_at: str
    data_status: str = "CONNECTED"


class BehavioralSimilarityResponse(BaseModel):
    vector_a: str
    vector_b: str
    dimensions: Optional[int] = None
    cosine_similarity: Optional[float] = None
    euclidean_distance: Optional[float] = None
    manhattan_distance: Optional[float] = None
    interpretation: Optional[str] = None
    interpretation_semantics: Optional[str] = None
    comparable: bool = True
    reason: Optional[str] = None
    data_status: str = "CONNECTED"


class BehavioralCorrelationClusterItem(BaseModel):
    cluster_id: str
    member_vector_ids: List[str] = Field(default_factory=list)
    average_similarity: float
    ip_addresses_observed: List[str] = Field(default_factory=list)


class BehavioralCorrelationResponse(BaseModel):
    data_status: str
    match_threshold: float
    total_vectors_evaluated: int
    clusters: List[BehavioralCorrelationClusterItem] = Field(default_factory=list)
    reason: Optional[str] = None
