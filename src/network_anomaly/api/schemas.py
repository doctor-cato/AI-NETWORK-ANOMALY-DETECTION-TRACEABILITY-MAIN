"""Pydantic schemas for FastAPI contracts, requests, responses, and validation.

All schemas enforce strict typing, data boundary validation, and fail-safe serialization.
Sensitive secret materials are strictly excluded from all schemas.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator


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
    model_name: Optional[str] = Field(
        "random_forest", description="Model family: 'random_forest' or 'isolation_forest'"
    )
    threshold: Optional[float] = Field(
        0.5, ge=0.0, le=1.0, description="Decision threshold for binary anomaly"
    )
    create_incidents: bool = Field(
        True, description="Whether to automatically create incident records for high anomalies"
    )


class AnalyzeResultItem(BaseModel):
    """Single inference result row."""

    model_config = ConfigDict(extra="forbid")

    index: int = Field(..., ge=0, description="Row index in input batch")
    event_id: Optional[str] = Field(None, description="Associated event ID if provided")
    is_anomaly: bool = Field(..., description="True if anomaly score exceeds threshold")
    anomaly_score: float = Field(
        ..., ge=0.0, le=1.0, description="Calibrated anomaly score or attack probability [0, 1]"
    )
    prediction: int = Field(..., description="Binary prediction: 0 (Normal), 1 (Anomaly)")
    attack_type: Optional[str] = Field(None, description="Inferred or classified attack category")
    model_used: str = Field(..., description="Model identifier used for analysis")
    incident_created: bool = Field(
        False, description="Whether an incident was persisted for this flow"
    )
    incident_id: Optional[str] = Field(None, description="Generated incident ID if created")


class AnalyzeResponse(BaseModel):
    """Response returned from analysis inference."""

    model_config = ConfigDict(extra="forbid")

    model_ready: bool = Field(..., description="Whether verified production model was used")
    count: int = Field(..., ge=0, description="Number of analyzed items")
    anomalies_detected: int = Field(
        ..., ge=0, description="Number of items classified as anomalous"
    )
    results: List[AnalyzeResultItem] = Field(default_factory=list)
    timestamp: str = Field(...)


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
