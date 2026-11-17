"""Canonical Security Event schema v2.0 for multi-source ingestion.

Preserves raw data provenance, supports Flow, DNS, Web, Auth, and System logs,
and enforces explicit validation boundaries without silent data corruption.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field, field_validator


class EventKind(str, Enum):
    FLOW = "flow"
    DNS = "dns"
    WEB = "web"
    AUTH = "auth"
    SYSTEM = "system"


class ValidationStatus(str, Enum):
    VALID = "VALID"
    FEATURE_INCOMPLETE = "FEATURE_INCOMPLETE"
    TIMESTAMP_INVALID = "TIMESTAMP_INVALID"
    OUT_OF_BOUNDS = "OUT_OF_BOUNDS"
    REJECTED = "REJECTED"


class RawProvenance(BaseModel):
    source_file: str = Field(..., description="File path or stream name of source")
    line_or_offset: Optional[int] = Field(None, description="Line number or byte offset in source")
    source_checksum: Optional[str] = Field(None, description="SHA-256 of source file/chunk")
    adapter_name: str = Field(..., description="Name of the adapter that parsed this event")


class FlowMetrics(BaseModel):
    duration_ms: Optional[float] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    pkts_in: Optional[int] = None
    pkts_out: Optional[int] = None
    tcp_flags: Optional[int] = None


class DNSData(BaseModel):
    query_name: str
    query_type: Optional[str] = None
    query_id: Optional[int] = None
    rcode: Optional[int] = None
    ttl_answer: Optional[int] = None


class HTTPData(BaseModel):
    method: str
    url: str
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    content_type: Optional[str] = None


class AuthData(BaseModel):
    username: str
    auth_result: str  # SUCCESS, FAILURE, CHALLENGE
    service: Optional[str] = None
    failure_reason: Optional[str] = None


class SystemData(BaseModel):
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    action: str
    return_code: Optional[int] = None


class CanonicalSecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = "2.0.0"
    event_timestamp: datetime
    event_kind: EventKind
    source_id: str
    entity_id: Optional[str] = None

    # Network Tuples (if applicable)
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None

    # Specialized event payloads
    flow_metrics: Optional[FlowMetrics] = None
    dns_data: Optional[DNSData] = None
    http_data: Optional[HTTPData] = None
    auth_data: Optional[AuthData] = None
    system_data: Optional[SystemData] = None

    # Provenance tracking
    raw_provenance: RawProvenance

    # Ground truth & classification
    attack_category: Optional[str] = None

    # ML & Behavioral integration
    ml_features: Optional[Dict[str, float]] = None
    is_ml_complete: bool = False
    validation_status: ValidationStatus = ValidationStatus.VALID
    validation_errors: List[str] = Field(default_factory=list)

    @field_validator("event_timestamp")
    def validate_timestamp_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            # Force UTC if naive
            v = v.replace(tzinfo=timezone.utc)
        return v

    @field_validator("source_port", "dest_port")
    def validate_port_bounds(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (0 <= v <= 65535):
            raise ValueError(f"Port number {v} out of valid bounds [0, 65535]")
        return v
