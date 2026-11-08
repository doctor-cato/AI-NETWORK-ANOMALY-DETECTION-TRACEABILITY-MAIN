"""Canonical Network Event schemas and status taxonomies for Multi-Source Ingestion (Issue #46)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ValidationStatus(str, Enum):
    """Four mandatory data validation tiers defined in Issue #46 Section 4, plus explicit benchmark evaluation status."""

    PARSEABLE = "PARSEABLE"
    SCHEMA_COMPATIBLE = "SCHEMA_COMPATIBLE"
    SEMANTICALLY_COMPATIBLE = "SEMANTICALLY_COMPATIBLE"
    MODEL_VALIDATED = "MODEL_VALIDATED"
    BENCHMARK_FAILED = "BENCHMARK_FAILED"


class InferenceEligibility(str, Enum):
    """Inference readiness and abstention decision states."""

    PREDICTION_AVAILABLE = "PREDICTION_AVAILABLE"
    ABSTAINED = "ABSTAINED"
    FEATURE_INCOMPATIBLE = "FEATURE_INCOMPATIBLE"
    FEATURE_INCOMPLETE = "FEATURE_INCOMPLETE"
    SOURCE_UNSUPPORTED = "SOURCE_UNSUPPORTED"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    MODEL_NOT_READY = "MODEL_NOT_READY"
    SEMANTIC_MISMATCH = "SEMANTIC_MISMATCH"
    VALIDATION_NOT_VERIFIED = "VALIDATION_NOT_VERIFIED"
    BENCHMARK_UNSATISFACTORY = "BENCHMARK_UNSATISFACTORY"


class FeatureMappingStatus(str, Enum):
    """Classification of individual feature compatibility from external source to ML model."""

    EXACT = "EXACT"
    DERIVABLE = "DERIVABLE"
    APPROXIMATE = "APPROXIMATE"
    MISSING = "MISSING"
    SEMANTIC_MISMATCH = "SEMANTIC_MISMATCH"


@dataclass
class EventMetadata:
    """Provenance and lineage metadata for an ingested network record."""

    source_id: str
    schema_version: str
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    raw_record_id: Optional[str] = None
    ingestion_timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class Network5Tuple:
    """Core network 5-tuple identification for flow tracking and graph correlation."""

    ipv4_src_addr: str
    l4_src_port: int
    ipv4_dst_addr: str
    l4_dst_port: int
    protocol: int


@dataclass
class FlowMetrics:
    """Bidirectional volume and duration counters."""

    in_bytes: int
    in_pkts: int
    out_bytes: int = 0
    out_pkts: int = 0
    flow_duration_ms: float = 0.0


@dataclass
class ExtendedTelemetry:
    """Micro-telemetry counters: TCP flags, TTL, IAT, and packet length distributions."""

    tcp_flags: int = 0
    client_tcp_flags: int = 0
    server_tcp_flags: int = 0
    min_ttl: Optional[int] = None
    max_ttl: Optional[int] = None
    longest_flow_pkt: Optional[int] = None
    shortest_flow_pkt: Optional[int] = None
    min_ip_pkt_len: Optional[int] = None
    max_ip_pkt_len: Optional[int] = None
    iat_stats: Dict[str, float] = field(default_factory=dict)
    packet_size_bins: Dict[str, int] = field(default_factory=dict)


@dataclass
class ApplicationContext:
    """L7 protocol identification and protocol-specific fields (DNS, FTP, HTTP)."""

    l7_proto: Optional[int] = None
    service_name: Optional[str] = None
    dns_query_id: Optional[int] = None
    dns_query_type: Optional[int] = None
    dns_ttl_answer: Optional[int] = None
    ftp_command_ret_code: Optional[int] = None


@dataclass
class CanonicalNetworkEvent:
    """Unified representation of a network flow event across all ingestion adapters.

    Decouples raw wire format from downstream ML inference, Trace graph correlation,
    and Risk calculation.
    """

    metadata: EventMetadata
    network_5tuple: Network5Tuple
    metrics: FlowMetrics
    telemetry: ExtendedTelemetry = field(default_factory=ExtendedTelemetry)
    app_context: ApplicationContext = field(default_factory=ApplicationContext)
    ml_features: Optional[Dict[str, float]] = None
    missing_features: List[str] = field(default_factory=list)
    invalid_features: Dict[str, str] = field(default_factory=dict)
    invalid_metadata: Dict[str, str] = field(default_factory=dict)
    trace_metadata: Dict[str, Any] = field(default_factory=dict)
    eligibility: InferenceEligibility = InferenceEligibility.FEATURE_INCOMPATIBLE
    validation_status: ValidationStatus = ValidationStatus.PARSEABLE
    ood_warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize event to a nested dictionary suitable for JSON/API responses."""
        return {
            "metadata": {
                "source_id": self.metadata.source_id,
                "schema_version": self.metadata.schema_version,
                "event_id": self.metadata.event_id,
                "raw_record_id": self.metadata.raw_record_id,
                "ingestion_timestamp_utc": self.metadata.ingestion_timestamp_utc,
            },
            "network_5tuple": {
                "ipv4_src_addr": self.network_5tuple.ipv4_src_addr,
                "l4_src_port": self.network_5tuple.l4_src_port,
                "ipv4_dst_addr": self.network_5tuple.ipv4_dst_addr,
                "l4_dst_port": self.network_5tuple.l4_dst_port,
                "protocol": self.network_5tuple.protocol,
            },
            "metrics": {
                "in_bytes": self.metrics.in_bytes,
                "in_pkts": self.metrics.in_pkts,
                "out_bytes": self.metrics.out_bytes,
                "out_pkts": self.metrics.out_pkts,
                "flow_duration_ms": self.metrics.flow_duration_ms,
            },
            "telemetry": {
                "tcp_flags": self.telemetry.tcp_flags,
                "min_ttl": self.telemetry.min_ttl,
                "max_ttl": self.telemetry.max_ttl,
            },
            "app_context": {
                "l7_proto": self.app_context.l7_proto,
                "service_name": self.app_context.service_name,
            },
            "ml_features_available": self.ml_features is not None,
            "missing_features": self.missing_features,
            "invalid_features": self.invalid_features,
            "invalid_metadata": self.invalid_metadata,
            "trace_metadata": self.trace_metadata,
            "eligibility": self.eligibility.value,
            "validation_status": self.validation_status.value,
            "ood_warnings": self.ood_warnings,
        }
