"""Zeek conn.log Adapter for Trace Engine metadata ingestion (Issue #46 / Issue #24)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from network_anomaly.ingestion.adapters.base import BaseSourceAdapter
from network_anomaly.ingestion.schemas import (
    ApplicationContext,
    CanonicalNetworkEvent,
    EventMetadata,
    ExtendedTelemetry,
    FlowMetrics,
    InferenceEligibility,
    Network5Tuple,
    ValidationStatus,
)

PROTO_MAP = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
}


class ZeekConnAdapter(BaseSourceAdapter):
    """Adapter for Zeek connection logs (conn.log).

    Transfers 5-tuple, uid, and connection lifecycle metadata to Trace Engine (#24).
    Enforces fail-closed ML abstention: ml_features is None, eligibility is FEATURE_INCOMPATIBLE.
    """

    def __init__(self, source_id: str = "source:zeek-conn", schema_version: str = "1.0.0") -> None:
        super().__init__(source_id=source_id, schema_version=schema_version)

    def adapt_record(self, raw_record: Dict[str, Any], record_idx: Optional[int] = None) -> CanonicalNetworkEvent:
        meta = EventMetadata(
            source_id=self.source_id,
            schema_version=self.schema_version,
            raw_record_id=str(raw_record.get("uid", record_idx or "")),
        )

        # Parse protocol
        proto_raw = str(raw_record.get("proto", "tcp")).lower()
        protocol_num = PROTO_MAP.get(proto_raw, 6)

        five_tuple = Network5Tuple(
            ipv4_src_addr=str(raw_record.get("id.orig_h", raw_record.get("orig_h", ""))),
            l4_src_port=int(raw_record.get("id.orig_p", raw_record.get("orig_p", 0))),
            ipv4_dst_addr=str(raw_record.get("id.resp_h", raw_record.get("resp_h", ""))),
            l4_dst_port=int(raw_record.get("id.resp_p", raw_record.get("resp_p", 0))),
            protocol=protocol_num,
        )

        def _safe_int(val: Any) -> int:
            if val is None or val == "-" or val == "":
                return 0
            try:
                return int(val)
            except (ValueError, TypeError):
                return 0

        def _safe_float(val: Any) -> float:
            if val is None or val == "-" or val == "":
                return 0.0
            try:
                return float(val)
            except (ValueError, TypeError):
                return 0.0

        orig_bytes = _safe_int(raw_record.get("orig_bytes"))
        resp_bytes = _safe_int(raw_record.get("resp_bytes"))
        orig_pkts = _safe_int(raw_record.get("orig_pkts"))
        resp_pkts = _safe_int(raw_record.get("resp_pkts"))
        duration_sec = _safe_float(raw_record.get("duration"))

        metrics = FlowMetrics(
            in_bytes=orig_bytes,
            in_pkts=orig_pkts,
            out_bytes=resp_bytes,
            out_pkts=resp_pkts,
            flow_duration_ms=duration_sec * 1000.0,
        )

        app = ApplicationContext(
            service_name=str(raw_record.get("service", "")) if raw_record.get("service") != "-" else None
        )

        # Trace metadata strictly preserved for Trace Engine (Issue #24)
        trace_meta = {
            "uid": raw_record.get("uid"),
            "ts": raw_record.get("ts"),
            "conn_state": raw_record.get("conn_state"),
            "history": raw_record.get("history"),
            "missed_bytes": raw_record.get("missed_bytes"),
            "orig_ip_bytes": raw_record.get("orig_ip_bytes"),
            "resp_ip_bytes": raw_record.get("resp_ip_bytes"),
            "tunnel_parents": raw_record.get("tunnel_parents"),
        }

        return CanonicalNetworkEvent(
            metadata=meta,
            network_5tuple=five_tuple,
            metrics=metrics,
            telemetry=ExtendedTelemetry(),
            app_context=app,
            ml_features=None,  # Anti-imputation: strictly None!
            trace_metadata=trace_meta,
            eligibility=InferenceEligibility.FEATURE_INCOMPATIBLE,
            validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
            ood_warnings=["Missing 40/47 micro-telemetry features required for ML baseline."],
        )
