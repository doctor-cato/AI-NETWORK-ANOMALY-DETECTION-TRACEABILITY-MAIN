"""Suricata EVE JSON Adapter for flow and alert telemetry ingestion (Issue #46 / Issue #32)."""

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


class SuricataEveAdapter(BaseSourceAdapter):
    """Adapter for Suricata EVE JSON logs (flow and alert events).

    Transfers signature alerts and flow metadata to Risk Engine (#32) and Trace Engine (#24).
    Abstains from 47-feature ML inference.
    """

    def __init__(self, source_id: str = "source:suricata-eve", schema_version: str = "1.0.0") -> None:
        super().__init__(source_id=source_id, schema_version=schema_version)

    def adapt_record(self, raw_record: Dict[str, Any], record_idx: Optional[int] = None) -> CanonicalNetworkEvent:
        meta = EventMetadata(
            source_id=self.source_id,
            schema_version=self.schema_version,
            raw_record_id=str(record_idx or ""),
        )

        proto_raw = str(raw_record.get("proto", "tcp")).lower()
        protocol_num = PROTO_MAP.get(proto_raw, 6)

        five_tuple = Network5Tuple(
            ipv4_src_addr=str(raw_record.get("src_ip", "")),
            l4_src_port=int(raw_record.get("src_port", 0)),
            ipv4_dst_addr=str(raw_record.get("dest_ip", "")),
            l4_dst_port=int(raw_record.get("dest_port", 0)),
            protocol=protocol_num,
        )

        # Parse flow sub-object if present
        flow_data = raw_record.get("flow", {})
        in_bytes = int(flow_data.get("bytes_toserver", raw_record.get("bytes_toserver", 0)))
        out_bytes = int(flow_data.get("bytes_toclient", raw_record.get("bytes_toclient", 0)))
        in_pkts = int(flow_data.get("pkts_toserver", raw_record.get("pkts_toserver", 0)))
        out_pkts = int(flow_data.get("pkts_toclient", raw_record.get("pkts_toclient", 0)))
        age_sec = float(flow_data.get("age", 0.0))

        metrics = FlowMetrics(
            in_bytes=in_bytes,
            in_pkts=in_pkts,
            out_bytes=out_bytes,
            out_pkts=out_pkts,
            flow_duration_ms=age_sec * 1000.0,
        )

        app = ApplicationContext(
            service_name=raw_record.get("app_proto")
        )

        # Preserve alert for Risk Engine (#32)
        trace_meta = {
            "timestamp": raw_record.get("timestamp"),
            "event_type": raw_record.get("event_type"),
            "alert": raw_record.get("alert"),
            "community_id": raw_record.get("community_id"),
            "flow_id": raw_record.get("flow_id"),
        }

        return CanonicalNetworkEvent(
            metadata=meta,
            network_5tuple=five_tuple,
            metrics=metrics,
            telemetry=ExtendedTelemetry(),
            app_context=app,
            ml_features=None,
            trace_metadata=trace_meta,
            eligibility=InferenceEligibility.FEATURE_INCOMPATIBLE,
            validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
            ood_warnings=["Suricata EVE logs lack 40/47 micro-telemetry features for ML baseline."],
        )
