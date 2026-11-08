"""NetFlow v3 Adapter for NF-UNSW-NB15-v3 and compatible external datasets (Issue #46)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS, TARGET_COLUMNS, TRACE_METADATA_COLUMNS
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


class NetFlowV3Adapter(BaseSourceAdapter):
    """Adapter for 55-column NetFlow v3 formats (UNSW-NB15, CIC-IDS2018, ToN-IoT)."""

    def __init__(self, source_id: str = "source:nf-v3-external", schema_version: str = "1.0.0") -> None:
        super().__init__(source_id=source_id, schema_version=schema_version)

    def adapt_record(self, raw_record: Dict[str, Any], record_idx: Optional[int] = None) -> CanonicalNetworkEvent:
        # 1. Metadata
        meta = EventMetadata(
            source_id=self.source_id,
            schema_version=self.schema_version,
            raw_record_id=str(record_idx) if record_idx is not None else None,
        )

        # 2. 5-Tuple
        five_tuple = Network5Tuple(
            ipv4_src_addr=str(raw_record.get("IPV4_SRC_ADDR", "")),
            l4_src_port=int(raw_record.get("L4_SRC_PORT", 0)),
            ipv4_dst_addr=str(raw_record.get("IPV4_DST_ADDR", "")),
            l4_dst_port=int(raw_record.get("L4_DST_PORT", 0)),
            protocol=int(raw_record.get("PROTOCOL", 0)),
        )

        # 3. Flow Metrics
        metrics = FlowMetrics(
            in_bytes=int(raw_record.get("IN_BYTES", 0)),
            in_pkts=int(raw_record.get("IN_PKTS", 0)),
            out_bytes=int(raw_record.get("OUT_BYTES", 0)),
            out_pkts=int(raw_record.get("OUT_PKTS", 0)),
            flow_duration_ms=float(raw_record.get("FLOW_DURATION_MILLISECONDS", 0.0)),
        )

        # 4. Telemetry
        telemetry = ExtendedTelemetry(
            tcp_flags=int(raw_record.get("TCP_FLAGS", 0)),
            client_tcp_flags=int(raw_record.get("CLIENT_TCP_FLAGS", 0)),
            server_tcp_flags=int(raw_record.get("SERVER_TCP_FLAGS", 0)),
            min_ttl=int(raw_record.get("MIN_TTL", 0)),
            max_ttl=int(raw_record.get("MAX_TTL", 0)),
            longest_flow_pkt=int(raw_record.get("LONGEST_FLOW_PKT", 0)),
            shortest_flow_pkt=int(raw_record.get("SHORTEST_FLOW_PKT", 0)),
            min_ip_pkt_len=int(raw_record.get("MIN_IP_PKT_LEN", 0)),
            max_ip_pkt_len=int(raw_record.get("MAX_IP_PKT_LEN", 0)),
        )

        # 5. App context
        app = ApplicationContext(
            l7_proto=int(raw_record.get("L7_PROTO", 0)),
            dns_query_id=int(raw_record.get("DNS_QUERY_ID", 0)),
            dns_query_type=int(raw_record.get("DNS_QUERY_TYPE", 0)),
            dns_ttl_answer=int(raw_record.get("DNS_TTL_ANSWER", 0)),
            ftp_command_ret_code=int(raw_record.get("FTP_COMMAND_RET_CODE", 0)),
        )

        # 6. Extract 47 ML Features
        ml_features: Dict[str, float] = {}
        for col in ML_FEATURE_COLUMNS:
            val = raw_record.get(col)
            try:
                ml_features[col] = float(val) if val is not None else float("nan")
            except (ValueError, TypeError):
                ml_features[col] = float("nan")

        # 7. Trace and Target Metadata (strictly preserved for evaluation and Trace Engine)
        trace_meta: Dict[str, Any] = {}
        for col in TRACE_METADATA_COLUMNS:
            if col in raw_record:
                trace_meta[col] = raw_record[col]
        for col in TARGET_COLUMNS:
            if col in raw_record:
                trace_meta[col] = raw_record[col]

        # Determine validation status
        val_status = (
            ValidationStatus.MODEL_VALIDATED
            if "external" in self.source_id or "canonical" in self.source_id
            else ValidationStatus.SEMANTICALLY_COMPATIBLE
        )

        return CanonicalNetworkEvent(
            metadata=meta,
            network_5tuple=five_tuple,
            metrics=metrics,
            telemetry=telemetry,
            app_context=app,
            ml_features=ml_features,
            trace_metadata=trace_meta,
            eligibility=InferenceEligibility.PREDICTION_AVAILABLE,
            validation_status=val_status,
        )
