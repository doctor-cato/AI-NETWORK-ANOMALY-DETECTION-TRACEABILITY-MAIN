"""AWS VPC Flow Logs Adapter for cloud flow telemetry ingestion (Issue #46)."""

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


class AWSVPCFlowAdapter(BaseSourceAdapter):
    """Adapter for AWS VPC Flow Logs (version 2 standard).

    Extracts cloud 5-tuple and packet/byte counters.
    Rejects ML inference due to time-window aggregation and lack of 43/47 micro-features.
    """

    def __init__(
        self, source_id: str = "source:aws-vpc-flow", schema_version: str = "2.0.0"
    ) -> None:
        super().__init__(source_id=source_id, schema_version=schema_version)

    def adapt_record(
        self, raw_record: Dict[str, Any], record_idx: Optional[int] = None
    ) -> CanonicalNetworkEvent:
        meta = EventMetadata(
            source_id=self.source_id,
            schema_version=self.schema_version,
            raw_record_id=str(record_idx or ""),
        )

        def _safe_int(val: Any) -> int:
            if val is None or val == "-" or val == "":
                return 0
            try:
                return int(val)
            except (ValueError, TypeError):
                return 0

        five_tuple = Network5Tuple(
            ipv4_src_addr=str(raw_record.get("srcaddr", "")),
            l4_src_port=_safe_int(raw_record.get("srcport")),
            ipv4_dst_addr=str(raw_record.get("dstaddr", "")),
            l4_dst_port=_safe_int(raw_record.get("dstport")),
            protocol=_safe_int(raw_record.get("protocol")),
        )

        bytes_count = _safe_int(raw_record.get("bytes"))
        packets_count = _safe_int(raw_record.get("packets"))
        start_ts = _safe_int(raw_record.get("start"))
        end_ts = _safe_int(raw_record.get("end"))
        duration_ms = max(0.0, float(end_ts - start_ts) * 1000.0)

        metrics = FlowMetrics(
            in_bytes=bytes_count,
            in_pkts=packets_count,
            out_bytes=0,
            out_pkts=0,
            flow_duration_ms=duration_ms,
        )

        trace_meta = {
            "version": raw_record.get("version"),
            "account_id": raw_record.get("account-id"),
            "interface_id": raw_record.get("interface-id"),
            "start": start_ts,
            "end": end_ts,
            "action": raw_record.get("action"),
            "log_status": raw_record.get("log-status"),
        }

        return CanonicalNetworkEvent(
            metadata=meta,
            network_5tuple=five_tuple,
            metrics=metrics,
            telemetry=ExtendedTelemetry(),
            app_context=ApplicationContext(),
            ml_features=None,  # Anti-imputation: strictly None!
            trace_metadata=trace_meta,
            eligibility=InferenceEligibility.FEATURE_INCOMPATIBLE,
            validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
            ood_warnings=[
                "AWS VPC Flow Logs are window-aggregated (1-10 min) and lack micro-telemetry."
            ],
        )
