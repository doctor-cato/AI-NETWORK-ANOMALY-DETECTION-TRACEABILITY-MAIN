"""Cisco NetFlow v5 Adapter for legacy telemetry ingestion (Issue #46)."""

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


class NetFlowV5Adapter(BaseSourceAdapter):
    """Adapter for Cisco NetFlow v5 records.

    Transfers 5-tuple and single-direction byte/packet counters to Trace Engine (#24).
    Abstains from 47-feature ML inference (ml_features is None).
    """

    def __init__(self, source_id: str = "source:netflow-v5", schema_version: str = "5.0.0") -> None:
        super().__init__(source_id=source_id, schema_version=schema_version)

    def adapt_record(self, raw_record: Dict[str, Any], record_idx: Optional[int] = None) -> CanonicalNetworkEvent:
        meta = EventMetadata(
            source_id=self.source_id,
            schema_version=self.schema_version,
            raw_record_id=str(record_idx or ""),
        )

        five_tuple = Network5Tuple(
            ipv4_src_addr=str(raw_record.get("srcaddr", "")),
            l4_src_port=int(raw_record.get("srcport", 0)),
            ipv4_dst_addr=str(raw_record.get("dstaddr", "")),
            l4_dst_port=int(raw_record.get("dstport", 0)),
            protocol=int(raw_record.get("prot", raw_record.get("protocol", 0))),
        )

        d_octets = int(raw_record.get("dOctets", raw_record.get("octets", 0)))
        d_pkts = int(raw_record.get("dPkts", raw_record.get("packets", 0)))
        first = float(raw_record.get("first", 0.0))
        last = float(raw_record.get("last", 0.0))
        duration_ms = max(0.0, (last - first) if last >= first else 0.0)

        metrics = FlowMetrics(
            in_bytes=d_octets,
            in_pkts=d_pkts,
            out_bytes=0,
            out_pkts=0,
            flow_duration_ms=duration_ms,
        )

        telemetry = ExtendedTelemetry(
            tcp_flags=int(raw_record.get("tcp_flags", 0))
        )

        trace_meta = {
            "first": first,
            "last": last,
            "tos": raw_record.get("tos"),
            "src_as": raw_record.get("src_as"),
            "dst_as": raw_record.get("dst_as"),
            "src_mask": raw_record.get("src_mask"),
            "dst_mask": raw_record.get("dst_mask"),
        }

        return CanonicalNetworkEvent(
            metadata=meta,
            network_5tuple=five_tuple,
            metrics=metrics,
            telemetry=telemetry,
            app_context=ApplicationContext(),
            ml_features=None,  # Anti-imputation: strictly None!
            trace_metadata=trace_meta,
            eligibility=InferenceEligibility.FEATURE_INCOMPATIBLE,
            validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
            ood_warnings=["NetFlow v5 lacks 41/47 baseline ML features (unidirectional only)."],
        )
