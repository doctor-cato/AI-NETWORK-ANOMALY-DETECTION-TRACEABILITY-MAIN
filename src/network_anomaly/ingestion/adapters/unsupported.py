"""Fallback adapter for explicitly unsupported or semantically mismatched sources (Issue #46)."""

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


class UnsupportedSourceAdapter(BaseSourceAdapter):
    """Adapter for sources that cannot be mapped or are semantically invalid (e.g. sFlow)."""

    def __init__(self, source_id: str = "source:sflow", schema_version: str = "1.0.0") -> None:
        super().__init__(source_id=source_id, schema_version=schema_version)

    def adapt_record(
        self, raw_record: Dict[str, Any], record_idx: Optional[int] = None
    ) -> CanonicalNetworkEvent:
        meta = EventMetadata(
            source_id=self.source_id,
            schema_version=self.schema_version,
            raw_record_id=str(record_idx or ""),
        )

        five_tuple = Network5Tuple(
            ipv4_src_addr=str(raw_record.get("src_ip", raw_record.get("srcaddr", "0.0.0.0"))),
            l4_src_port=int(raw_record.get("src_port", raw_record.get("srcport", 0))),
            ipv4_dst_addr=str(raw_record.get("dest_ip", raw_record.get("dstaddr", "0.0.0.0"))),
            l4_dst_port=int(raw_record.get("dest_port", raw_record.get("dstport", 0))),
            protocol=int(raw_record.get("protocol", 0)),
        )

        metrics = FlowMetrics(in_bytes=0, in_pkts=0)

        return CanonicalNetworkEvent(
            metadata=meta,
            network_5tuple=five_tuple,
            metrics=metrics,
            telemetry=ExtendedTelemetry(),
            app_context=ApplicationContext(),
            ml_features=None,
            trace_metadata={"raw_record": raw_record},
            eligibility=InferenceEligibility.SEMANTIC_MISMATCH,
            validation_status=ValidationStatus.PARSEABLE,
            ood_warnings=[
                f"Source '{self.source_id}' is semantically incompatible with flow modeling."
            ],
        )
