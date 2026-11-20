"""Canonical v2 Flow Adapter for AIT-NDS-v2, CTU-SME-11, and canonical-flow-v2-18 CSVs."""

from __future__ import annotations

import math
from typing import Any, Dict, Optional

from network_anomaly.data.v2_schema import (
    ML_FEATURE_COLUMNS,
    compute_flow_features_from_base,
    parse_ait_nds_tstat_row,
    parse_ctu_zeek_conn_row,
    parse_protocol_number,
)
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


class CanonicalFlowV2Adapter(BaseSourceAdapter):
    """Adapter for canonical-flow-v2-18, AIT-NDS-v2 Tstat CSVs, and CTU-SME-11 Zeek logs."""

    def __init__(
        self,
        source_id: str = "source:canonical-flow-v2",
        schema_version: str = "2.0.0",
    ) -> None:
        super().__init__(source_id=source_id, schema_version=schema_version)

    def adapt_record(
        self, raw_record: Dict[str, Any], record_idx: Optional[int] = None
    ) -> CanonicalNetworkEvent:
        invalid_metadata: Dict[str, str] = {}
        missing_features = []
        invalid_features: Dict[str, str] = {}
        ml_feats: Optional[Dict[str, float]] = None

        parsed: Optional[Dict[str, Any]] = None
        if "#15#c_ip:1" in raw_record or "durat:31" in raw_record:
            try:
                kind = "tcp_complete" if "c_ttl_min:50" in raw_record else "tcp_nocomplete"
                parsed = parse_ait_nds_tstat_row(raw_record, flow_kind=kind)
            except Exception as exc:
                invalid_metadata["tstat_parse"] = str(exc)
        elif "#c_ip:1" in raw_record or "c_first_abs:3" in raw_record:
            try:
                parsed = parse_ait_nds_tstat_row(raw_record, flow_kind="udp_complete")
            except Exception as exc:
                invalid_metadata["tstat_parse"] = str(exc)
        elif "id.orig_h" in raw_record and "orig_ip_bytes" in raw_record:
            try:
                parsed = parse_ctu_zeek_conn_row(raw_record)
            except Exception as exc:
                invalid_metadata["zeek_parse"] = str(exc)

        if parsed is not None:
            src_ip = str(parsed["source_ip"])
            dst_ip = str(parsed["dest_ip"])
            src_port = int(parsed["source_port"])
            dst_port = int(parsed["dest_port"])
            proto_num = int(parsed["protocol_num"])
            dur_ms = float(parsed["duration_ms"])
            b_in = int(parsed["bytes_in"])
            b_out = int(parsed["bytes_out"])
            p_in = int(parsed["pkts_in"])
            p_out = int(parsed["pkts_out"])
            ts_ms = parsed["timestamp_ms"]
            ml_feats = {col: float(parsed[col]) for col in ML_FEATURE_COLUMNS}
        else:
            src_ip = str(raw_record.get("source_ip", ""))
            dst_ip = str(raw_record.get("dest_ip", ""))
            try:
                src_port = int(float(raw_record.get("source_port", 0)))
            except (ValueError, TypeError):
                src_port = -1
                invalid_metadata["source_port"] = "invalid"
            try:
                dst_port = int(float(raw_record.get("dest_port", 0)))
            except (ValueError, TypeError):
                dst_port = -1
                invalid_metadata["dest_port"] = "invalid"
            try:
                proto_raw = raw_record.get("protocol_num", raw_record.get("raw_protocol_str", 6))
                proto_num = parse_protocol_number(proto_raw)
            except (ValueError, TypeError):
                proto_num = -1
                invalid_metadata["protocol_num"] = "invalid"
            ts_ms = raw_record.get("timestamp_ms")

            candidate: Dict[str, float] = {}
            for col in ML_FEATURE_COLUMNS:
                if col not in raw_record or raw_record[col] is None or raw_record[col] == "":
                    missing_features.append(col)
                else:
                    try:
                        fv = float(raw_record[col])
                        if not math.isfinite(fv):
                            invalid_features[col] = "non_finite"
                        else:
                            candidate[col] = fv
                    except (ValueError, TypeError):
                        invalid_features[col] = "non_numeric"

            # If only derived columns were omitted while all 6 base fields exist, compute cleanly
            if missing_features and not invalid_features:
                base_keys = (
                    "duration_ms",
                    "bytes_in",
                    "bytes_out",
                    "pkts_in",
                    "pkts_out",
                    "protocol_num",
                )
                if all(k in candidate for k in base_keys):
                    try:
                        candidate = compute_flow_features_from_base(
                            duration_ms=candidate["duration_ms"],
                            bytes_in=candidate["bytes_in"],
                            bytes_out=candidate["bytes_out"],
                            pkts_in=candidate["pkts_in"],
                            pkts_out=candidate["pkts_out"],
                            protocol_num=int(candidate["protocol_num"]),
                        )
                        missing_features = []
                    except ValueError as exc:
                        invalid_features["base_flow"] = str(exc)

            if (
                not missing_features
                and not invalid_features
                and len(candidate) == len(ML_FEATURE_COLUMNS)
            ):
                ml_feats = candidate

            dur_ms = float(candidate.get("duration_ms", 0.0)) if "candidate" in locals() else 0.0
            b_in = int(candidate.get("bytes_in", 0)) if "candidate" in locals() else 0
            b_out = int(candidate.get("bytes_out", 0)) if "candidate" in locals() else 0
            p_in = int(candidate.get("pkts_in", 0)) if "candidate" in locals() else 0
            p_out = int(candidate.get("pkts_out", 0)) if "candidate" in locals() else 0

        is_complete = ml_feats is not None and not invalid_metadata
        return CanonicalNetworkEvent(
            metadata=EventMetadata(
                source_id=self.source_id,
                schema_version=self.schema_version,
                raw_record_id=str(record_idx if record_idx is not None else ""),
            ),
            network_5tuple=Network5Tuple(
                ipv4_src_addr=src_ip,
                l4_src_port=src_port,
                ipv4_dst_addr=dst_ip,
                l4_dst_port=dst_port,
                protocol=proto_num,
            ),
            metrics=FlowMetrics(
                in_bytes=b_in,
                in_pkts=p_in,
                out_bytes=b_out,
                out_pkts=p_out,
                flow_duration_ms=dur_ms,
            ),
            telemetry=ExtendedTelemetry(),
            app_context=ApplicationContext(),
            ml_features=ml_feats,
            missing_features=missing_features,
            invalid_features=invalid_features,
            invalid_metadata=invalid_metadata,
            trace_metadata={"timestamp_ms": ts_ms},
            eligibility=(
                InferenceEligibility.PREDICTION_AVAILABLE
                if is_complete
                else InferenceEligibility.FEATURE_INCOMPLETE
            ),
            validation_status=(
                ValidationStatus.SCHEMA_COMPATIBLE if is_complete else ValidationStatus.PARSEABLE
            ),
        )
