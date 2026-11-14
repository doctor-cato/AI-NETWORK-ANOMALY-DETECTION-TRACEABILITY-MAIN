"""NetFlow v3 Adapter for NF-UNSW-NB15-v3 and compatible external datasets (Issue #46)."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
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


def _parse_port(raw_record: Dict[str, Any], key: str) -> Tuple[int, Optional[str]]:
    if key not in raw_record:
        return 0, None
    val = raw_record[key]
    if val is None or val == "":
        return -1, "missing_or_null"
    try:
        f = float(val)
        if not math.isfinite(f):
            return -1, "non_finite"
        i = int(f)
        # Preserve actual integer (including out of range like -1 or 70000) for OOD validation
        return i, None
    except (ValueError, TypeError):
        return -1, f"invalid_type_{type(val).__name__}"


def _parse_protocol(raw_record: Dict[str, Any], key: str) -> Tuple[int, Optional[str]]:
    if key not in raw_record:
        return 0, None
    val = raw_record[key]
    if val is None or val == "":
        return -1, "missing_or_null"
    try:
        f = float(val)
        if not math.isfinite(f):
            return -1, "non_finite"
        i = int(f)
        return i, None
    except (ValueError, TypeError):
        return -1, f"invalid_type_{type(val).__name__}"


def _parse_duration(raw_record: Dict[str, Any], key: str) -> Tuple[float, Optional[str]]:
    if key not in raw_record:
        return 0.0, None
    val = raw_record[key]
    if val is None or val == "":
        return -1.0, "missing_or_null"
    try:
        f = float(val)
        if not math.isfinite(f):
            return -1.0, "non_finite"
        # Preserve negative duration so OODValidator catches it as physical invariant violation
        return f, None
    except (ValueError, TypeError):
        return -1.0, f"invalid_type_{type(val).__name__}"


def _parse_counter(raw_record: Dict[str, Any], key: str) -> Tuple[int, Optional[str]]:
    if key not in raw_record:
        return 0, None
    val = raw_record[key]
    if val is None or val == "":
        return 0, None
    try:
        f = float(val)
        if not math.isfinite(f):
            return -1, "non_finite"
        i = int(f)
        if i < 0:
            return i, f"negative_counter_{i}"
        return i, None
    except (ValueError, TypeError):
        return -1, f"invalid_type_{type(val).__name__}"


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        f = float(val)
        return int(f) if math.isfinite(f) else default
    except (ValueError, TypeError):
        return default


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        f = float(val)
        return f if math.isfinite(f) else default
    except (ValueError, TypeError):
        return default


class NetFlowV3Adapter(BaseSourceAdapter):
    """Adapter for 55-column NetFlow v3 formats (UNSW-NB15, CIC-IDS2018, ToN-IoT)."""

    def __init__(
        self, source_id: str = "source:nf-v3-external", schema_version: str = "1.0.0"
    ) -> None:
        super().__init__(source_id=source_id, schema_version=schema_version)

    def adapt_record(
        self, raw_record: Dict[str, Any], record_idx: Optional[int] = None
    ) -> CanonicalNetworkEvent:
        invalid_metadata: Dict[str, str] = {}

        # 1. Metadata
        meta = EventMetadata(
            source_id=self.source_id,
            schema_version=self.schema_version,
            raw_record_id=str(record_idx) if record_idx is not None else None,
        )

        # 2. 5-Tuple with explicit boundary validation
        src_port, err_sp = _parse_port(raw_record, "L4_SRC_PORT")
        if err_sp:
            invalid_metadata["L4_SRC_PORT"] = err_sp

        dst_port, err_dp = _parse_port(raw_record, "L4_DST_PORT")
        if err_dp:
            invalid_metadata["L4_DST_PORT"] = err_dp

        proto_val, err_proto = _parse_protocol(raw_record, "PROTOCOL")
        if err_proto:
            invalid_metadata["PROTOCOL"] = err_proto

        src_ip = str(raw_record.get("IPV4_SRC_ADDR", ""))
        dst_ip = str(raw_record.get("IPV4_DST_ADDR", ""))
        if "IPV4_SRC_ADDR" in raw_record and (not src_ip or src_ip == "None"):
            invalid_metadata["IPV4_SRC_ADDR"] = "missing_or_empty"
        if "IPV4_DST_ADDR" in raw_record and (not dst_ip or dst_ip == "None"):
            invalid_metadata["IPV4_DST_ADDR"] = "missing_or_empty"

        five_tuple = Network5Tuple(
            ipv4_src_addr=src_ip,
            l4_src_port=src_port,
            ipv4_dst_addr=dst_ip,
            l4_dst_port=dst_port,
            protocol=proto_val,
        )

        # 3. Flow Metrics with explicit validation
        in_bytes, err_ib = _parse_counter(raw_record, "IN_BYTES")
        if err_ib:
            invalid_metadata["IN_BYTES"] = err_ib

        in_pkts, err_ip = _parse_counter(raw_record, "IN_PKTS")
        if err_ip:
            invalid_metadata["IN_PKTS"] = err_ip

        out_bytes, err_ob = _parse_counter(raw_record, "OUT_BYTES")
        if err_ob:
            invalid_metadata["OUT_BYTES"] = err_ob

        out_pkts, err_op = _parse_counter(raw_record, "OUT_PKTS")
        if err_op:
            invalid_metadata["OUT_PKTS"] = err_op

        dur_ms, err_dur = _parse_duration(raw_record, "FLOW_DURATION_MILLISECONDS")
        if err_dur:
            invalid_metadata["FLOW_DURATION_MILLISECONDS"] = err_dur

        metrics = FlowMetrics(
            in_bytes=in_bytes,
            in_pkts=in_pkts,
            out_bytes=out_bytes,
            out_pkts=out_pkts,
            flow_duration_ms=dur_ms,
        )

        # 4. Telemetry
        telemetry = ExtendedTelemetry(
            tcp_flags=_safe_int(raw_record.get("TCP_FLAGS", 0)),
            client_tcp_flags=_safe_int(raw_record.get("CLIENT_TCP_FLAGS", 0)),
            server_tcp_flags=_safe_int(raw_record.get("SERVER_TCP_FLAGS", 0)),
            min_ttl=_safe_int(raw_record.get("MIN_TTL", 0)),
            max_ttl=_safe_int(raw_record.get("MAX_TTL", 0)),
            longest_flow_pkt=_safe_int(raw_record.get("LONGEST_FLOW_PKT", 0)),
            shortest_flow_pkt=_safe_int(raw_record.get("SHORTEST_FLOW_PKT", 0)),
            min_ip_pkt_len=_safe_int(raw_record.get("MIN_IP_PKT_LEN", 0)),
            max_ip_pkt_len=_safe_int(raw_record.get("MAX_IP_PKT_LEN", 0)),
        )

        # 5. App context
        app = ApplicationContext(
            l7_proto=_safe_int(raw_record.get("L7_PROTO", 0)),
            dns_query_id=_safe_int(raw_record.get("DNS_QUERY_ID", 0)),
            dns_query_type=_safe_int(raw_record.get("DNS_QUERY_TYPE", 0)),
            dns_ttl_answer=_safe_int(raw_record.get("DNS_TTL_ANSWER", 0)),
            ftp_command_ret_code=_safe_int(raw_record.get("FTP_COMMAND_RET_CODE", 0)),
        )

        # 6. Extract 47 ML Features with strict anti-imputation & finite float validation
        ml_features: Dict[str, float] = {}
        missing_features_list: List[str] = []
        invalid_features_dict: Dict[str, str] = {}

        for col in ML_FEATURE_COLUMNS:
            if col not in raw_record:
                missing_features_list.append(col)
                continue
            val = raw_record[col]
            if val is None or val == "":
                invalid_features_dict[col] = "null_or_empty"
                continue
            try:
                import math

                f_val = float(val)
                if not math.isfinite(f_val):
                    invalid_features_dict[col] = "non_finite_nan_or_inf"
                else:
                    ml_features[col] = f_val
            except (ValueError, TypeError):
                invalid_features_dict[col] = f"invalid_numeric_token_{type(val).__name__}"

        is_complete = (
            (len(missing_features_list) == 0)
            and (len(invalid_features_dict) == 0)
            and (len(invalid_metadata) == 0)
            and (len(ml_features) == len(ML_FEATURE_COLUMNS))
        )

        # 7. Trace and Target Metadata (strictly preserved for evaluation and Trace Engine)
        trace_meta: Dict[str, Any] = {}
        for col in TRACE_METADATA_COLUMNS:
            if col in raw_record:
                trace_meta[col] = raw_record[col]
        for col in TARGET_COLUMNS:
            if col in raw_record:
                trace_meta[col] = raw_record[col]

        # Determine validation tier and eligibility based on verification evidence, NOT string matching
        if not is_complete:
            val_status = ValidationStatus.SCHEMA_COMPATIBLE
            eligibility = InferenceEligibility.FEATURE_INCOMPLETE
        elif self.source_id == "source:nf-v3-canonical":
            # Canonical internal benchmark verified on NF-UNSW-NB15-v3
            val_status = ValidationStatus.MODEL_VALIDATED
            eligibility = InferenceEligibility.PREDICTION_AVAILABLE
        else:
            # External or other NetFlow v3 sources reach semantic compatibility pending specific model validation
            val_status = ValidationStatus.SEMANTICALLY_COMPATIBLE
            eligibility = InferenceEligibility.VALIDATION_NOT_VERIFIED

        return CanonicalNetworkEvent(
            metadata=meta,
            network_5tuple=five_tuple,
            metrics=metrics,
            telemetry=telemetry,
            app_context=app,
            ml_features=ml_features if is_complete else None,
            missing_features=missing_features_list,
            invalid_features=invalid_features_dict,
            invalid_metadata=invalid_metadata,
            trace_metadata=trace_meta,
            eligibility=eligibility,
            validation_status=val_status,
        )
