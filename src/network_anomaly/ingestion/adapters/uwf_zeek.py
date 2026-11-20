"""UWF-ZeekData24 / UWF-ZeekData22 adapter for canonical-flow-v2-18 (evaluation-only)."""

from __future__ import annotations

import math
from typing import Any, Dict, Mapping, Optional

from network_anomaly.data.taxonomy import LabelMappingResult, classify_raw_label
from network_anomaly.data.v2_schema import (
    ML_FEATURE_COLUMNS,
    compute_flow_features_from_base,
    parse_protocol_number,
)
from network_anomaly.ingestion.adapters.base import BaseSourceAdapter
from network_anomaly.ingestion.schemas import (
    ApplicationContext,
    CanonicalNetworkEvent,
    EventMetadata,
    FlowMetrics,
    InferenceEligibility,
    Network5Tuple,
    ValidationStatus,
)

UWF_TACTIC_TO_CATEGORY: Dict[str, str] = {
    "none": "Benign",
    "benign": "Benign",
    "normal": "Benign",
    "reconnaissance": "Reconnaissance",
    "discovery": "Post_Exploitation_Discovery",
    "credential access": "Credential_Attack",
    "credential_access": "Credential_Attack",
    "initial access": "Exploitation_And_C2",
    "initial_access": "Exploitation_And_C2",
    "execution": "Exploitation_And_C2",
    "persistence": "Exploitation_And_C2",
    "privilege escalation": "Exploitation_And_C2",
    "privilege_escalation": "Exploitation_And_C2",
    "defense evasion": "Exploitation_And_C2",
    "defense_evasion": "Exploitation_And_C2",
    "lateral movement": "Exploitation_And_C2",
    "lateral_movement": "Exploitation_And_C2",
    "command and control": "Exploitation_And_C2",
    "command_and_control": "Exploitation_And_C2",
    "collection": "Data_Exfiltration",
    "exfiltration": "Data_Exfiltration",
    "impact": "Malware_And_DoS",
}


def map_uwf_tactic_label(
    raw_tactic: Optional[str],
    raw_binary: Optional[Any] = None,
) -> LabelMappingResult:
    """Map UWF-ZeekData24/22 MITRE ATT&CK tactic labels onto taxonomy-v2 without coercion."""
    tactic_str = "" if raw_tactic is None else str(raw_tactic).strip()
    tactic_norm = tactic_str.lower()
    binary_norm = "" if raw_binary is None else str(raw_binary).strip().lower()

    if tactic_norm in UWF_TACTIC_TO_CATEGORY:
        cat = UWF_TACTIC_TO_CATEGORY[tactic_norm]
        if cat == "Benign":
            if binary_norm in {"true", "1", "malicious", "attack"}:
                return LabelMappingResult(
                    raw_label=tactic_str,
                    canonical_category="Unmapped",
                    binary_label=None,
                    label_status="UNMAPPED",
                )
            return LabelMappingResult(
                raw_label=tactic_str,
                canonical_category="Benign",
                binary_label=0,
                label_status="MAPPED_BENIGN",
            )
        return LabelMappingResult(
            raw_label=tactic_str,
            canonical_category=cat,
            binary_label=1,
            label_status="MAPPED_ATTACK",
        )

    if binary_norm in {"false", "0"} and not tactic_norm:
        return LabelMappingResult(
            raw_label="False",
            canonical_category="Benign",
            binary_label=0,
            label_status="MAPPED_BENIGN",
        )

    return classify_raw_label(tactic_str)


def _is_zeek_unset(val: Any) -> bool:
    if val is None:
        return True
    if isinstance(val, float) and not math.isfinite(val):
        return True
    text = str(val).strip().lower()
    return text in {"", "-", "(empty)", "nan", "none", "null"}


def parse_uwf_zeek_row(
    raw: Mapping[str, Any],
    *,
    allow_zeek_unset_zero: bool = False,
    subset_name: str = "UWF-ZeekData24",
) -> Dict[str, Any]:
    """Parse one UWF-ZeekData24/22 Zeek CSV row into canonical-flow-v2-18 fields.

    When ``allow_zeek_unset_zero=False`` (strict fail-closed default), empty
    Zeek ``duration`` / ``orig_bytes`` / ``resp_bytes`` raise ``ValueError`` so
    missing measurements are never silently imputed. Setting
    ``allow_zeek_unset_zero=True`` mirrors ``parse_ctu_zeek_conn_row`` by
    treating explicit Zeek unset tokens (``''`` / ``'-'``) as ``0.0`` while
    recording ``had_unset_duration`` and ``had_unset_l4_bytes`` flags.
    """
    src_ip = str(raw.get("src_ip_zeek", raw.get("src_ip", ""))).strip()
    dst_ip = str(raw.get("dest_ip_zeek", raw.get("dest_ip", ""))).strip()
    if not src_ip or not dst_ip:
        raise ValueError("Missing source or destination IP in UWF Zeek row")

    src_port = int(float(raw.get("src_port_zeek", raw.get("src_port"))))
    dst_port = int(float(raw.get("dest_port_zeek", raw.get("dest_port"))))
    ts_ms = float(raw["ts"]) * 1000.0
    raw_proto = str(raw.get("proto", raw.get("protocol", ""))).strip().upper()
    proto_num = parse_protocol_number(raw_proto)

    had_unset_dur = _is_zeek_unset(raw.get("duration"))
    if had_unset_dur:
        if not allow_zeek_unset_zero:
            raise ValueError("Missing Zeek duration under strict anti-imputation mode")
        dur_ms = 0.0
    else:
        dur_ms = float(raw["duration"]) * 1000.0

    raw_ob = raw.get("orig_bytes")
    raw_rb = raw.get("resp_bytes")
    had_unset_bytes = _is_zeek_unset(raw_ob) or _is_zeek_unset(raw_rb)
    if had_unset_bytes and not allow_zeek_unset_zero:
        raise ValueError("Missing Zeek L4 orig_bytes/resp_bytes under strict anti-imputation mode")

    bytes_in = 0.0 if _is_zeek_unset(raw_ob) else float(raw_ob)
    bytes_out = 0.0 if _is_zeek_unset(raw_rb) else float(raw_rb)
    pkts_in = float(raw["orig_pkts"])
    pkts_out = float(raw["resp_pkts"])

    feats = compute_flow_features_from_base(
        duration_ms=dur_ms,
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        pkts_in=pkts_in,
        pkts_out=pkts_out,
        protocol_num=proto_num,
    )

    tactic = raw.get("label_tactic", raw.get("mitre_attack_tactics"))
    label_res = map_uwf_tactic_label(tactic, raw.get("label_binary"))

    out: Dict[str, Any] = {
        "timestamp_ms": ts_ms,
        "source_ip": src_ip,
        "source_port": src_port,
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "source_dataset": "UWF-ZeekData24",
        "scenario_or_device": subset_name,
        "flow_id": str(raw.get("uid", "")),
        "raw_protocol_str": raw_proto,
        "probe_source": "zeek:uwf-conn-csv",
        "raw_label": label_res.raw_label,
        "attack_category": label_res.canonical_category,
        "label_binary": label_res.binary_label,
        "label_status": label_res.label_status,
        "had_unset_duration": had_unset_dur,
        "had_unset_l4_bytes": had_unset_bytes,
    }
    out.update(feats)
    return out


class UWFZeekAdapter(BaseSourceAdapter):
    """Adapter for UWF-ZeekData24 / UWF-ZeekData22 CSV rows (evaluation-only)."""

    def __init__(
        self,
        source_id: str = "source:uwf-zeek24",
        schema_version: str = "2.0.0",
        allow_zeek_unset_zero: bool = False,
    ) -> None:
        super().__init__(source_id=source_id, schema_version=schema_version)
        self.allow_zeek_unset_zero = bool(allow_zeek_unset_zero)

    def adapt_record(
        self, raw_record: Dict[str, Any], record_idx: Optional[int] = None
    ) -> CanonicalNetworkEvent:
        invalid_metadata: Dict[str, str] = {}
        missing_features = []
        ml_feats: Optional[Dict[str, float]] = None

        try:
            parsed = parse_uwf_zeek_row(
                raw_record,
                allow_zeek_unset_zero=self.allow_zeek_unset_zero,
            )
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
            eligibility = InferenceEligibility.RESEARCH_ONLY
            status = ValidationStatus.SEMANTICALLY_COMPATIBLE
        except Exception as exc:
            invalid_metadata["uwf_zeek_parse"] = str(exc)
            src_ip = str(raw_record.get("src_ip_zeek", raw_record.get("src_ip", "")))
            dst_ip = str(raw_record.get("dest_ip_zeek", raw_record.get("dest_ip", "")))
            src_port = -1
            dst_port = -1
            proto_num = 0
            dur_ms = 0.0
            b_in = b_out = p_in = p_out = 0
            ts_ms = None
            missing_features = list(ML_FEATURE_COLUMNS)
            eligibility = InferenceEligibility.FEATURE_INCOMPLETE
            status = ValidationStatus.PARSEABLE

        five_tuple = Network5Tuple(
            ipv4_src_addr=src_ip,
            l4_src_port=src_port,
            ipv4_dst_addr=dst_ip,
            l4_dst_port=dst_port,
            protocol=proto_num,
        )
        metrics = FlowMetrics(
            in_bytes=b_in,
            in_pkts=p_in,
            out_bytes=b_out,
            out_pkts=p_out,
            flow_duration_ms=dur_ms,
        )
        meta = EventMetadata(
            source_id=self.source_id,
            schema_version=self.schema_version,
            raw_record_id=str(raw_record.get("uid", record_idx or "")),
        )
        service_val = str(raw_record.get("service", "") or "").strip()
        app = ApplicationContext(service_name=service_val or None)
        trace_meta = {
            "uid": raw_record.get("uid"),
            "community_id": raw_record.get("community_id"),
            "ts_ms": ts_ms,
            "conn_state": raw_record.get("conn_state"),
            "history": raw_record.get("history"),
            "label_tactic": raw_record.get("label_tactic", raw_record.get("mitre_attack_tactics")),
            "evaluation_only": True,
        }
        return CanonicalNetworkEvent(
            metadata=meta,
            network_5tuple=five_tuple,
            metrics=metrics,
            app_context=app,
            ml_features=ml_feats,
            missing_features=missing_features,
            invalid_metadata=invalid_metadata,
            trace_metadata=trace_meta,
            eligibility=eligibility,
            validation_status=status,
        )
