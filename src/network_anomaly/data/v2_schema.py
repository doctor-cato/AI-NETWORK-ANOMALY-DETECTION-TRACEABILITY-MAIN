"""Canonical Flow Feature Contract v2.0 for NetFlow Sentinel v2.

Replaces the retired v1 NF-UNSW-NB15-v3 47-feature nProbe contract with a
dataset-native, probe-aligned 18-feature contract built strictly from real
bidirectional flow fields shared across:
  - AIT NetFlow Data Set v2 (Tstat tcp_complete, tcp_nocomplete, udp_complete)
  - CTU-SME-11 (Zeek conn.log.labeled)
  - Live NetFlow v9 / IPFIX / PCAP-to-flow telemetry (FlowMetrics)

Zero fabricated features, zero TTL shortcuts, and zero target/identifier leakage.
"""

from __future__ import annotations

import math
from hashlib import blake2b
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

DATASET_SUITE_NAME = "NetFlow-Sentinel-v2-MultiSource"
FEATURE_CONTRACT_ID = "canonical-flow-v2-18"
FEATURE_CONTRACT_VERSION = "2.0.0"
FINGERPRINT_SCHEMA_VERSION = "canonical-flow-v2-fingerprint-v1"

TIMESTAMP_COLUMNS: Tuple[str, ...] = ("timestamp_ms",)
IDENTIFIER_COLUMNS: Tuple[str, ...] = ("source_ip", "dest_ip")
PORT_COLUMNS: Tuple[str, ...] = ("source_port", "dest_port")
TRACE_METADATA_COLUMNS: Tuple[str, ...] = (
    TIMESTAMP_COLUMNS + IDENTIFIER_COLUMNS + PORT_COLUMNS
)
PROVENANCE_COLUMNS: Tuple[str, ...] = (
    "source_dataset",
    "scenario_or_device",
    "flow_id",
    "raw_protocol_str",
    "probe_source",
)
TARGET_COLUMNS: Tuple[str, ...] = (
    "label_binary",
    "attack_category",
    "raw_label",
    "label_status",
)

# 6 base observed flow fields + 12 deterministic flow-dynamics features = 18 ML features
BASE_FLOW_FEATURE_COLUMNS: Tuple[str, ...] = (
    "duration_ms",
    "bytes_in",
    "bytes_out",
    "pkts_in",
    "pkts_out",
    "protocol_num",
)

DERIVED_FLOW_FEATURE_COLUMNS: Tuple[str, ...] = (
    "total_bytes",
    "total_pkts",
    "bytes_in_ratio",
    "pkts_in_ratio",
    "bytes_per_pkt_in",
    "bytes_per_pkt_out",
    "bytes_per_sec_in",
    "bytes_per_sec_out",
    "pkts_per_sec",
    "has_response",
    "is_tcp",
    "is_udp",
)

ML_FEATURE_COLUMNS: Tuple[str, ...] = BASE_FLOW_FEATURE_COLUMNS + DERIVED_FLOW_FEATURE_COLUMNS

CATEGORICAL_CODED_COLUMNS: Tuple[str, ...] = ("protocol_num",)
QUANTITATIVE_ML_COLUMNS: Tuple[str, ...] = tuple(
    col for col in ML_FEATURE_COLUMNS if col not in set(CATEGORICAL_CODED_COLUMNS)
)

ALL_CANONICAL_COLUMNS: Tuple[str, ...] = (
    TRACE_METADATA_COLUMNS
    + PROVENANCE_COLUMNS
    + ML_FEATURE_COLUMNS
    + TARGET_COLUMNS
)

PROTOCOL_NAME_TO_NUMBER: Dict[str, int] = {
    "ICMP": 1,
    "IGMP": 2,
    "TCP": 6,
    "UDP": 17,
    "GRE": 47,
    "ESP": 50,
    "AH": 51,
    "ICMPV6": 58,
    "IPV6-ICMP": 58,
    "OSPF": 89,
}


def parse_protocol_number(raw_proto: Any) -> int:
    """Convert numeric or string protocol representation to IANA protocol number."""
    if raw_proto is None or isinstance(raw_proto, bool):
        raise ValueError(f"Invalid protocol value: {raw_proto!r}")
    if isinstance(raw_proto, (int, float)):
        fval = float(raw_proto)
        if not math.isfinite(fval) or fval < 0 or fval > 255:
            raise ValueError(f"Protocol number out of range [0, 255]: {raw_proto!r}")
        return int(fval)
    text = str(raw_proto).strip().upper()
    if not text:
        raise ValueError("Empty protocol string")
    if text in PROTOCOL_NAME_TO_NUMBER:
        return PROTOCOL_NAME_TO_NUMBER[text]
    try:
        fval = float(text)
    except ValueError as exc:
        raise ValueError(f"Unrecognized protocol: {raw_proto!r}") from exc
    if not math.isfinite(fval) or fval < 0 or fval > 255:
        raise ValueError(f"Protocol number out of range [0, 255]: {raw_proto!r}")
    return int(fval)


def compute_flow_features_from_base(
    *,
    duration_ms: float,
    bytes_in: float,
    bytes_out: float,
    pkts_in: float,
    pkts_out: float,
    protocol_num: int,
) -> Dict[str, float]:
    """Compute the canonical 18-feature dictionary from 6 validated base flow fields.

    Raises ValueError on non-finite or negative values (fail-closed, zero imputation).
    """
    vals = (duration_ms, bytes_in, bytes_out, pkts_in, pkts_out, float(protocol_num))
    if not all(math.isfinite(v) for v in vals):
        raise ValueError("Base flow fields must all be finite numeric values")
    if min(duration_ms, bytes_in, bytes_out, pkts_in, pkts_out) < 0.0:
        raise ValueError(
            f"Negative physical flow metric prohibited: "
            f"dur={duration_ms}, bytes=({bytes_in},{bytes_out}), pkts=({pkts_in},{pkts_out})"
        )
    if not (0 <= int(protocol_num) <= 255):
        raise ValueError(f"protocol_num out of [0, 255]: {protocol_num}")

    proto_i = int(protocol_num)
    total_bytes = float(bytes_in + bytes_out)
    total_pkts = float(pkts_in + pkts_out)
    safe_dur_ms = max(float(duration_ms), 1.0)

    return {
        "duration_ms": float(duration_ms),
        "bytes_in": float(bytes_in),
        "bytes_out": float(bytes_out),
        "pkts_in": float(pkts_in),
        "pkts_out": float(pkts_out),
        "protocol_num": float(proto_i),
        "total_bytes": total_bytes,
        "total_pkts": total_pkts,
        "bytes_in_ratio": float(bytes_in / max(total_bytes, 1.0)),
        "pkts_in_ratio": float(pkts_in / max(total_pkts, 1.0)),
        "bytes_per_pkt_in": float(bytes_in / max(pkts_in, 1.0)),
        "bytes_per_pkt_out": float(bytes_out / max(pkts_out, 1.0)),
        "bytes_per_sec_in": float((bytes_in * 1000.0) / safe_dur_ms),
        "bytes_per_sec_out": float((bytes_out * 1000.0) / safe_dur_ms),
        "pkts_per_sec": float((total_pkts * 1000.0) / safe_dur_ms),
        "has_response": 1.0 if pkts_out > 0.0 else 0.0,
        "is_tcp": 1.0 if proto_i == 6 else 0.0,
        "is_udp": 1.0 if proto_i == 17 else 0.0,
    }


def validate_semantic_column_roles() -> bool:
    """Ensure categorical-coded and quantitative roles partition ML_FEATURE_COLUMNS."""
    cat_set = set(CATEGORICAL_CODED_COLUMNS)
    quant_set = set(QUANTITATIVE_ML_COLUMNS)
    ml_set = set(ML_FEATURE_COLUMNS)
    if cat_set & quant_set:
        raise ValueError("categorical-coded and quantitative v2 columns overlap")
    if cat_set | quant_set != ml_set:
        raise ValueError("semantic column roles must cover the v2 ML contract exactly")
    return True


def validate_feature_selection(
    columns: Iterable[str],
    *,
    require_complete: bool = True,
) -> Tuple[str, ...]:
    """Reject targets, trace metadata, provenance leakage, unknowns, and duplicates."""
    selected = tuple(columns)
    if len(selected) != len(set(selected)):
        raise ValueError("feature selection contains duplicate columns")
    forbidden_cols = set(TRACE_METADATA_COLUMNS) | set(PROVENANCE_COLUMNS) | set(TARGET_COLUMNS)
    # Also explicitly block AIT/CTU leakage columns if raw columns are ever checked
    forbidden_cols |= {
        "role_cli",
        "role_serv",
        "network_cli",
        "network_serv",
        "ipv4_address_cli",
        "ipv4_address_serv",
        "label",
        "detailedlabel",
        "Label",
        "Attack",
        "uid",
    }
    forbidden = sorted(set(selected) & forbidden_cols)
    if forbidden:
        raise ValueError(f"feature selection contains forbidden leakage columns: {forbidden}")
    unknown = sorted(set(selected) - set(ML_FEATURE_COLUMNS))
    if unknown:
        raise ValueError(f"feature selection contains unknown columns: {unknown}")
    if require_complete and selected != ML_FEATURE_COLUMNS:
        raise ValueError(
            f"feature selection does not match ordered {FEATURE_CONTRACT_ID} contract"
        )
    return selected


def canonical_flow_group(
    row: Mapping[str, Any],
    *,
    bucket_milliseconds: int = 300_000,
) -> Tuple[Tuple[str, int], Tuple[str, int], int, int]:
    """Create a direction-independent 5-tuple/time-bucket grouping key."""
    if bucket_milliseconds <= 0:
        raise ValueError("bucket_milliseconds must be positive")
    ts_ms = int(float(row["timestamp_ms"]))
    src = (str(row["source_ip"]), int(row["source_port"]))
    dst = (str(row["dest_ip"]), int(row["dest_port"]))
    first, second = sorted((src, dst))
    proto = int(float(row["protocol_num"]))
    return first, second, proto, ts_ms // bucket_milliseconds


def _fingerprint(row: Mapping[str, Any], columns: Sequence[str], purpose: str) -> bytes:
    digest = blake2b(digest_size=16)
    digest.update(FINGERPRINT_SCHEMA_VERSION.encode("ascii"))
    digest.update(purpose.encode("ascii"))
    for col in columns:
        val = str(row[col]).encode("utf-8", errors="surrogatepass")
        digest.update(len(val).to_bytes(4, "big"))
        digest.update(val)
    return digest.digest()


def ml_feature_fingerprint(row: Mapping[str, Any]) -> bytes:
    """Fingerprint the ordered 18-feature canonical v2 ML matrix."""
    return _fingerprint(row, ML_FEATURE_COLUMNS, "ml-feature-v2")


def source_feature_fingerprint(row: Mapping[str, Any]) -> bytes:
    """Fingerprint trace metadata + ML features (excluding targets)."""
    cols = TRACE_METADATA_COLUMNS + ML_FEATURE_COLUMNS
    return _fingerprint(row, cols, "source-feature-v2")


def full_row_fingerprint(row: Mapping[str, Any]) -> bytes:
    """Fingerprint trace metadata + ML features + targets."""
    cols = TRACE_METADATA_COLUMNS + ML_FEATURE_COLUMNS + ("label_binary", "attack_category")
    return _fingerprint(row, cols, "full-row-v2")


def parse_ait_nds_tstat_row(
    raw: Mapping[str, Any],
    *,
    flow_kind: str,
    scenario: str = "unknown",
) -> Optional[Dict[str, Any]]:
    """Parse one row from AIT-NDS-v2 (tcp_complete, tcp_nocomplete, or udp_complete).

    Raises ValueError on missing/invalid physical values.
    """
    is_udp = flow_kind == "udp_complete"
    if is_udp:
        src_ip = str(raw.get("#c_ip:1") or raw.get("c_ip:1") or "").strip()
        src_port = int(float(raw["c_port:2"]))
        dst_ip = str(raw.get("s_ip:10") or "").strip()
        dst_port = int(float(raw["s_port:11"]))
        ts_ms = float(raw["c_first_abs:3"])
        # Tstat udp_complete records c_durat:4 and s_durat:13 in seconds (tcp_*.csv uses ms).
        dur_ms = max(float(raw["c_durat:4"]), float(raw["s_durat:13"])) * 1000.0
        bytes_in = float(raw["c_bytes_all:5"])
        bytes_out = float(raw["s_bytes_all:14"])
        pkts_in = float(raw["c_pkts_all:6"])
        pkts_out = float(raw["s_pkts_all:15"])
        proto_num = 17
        raw_proto = "UDP"
    else:
        src_ip = str(raw.get("#15#c_ip:1") or raw.get("c_ip:1") or "").strip()
        src_port = int(float(raw["c_port:2"]))
        dst_ip = str(raw.get("s_ip:15") or "").strip()
        dst_port = int(float(raw["s_port:16"]))
        ts_ms = float(raw["first:29"])
        dur_ms = float(raw["durat:31"])
        bytes_in = float(raw["c_bytes_all:9"])
        bytes_out = float(raw["s_bytes_all:23"])
        pkts_in = float(raw["c_pkts_all:3"])
        pkts_out = float(raw["s_pkts_all:17"])
        proto_num = 6
        raw_proto = "TCP"

    feats = compute_flow_features_from_base(
        duration_ms=dur_ms,
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        pkts_in=pkts_in,
        pkts_out=pkts_out,
        protocol_num=proto_num,
    )
    out: Dict[str, Any] = {
        "timestamp_ms": ts_ms,
        "source_ip": src_ip,
        "source_port": src_port,
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "source_dataset": "AIT-NDS-v2",
        "scenario_or_device": scenario,
        "raw_protocol_str": raw_proto,
        "probe_source": f"tstat:{flow_kind}",
        "raw_label": str(raw.get("label", "")),
    }
    out.update(feats)
    return out


def parse_ctu_zeek_conn_row(
    raw: Mapping[str, Any],
    *,
    device: str = "unknown",
) -> Dict[str, Any]:
    """Parse one row from CTU-SME-11 Zeek conn.log.labeled into canonical v2 schema.

    Uses L4 transport payload ``orig_bytes`` and ``resp_bytes`` (coercing Zeek
    ``'-'`` / ``'(empty)'`` to ``0.0``) so byte semantics match AIT-NDS-v2 Tstat
    ``c_bytes_all``/``s_bytes_all`` (fallback to ``orig_ip_bytes``/``resp_ip_bytes``
    only when L4 byte keys are absent). When Zeek ``duration`` is ``'-'``,
    ``duration_ms`` is explicitly ``0.0``.
    """
    ts_sec = float(raw["ts"])
    ts_ms = ts_sec * 1000.0
    src_ip = str(raw["id.orig_h"]).strip()
    src_port = int(raw["id.orig_p"])
    dst_ip = str(raw["id.resp_h"]).strip()
    dst_port = int(raw["id.resp_p"])
    raw_proto = str(raw["proto"]).strip().upper()
    proto_num = parse_protocol_number(raw_proto)

    raw_dur = str(raw.get("duration", "-")).strip()
    dur_ms = 0.0 if raw_dur in ("-", "", "(empty)") else float(raw_dur) * 1000.0

    def _zeek_l4_bytes(l4_key: str, l3_fallback_key: str) -> float:
        if l4_key in raw:
            val = str(raw.get(l4_key, "-")).strip()
            return 0.0 if val in ("-", "", "(empty)", "nan", "NaN", "None") else float(val)
        return float(raw[l3_fallback_key])

    bytes_in = _zeek_l4_bytes("orig_bytes", "orig_ip_bytes")
    bytes_out = _zeek_l4_bytes("resp_bytes", "resp_ip_bytes")
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
    out: Dict[str, Any] = {
        "timestamp_ms": ts_ms,
        "source_ip": src_ip,
        "source_port": src_port,
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "source_dataset": "CTU-SME-11",
        "scenario_or_device": device,
        "flow_id": str(raw.get("uid", "")),
        "raw_protocol_str": raw_proto,
        "probe_source": "zeek:conn.log.labeled",
        "raw_label": str(raw.get("label", "")),
        "raw_detailed_label": str(raw.get("detailedlabel", raw.get("detailed-label", ""))),
    }
    out.update(feats)
    return out
