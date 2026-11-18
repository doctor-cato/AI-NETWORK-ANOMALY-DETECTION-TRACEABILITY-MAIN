"""Unit tests for UWF-ZeekData24/22 adapter and anti-imputation behavior."""

from __future__ import annotations

import math

import pytest

from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters.uwf_zeek import (
    UWFZeekAdapter,
    map_uwf_tactic_label,
    parse_uwf_zeek_row,
)
from network_anomaly.ingestion.registry import SourceRegistry
from network_anomaly.ingestion.schemas import InferenceEligibility, ValidationStatus


def test_uwf_zeek_adapter_registered_and_detectable() -> None:
    reg = SourceRegistry()
    src = reg.get_source("source:uwf-zeek24")
    assert src.adapter_name == "UWFZeekAdapter"
    detected = reg.detect_source(
        [
            "src_ip_zeek",
            "dest_ip_zeek",
            "src_port_zeek",
            "dest_port_zeek",
            "orig_bytes",
            "resp_bytes",
            "orig_pkts",
            "resp_pkts",
            "duration",
            "proto",
            "ts",
        ]
    )
    assert detected is not None
    assert detected.source_id == "source:uwf-zeek24"
    adapter = reg.create_adapter("source:uwf-zeek24")
    assert isinstance(adapter, UWFZeekAdapter)


def test_uwf_zeek_parse_l4_bytes_and_taxonomy_mapping() -> None:
    row = {
        "ts": "1709288997.389379",
        "src_ip_zeek": "143.88.3.11",
        "src_port_zeek": "46305",
        "dest_ip_zeek": "143.88.4.13",
        "dest_port_zeek": "4848",
        "proto": "tcp",
        "duration": "0.006303",
        "orig_bytes": "120",
        "resp_bytes": "240",
        "orig_ip_bytes": "864",
        "resp_ip_bytes": "656",
        "orig_pkts": "16",
        "resp_pkts": "12",
        "uid": "CZlP6n1w1g5GCfyPHk",
        "community_id": "1:test",
        "label_tactic": "Credential Access",
        "label_binary": "True",
    }
    parsed = parse_uwf_zeek_row(row)
    assert math.isclose(parsed["duration_ms"], 6.303, rel_tol=1e-6)
    # Must use L4 orig_bytes/resp_bytes (120/240), NOT L3 orig_ip_bytes (864/656)
    assert parsed["bytes_in"] == 120.0
    assert parsed["bytes_out"] == 240.0
    assert parsed["protocol_num"] == 6.0
    assert parsed["attack_category"] == "Credential_Attack"
    assert parsed["label_binary"] == 1
    assert parsed["label_status"] == "MAPPED_ATTACK"
    for col in ML_FEATURE_COLUMNS:
        assert col in parsed and math.isfinite(parsed[col])


def test_uwf_zeek_strict_anti_imputation_and_label_guard() -> None:
    incomplete_row = {
        "ts": "1730800800.646468",
        "src_ip_zeek": "143.88.255.11",
        "src_port_zeek": "53888",
        "dest_ip_zeek": "8.8.4.4",
        "dest_port_zeek": "53",
        "proto": "udp",
        "duration": "",
        "orig_bytes": "",
        "resp_bytes": "0",
        "orig_pkts": "1",
        "resp_pkts": "0",
        "label_tactic": "none",
        "label_binary": "False",
    }
    with pytest.raises(ValueError, match="strict anti-imputation"):
        parse_uwf_zeek_row(incomplete_row, allow_zeek_unset_zero=False)

    strict_adapter = UWFZeekAdapter(allow_zeek_unset_zero=False)
    ev_bad = strict_adapter.adapt_record(incomplete_row)
    assert ev_bad.ml_features is None
    assert ev_bad.eligibility == InferenceEligibility.FEATURE_INCOMPLETE

    zeek_unset_adapter = UWFZeekAdapter(allow_zeek_unset_zero=True)
    ev_ok = zeek_unset_adapter.adapt_record(incomplete_row)
    assert ev_ok.ml_features is not None
    assert ev_ok.validation_status == ValidationStatus.SEMANTICALLY_COMPATIBLE
    assert ev_ok.eligibility == InferenceEligibility.RESEARCH_ONLY

    # Conflicting tactic='none' + binary='True' must stay UNMAPPED (never coerced to Benign)
    conflict = map_uwf_tactic_label("none", "True")
    assert conflict.canonical_category == "Unmapped"
    assert conflict.binary_label is None
