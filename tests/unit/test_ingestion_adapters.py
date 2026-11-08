"""Unit tests for multi-source ingestion adapters (Issue #46)."""

import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters import (
    AWSVPCFlowAdapter,
    BaseSourceAdapter,
    NetFlowV3Adapter,
    NetFlowV5Adapter,
    SuricataEveAdapter,
    UnsupportedSourceAdapter,
    ZeekConnAdapter,
)
from network_anomaly.ingestion.schemas import InferenceEligibility, ValidationStatus


def test_netflow_v3_adapter_full_features():
    adapter = NetFlowV3Adapter()
    sample_record = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    sample_record.update({
        "IPV4_SRC_ADDR": "192.168.1.100",
        "L4_SRC_PORT": 44321,
        "IPV4_DST_ADDR": "10.0.0.1",
        "L4_DST_PORT": 80,
        "PROTOCOL": 6,
        "FLOW_START_MILLISECONDS": 1600000000000,
        "FLOW_END_MILLISECONDS": 1600000001000,
        "Label": 1,
        "Attack": "Exploits",
    })

    event = adapter.adapt_record(sample_record, record_idx=0)

    assert event.metadata.source_id == "source:nf-v3-external"
    assert event.network_5tuple.ipv4_src_addr == "192.168.1.100"
    assert event.network_5tuple.protocol == 6
    assert event.eligibility == InferenceEligibility.PREDICTION_AVAILABLE
    assert event.validation_status == ValidationStatus.MODEL_VALIDATED
    assert event.ml_features is not None
    assert len(event.ml_features) == len(ML_FEATURE_COLUMNS)
    assert event.trace_metadata["Label"] == 1
    assert event.trace_metadata["Attack"] == "Exploits"


def test_zeek_conn_adapter_abstains_ml_and_preserves_trace():
    adapter = ZeekConnAdapter()
    zeek_rec = {
        "ts": 1518611287.705,
        "uid": "C123456abcdef",
        "id.orig_h": "192.168.1.50",
        "id.orig_p": 54321,
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        "proto": "udp",
        "service": "dns",
        "duration": "0.045",
        "orig_bytes": "120",
        "resp_bytes": "240",
        "orig_pkts": "2",
        "resp_pkts": "2",
        "conn_state": "SF",
        "history": "Dd",
    }

    event = adapter.adapt_record(zeek_rec, record_idx=42)

    assert event.metadata.source_id == "source:zeek-conn"
    assert event.network_5tuple.ipv4_src_addr == "192.168.1.50"
    assert event.network_5tuple.protocol == 17  # UDP
    assert event.metrics.flow_duration_ms == 45.0
    assert event.metrics.in_bytes == 120
    assert event.metrics.out_bytes == 240
    # Crucial: Anti-imputation strictly enforced
    assert event.ml_features is None
    assert event.eligibility == InferenceEligibility.FEATURE_INCOMPATIBLE
    assert event.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert event.trace_metadata["uid"] == "C123456abcdef"
    assert event.trace_metadata["conn_state"] == "SF"


def test_netflow_v5_adapter_abstains_ml():
    adapter = NetFlowV5Adapter()
    v5_rec = {
        "srcaddr": "10.1.1.5",
        "dstaddr": "10.1.1.20",
        "srcport": 8080,
        "dstport": 80,
        "prot": 6,
        "dOctets": 4096,
        "dPkts": 10,
        "first": 1000.0,
        "last": 1002.5,
        "tcp_flags": 18,
    }

    event = adapter.adapt_record(v5_rec, record_idx=1)

    assert event.network_5tuple.ipv4_src_addr == "10.1.1.5"
    assert event.metrics.in_bytes == 4096
    assert event.metrics.flow_duration_ms == 2.5
    assert event.telemetry.tcp_flags == 18
    assert event.ml_features is None
    assert event.eligibility == InferenceEligibility.FEATURE_INCOMPATIBLE


def test_aws_vpc_flow_adapter():
    adapter = AWSVPCFlowAdapter()
    aws_rec = {
        "version": 2,
        "account-id": "123456789012",
        "interface-id": "eni-abc123",
        "srcaddr": "172.31.1.10",
        "dstaddr": "172.31.2.20",
        "srcport": "443",
        "dstport": "52140",
        "protocol": "6",
        "packets": "15",
        "bytes": "2400",
        "start": "1600000000",
        "end": "1600000060",
        "action": "ACCEPT",
        "log-status": "OK",
    }

    event = adapter.adapt_record(aws_rec, record_idx=0)

    assert event.network_5tuple.ipv4_src_addr == "172.31.1.10"
    assert event.metrics.in_bytes == 2400
    assert event.metrics.flow_duration_ms == 60000.0
    assert event.trace_metadata["action"] == "ACCEPT"
    assert event.ml_features is None
    assert event.eligibility == InferenceEligibility.FEATURE_INCOMPATIBLE


def test_suricata_eve_adapter_preserves_alerts():
    adapter = SuricataEveAdapter()
    suricata_rec = {
        "timestamp": "2026-11-08T12:00:00.000Z",
        "event_type": "alert",
        "src_ip": "1.2.3.4",
        "src_port": 1234,
        "dest_ip": "5.6.7.8",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "signature_id": 2001234,
            "signature": "ET SCAN Potential Nmap Scan",
            "category": "Attempted Information Leak",
            "severity": 2,
        },
    }

    event = adapter.adapt_record(suricata_rec, record_idx=10)

    assert event.network_5tuple.ipv4_src_addr == "1.2.3.4"
    assert event.trace_metadata["alert"]["signature_id"] == 2001234
    assert event.ml_features is None
    assert event.eligibility == InferenceEligibility.FEATURE_INCOMPATIBLE


def test_unsupported_source_adapter_sflow():
    adapter = UnsupportedSourceAdapter(source_id="source:sflow")
    event = adapter.adapt_record({"src_ip": "10.0.0.1", "src_port": 80}, record_idx=0)

    assert event.eligibility == InferenceEligibility.SEMANTIC_MISMATCH
    assert event.ml_features is None
    assert "incompatible" in event.ood_warnings[0]


def test_base_adapter_extract_ml_matrix():
    v3_adapter = NetFlowV3Adapter()
    rec1 = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec2 = {col: 20.0 for col in ML_FEATURE_COLUMNS}

    zeek_adapter = ZeekConnAdapter()
    rec3 = {"id.orig_h": "1.1.1.1", "id.orig_p": 80, "id.resp_h": "2.2.2.2", "id.resp_p": 80, "proto": "tcp"}

    events = [
        v3_adapter.adapt_record(rec1, 0),
        zeek_adapter.adapt_record(rec3, 1),
        v3_adapter.adapt_record(rec2, 2),
    ]

    df_ml, eligible_idx = BaseSourceAdapter.extract_ml_matrix(events)

    assert len(eligible_idx) == 2
    assert eligible_idx == [0, 2]
    assert len(df_ml) == 2
    assert list(df_ml.columns) == list(ML_FEATURE_COLUMNS)
    assert df_ml.iloc[0]["PROTOCOL"] == 10.0
    assert df_ml.iloc[1]["PROTOCOL"] == 20.0
