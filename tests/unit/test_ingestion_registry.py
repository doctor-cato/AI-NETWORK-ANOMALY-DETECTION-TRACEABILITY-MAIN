"""Unit tests for SourceRegistry and source signature detection (Issue #46)."""

import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ALL_COLUMNS, ML_FEATURE_COLUMNS
from network_anomaly.ingestion.exceptions import SourceUnsupportedError
from network_anomaly.ingestion.registry import SourceDefinition, SourceRegistry


def test_registry_contains_default_sources():
    registry = SourceRegistry()
    sources = registry.list_sources()
    source_ids = {s.source_id for s in sources}

    assert "source:nf-v3-canonical" in source_ids
    assert "source:nf-v3-external" in source_ids
    assert "source:zeek-conn" in source_ids
    assert "source:netflow-v5" in source_ids
    assert "source:netflow-v9-ipfix" in source_ids
    assert "source:aws-vpc-flow" in source_ids
    assert "source:suricata-eve" in source_ids
    assert "source:sflow" in source_ids


def test_registry_get_source_success():
    registry = SourceRegistry()
    source = registry.get_source("source:nf-v3-canonical")
    assert source.name == "NF-UNSW-NB15-v3 Canonical Flow"
    assert source.ml_supported is True
    assert source.trace_supported is True


def test_registry_get_unknown_source_raises():
    registry = SourceRegistry()
    with pytest.raises(SourceUnsupportedError, match="not registered"):
        registry.get_source("source:unknown-corp-proxy")


def test_registry_detect_source_netflow_v3():
    registry = SourceRegistry()
    # 47 ML features signature
    detected = registry.detect_source(list(ALL_COLUMNS))
    assert detected is not None
    assert detected.source_id == "source:nf-v3-external"
    assert detected.ml_supported is True


def test_registry_detect_source_zeek():
    registry = SourceRegistry()
    zeek_cols = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service"]
    detected = registry.detect_source(zeek_cols)
    assert detected is not None
    assert detected.source_id == "source:zeek-conn"
    assert detected.ml_supported is False
    assert detected.trace_supported is True


def test_registry_detect_source_netflow_v5():
    registry = SourceRegistry()
    v5_cols = ["srcaddr", "dstaddr", "srcport", "dstport", "dOctets", "dPkts", "prot"]
    detected = registry.detect_source(v5_cols)
    assert detected is not None
    assert detected.source_id == "source:netflow-v5"
    assert detected.ml_supported is False


def test_registry_detect_source_aws_vpc():
    registry = SourceRegistry()
    aws_cols = ["version", "account-id", "interface-id", "srcaddr", "dstaddr", "action"]
    detected = registry.detect_source(aws_cols)
    assert detected is not None
    assert detected.source_id == "source:aws-vpc-flow"


def test_registry_detect_source_suricata():
    registry = SourceRegistry()
    suricata_cols = ["timestamp", "event_type", "src_ip", "dest_ip"]
    detected = registry.detect_source(suricata_cols)
    assert detected is not None
    assert detected.source_id == "source:suricata-eve"


def test_registry_detect_unrecognized_columns_returns_none():
    registry = SourceRegistry()
    unknown_cols = ["random_user", "timestamp", "session_cookie"]
    assert registry.detect_source(unknown_cols) is None
