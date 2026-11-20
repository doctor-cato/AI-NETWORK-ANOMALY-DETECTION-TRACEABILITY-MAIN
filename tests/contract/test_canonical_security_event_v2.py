"""Contract tests for CanonicalSecurityEvent v2 and FeatureContract (Issue #79)."""

from datetime import datetime, timezone

import numpy as np
import pytest

from network_anomaly.canonical.event import (
    AuthData,
    CanonicalSecurityEvent,
    DNSData,
    EventKind,
    FlowMetrics,
    HTTPData,
    RawProvenance,
    SystemData,
    ValidationStatus,
)
from network_anomaly.canonical.feature_contract import (
    get_flow_feature_contract_v2,
)
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS


def test_canonical_security_event_v2_flow():
    now = datetime.now(timezone.utc)
    event = CanonicalSecurityEvent(
        event_timestamp=now,
        event_kind=EventKind.FLOW,
        source_id="source:ait-nds-v2",
        entity_id="entity:host-101",
        source_ip="192.168.1.10",
        source_port=54321,
        dest_ip="10.0.0.5",
        dest_port=443,
        protocol="TCP",
        flow_metrics=FlowMetrics(duration_ms=120.5, bytes_in=1000, bytes_out=5000),
        raw_provenance=RawProvenance(
            source_file="test_flow.csv",
            line_or_offset=15,
            adapter_name="CanonicalFlowV2Adapter",
        ),
    )

    assert event.event_kind == EventKind.FLOW
    assert event.source_ip == "192.168.1.10"
    assert event.dest_port == 443
    assert event.flow_metrics.bytes_in == 1000
    assert event.raw_provenance.line_or_offset == 15
    assert event.validation_status == ValidationStatus.VALID


def test_canonical_security_event_v2_other_kinds():
    now = datetime.now(timezone.utc)
    # DNS Event
    dns_event = CanonicalSecurityEvent(
        event_timestamp=now,
        event_kind=EventKind.DNS,
        source_id="source:zeek-dns",
        dest_ip="8.8.8.8",
        dest_port=53,
        dns_data=DNSData(query_name="malicious.example.com", query_type="A", rcode=0),
        raw_provenance=RawProvenance(source_file="dns.log", adapter_name="ZeekDNSAdapter"),
    )
    assert dns_event.dns_data.query_name == "malicious.example.com"

    # Web Event
    web_event = CanonicalSecurityEvent(
        event_timestamp=now,
        event_kind=EventKind.WEB,
        source_id="source:nginx-access",
        http_data=HTTPData(method="POST", url="/api/v1/login", status_code=401),
        raw_provenance=RawProvenance(source_file="access.log", adapter_name="NginxWebAdapter"),
    )
    assert web_event.http_data.status_code == 401

    # Auth Event
    auth_event = CanonicalSecurityEvent(
        event_timestamp=now,
        event_kind=EventKind.AUTH,
        source_id="source:auth-audit",
        auth_data=AuthData(username="admin", auth_result="FAILURE", service="ssh"),
        raw_provenance=RawProvenance(source_file="auth.log", adapter_name="LinuxAuthAdapter"),
    )
    assert auth_event.auth_data.auth_result == "FAILURE"

    # System Event
    sys_event = CanonicalSecurityEvent(
        event_timestamp=now,
        event_kind=EventKind.SYSTEM,
        source_id="source:sysmon",
        system_data=SystemData(
            process_name="powershell.exe", action="PROCESS_CREATE", process_id=4012
        ),
        raw_provenance=RawProvenance(source_file="sysmon.json", adapter_name="SysmonAdapter"),
    )
    assert sys_event.system_data.process_id == 4012


def test_port_validation():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError, match="out of valid bounds"):
        CanonicalSecurityEvent(
            event_timestamp=now,
            event_kind=EventKind.FLOW,
            source_id="source:test",
            source_port=70000,  # Invalid port
            raw_provenance=RawProvenance(source_file="test.csv", adapter_name="test"),
        )


def test_feature_contract_validation_and_no_imputation():
    contract = get_flow_feature_contract_v2()
    assert len(contract.feature_names) == 18

    # 1. Complete valid 18 features
    complete_record = {feat: float(i + 1) for i, feat in enumerate(ML_FEATURE_COLUMNS)}
    is_valid, errors = contract.validate_features(complete_record)
    assert is_valid is True
    assert len(errors) == 0

    vec = contract.extract_vector(complete_record)
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (18,)
    assert vec[0] == 1.0

    # 2. Missing feature: strictly rejected, no implicit imputation
    incomplete_record = dict(complete_record)
    del incomplete_record[contract.feature_names[0]]  # Remove 1 feature
    is_valid, errors = contract.validate_features(incomplete_record)
    assert is_valid is False
    assert contract.feature_names[0] in errors

    with pytest.raises(ValueError, match="Implicit imputation is strictly prohibited"):
        contract.extract_vector(incomplete_record)

    # 3. NaN/Inf feature rejected
    nan_record = dict(complete_record)
    nan_record[contract.feature_names[1]] = float("nan")
    is_valid, errors = contract.validate_features(nan_record)
    assert is_valid is False
    assert contract.feature_names[1] in errors


def test_v2_canonical_row_compatibility():
    """Verify that a full 18-feature canonical v2 row maps cleanly to CanonicalSecurityEvent."""
    contract = get_flow_feature_contract_v2()
    dummy_row = {feat: 0.5 for feat in ML_FEATURE_COLUMNS}
    dummy_row["timestamp_ms"] = 1600000000000
    dummy_row["source_ip"] = "192.168.1.100"
    dummy_row["dest_ip"] = "10.0.0.1"
    dummy_row["source_port"] = 1024
    dummy_row["dest_port"] = 80
    dummy_row["label_binary"] = 0
    dummy_row["attack_category"] = "Benign"

    now = datetime.fromtimestamp(dummy_row["timestamp_ms"] / 1000.0, timezone.utc)
    event = CanonicalSecurityEvent(
        event_timestamp=now,
        event_kind=EventKind.FLOW,
        source_id="source:ait-nds-v2",
        source_ip=dummy_row["source_ip"],
        source_port=dummy_row["source_port"],
        dest_ip=dummy_row["dest_ip"],
        dest_port=dummy_row["dest_port"],
        protocol="TCP",
        raw_provenance=RawProvenance(
            source_file="v2_sample.csv", adapter_name="CanonicalFlowV2Adapter"
        ),
        ml_features={k: float(dummy_row[k]) for k in ML_FEATURE_COLUMNS},
        is_ml_complete=True,
    )

    assert event.is_ml_complete is True
    assert event.ml_features is not None
    vec = contract.extract_vector(event.ml_features)
    assert vec.shape == (18,)
