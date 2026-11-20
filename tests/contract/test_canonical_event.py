"""Contract tests for CanonicalNetworkEvent and leakage isolation."""

from network_anomaly.data.v2_schema import (
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.ingestion.adapters import CanonicalFlowV2Adapter
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


def test_canonical_event_serialization_contract():
    event = CanonicalNetworkEvent(
        metadata=EventMetadata(
            source_id="source:test", schema_version="1.0.0", raw_record_id="rec-1"
        ),
        network_5tuple=Network5Tuple(
            ipv4_src_addr="1.2.3.4",
            l4_src_port=12345,
            ipv4_dst_addr="5.6.7.8",
            l4_dst_port=80,
            protocol=6,
        ),
        metrics=FlowMetrics(
            in_bytes=100, in_pkts=2, out_bytes=200, out_pkts=3, flow_duration_ms=15.5
        ),
        telemetry=ExtendedTelemetry(tcp_flags=18, min_ttl=64, max_ttl=64),
        app_context=ApplicationContext(l7_proto=80, service_name="http"),
        ml_features={"protocol_num": 6.0},
        trace_metadata={"custom_tag": "test"},
        eligibility=InferenceEligibility.PREDICTION_AVAILABLE,
        validation_status=ValidationStatus.SEMANTICALLY_COMPATIBLE,
        ood_warnings=["Test warning"],
    )

    d = event.to_dict()

    assert d["metadata"]["source_id"] == "source:test"
    assert d["metadata"]["raw_record_id"] == "rec-1"
    assert d["network_5tuple"]["ipv4_src_addr"] == "1.2.3.4"
    assert d["network_5tuple"]["protocol"] == 6
    assert d["metrics"]["in_bytes"] == 100
    assert d["metrics"]["flow_duration_ms"] == 15.5
    assert d["telemetry"]["tcp_flags"] == 18
    assert d["app_context"]["l7_proto"] == 80
    assert d["ml_features_available"] is True
    assert d["eligibility"] == "PREDICTION_AVAILABLE"
    assert d["validation_status"] == "SEMANTICALLY_COMPATIBLE"
    assert d["ood_warnings"] == ["Test warning"]


def test_strict_isolation_targets_never_in_ml_features():
    """Verify Contract A: Targets (label_binary, attack_category) are NEVER in ml_features."""
    adapter = CanonicalFlowV2Adapter()
    raw = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    raw["protocol_num"] = 6
    raw["label_binary"] = 1
    raw["attack_category"] = "Exploitation_And_C2"

    event = adapter.adapt_record(raw)

    assert event.ml_features is not None
    for target in TARGET_COLUMNS:
        assert target not in event.ml_features, f"Target '{target}' leaked into ml_features!"
    assert "label_binary" not in event.ml_features
    assert "attack_category" not in event.ml_features


def test_strict_isolation_trace_identifiers_never_in_ml_features():
    """Verify Contract B: 5-tuple IP/Port/Timestamp identifiers are NEVER in ml_features."""
    adapter = CanonicalFlowV2Adapter()
    raw = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    raw["protocol_num"] = 6
    raw["source_ip"] = "192.168.1.1"
    raw["dest_ip"] = "10.0.0.1"
    raw["source_port"] = 55555
    raw["dest_port"] = 443
    raw["timestamp_ms"] = 1700000000000

    event = adapter.adapt_record(raw)

    assert event.ml_features is not None
    for ident in TRACE_METADATA_COLUMNS:
        assert ident not in event.ml_features, f"Identifier '{ident}' leaked into ml_features!"
    assert event.network_5tuple.ipv4_src_addr == "192.168.1.1"
    assert event.network_5tuple.ipv4_dst_addr == "10.0.0.1"
