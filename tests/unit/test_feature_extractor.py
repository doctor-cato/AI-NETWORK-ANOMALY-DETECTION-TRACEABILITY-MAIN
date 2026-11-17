"""Feature contract tests: strict 18 v2 features, zero imputation, explicit rejection."""

from __future__ import annotations

from datetime import datetime, timezone

import numpy as np

from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.canonical.feature_contract import get_flow_feature_contract_v2
from network_anomaly.streaming.feature_extractor import RealtimeFeatureExtractor


def _flow_event(ml_features=None, metrics=None, protocol="TCP") -> CanonicalSecurityEvent:
    return CanonicalSecurityEvent(
        event_timestamp=datetime.now(timezone.utc),
        event_kind=EventKind.FLOW,
        source_id="unit-test",
        source_ip="192.0.2.1",
        dest_ip="192.0.2.2",
        source_port=40000,
        dest_port=443,
        protocol=protocol,
        flow_metrics=metrics,
        raw_provenance=RawProvenance(source_file="unit.pcap", adapter_name="UnitTest"),
        ml_features=ml_features,
    )


class TestFeatureContract:
    def test_complete_heterogeneous_row_is_accepted_in_contract_order(self, baseline_features):
        contract = get_flow_feature_contract_v2()
        row = baseline_features()
        extractor = RealtimeFeatureExtractor()

        result = extractor.extract(_flow_event(row))

        assert result.is_ml_ready is True
        assert result.status == "MODEL_READY"
        assert result.feature_vector.shape == (18,)
        expected = np.asarray([row[name] for name in contract.feature_names])
        np.testing.assert_allclose(result.feature_vector, expected)
        assert result.missing_features == []
        assert len(set(row.values())) > 5  # fixture is not a uniform fill

    def test_partial_row_is_rejected_with_exact_missing_list(self):
        extractor = RealtimeFeatureExtractor()
        result = extractor.extract(_flow_event({"bytes_out": 10.0}))

        assert result.is_ml_ready is False
        assert result.status == "NOT_MODEL_READY"
        assert result.feature_vector is None
        assert result.feature_dict is None
        assert len(result.missing_features) == 17
        assert "bytes_out" not in result.missing_features
        assert "bytes_in" in result.missing_features

    def test_incomplete_flow_metrics_rejects_without_silent_imputation(self):
        metrics = FlowMetrics(
            duration_ms=125.0,
            bytes_in=900,
            bytes_out=None,
            pkts_in=9,
            pkts_out=12,
        )
        extractor = RealtimeFeatureExtractor()
        result = extractor.extract(_flow_event(metrics=metrics, protocol="TCP"))

        assert result.is_ml_ready is False
        assert result.feature_vector is None

    def test_complete_flow_metrics_derives_all_18_v2_features(self):
        contract = get_flow_feature_contract_v2()
        metrics = FlowMetrics(
            duration_ms=34.0,
            bytes_in=1580,
            bytes_out=2260,
            pkts_in=16,
            pkts_out=18,
            tcp_flags=27,
        )

        result = RealtimeFeatureExtractor().extract(
            _flow_event(metrics=metrics, protocol="TCP")
        )
        assert result.is_ml_ready is True
        assert result.feature_vector.shape == (18,)
        index = contract.feature_names.index("bytes_in")
        assert result.feature_vector[index] == 1580.0

    def test_non_flow_events_are_routed_not_scored(self):
        event = CanonicalSecurityEvent(
            event_timestamp=datetime.now(timezone.utc),
            event_kind=EventKind.DNS,
            source_id="dns-test",
            raw_provenance=RawProvenance(source_file="dns.log", adapter_name="UnitTest"),
        )
        result = RealtimeFeatureExtractor().extract(event)
        assert result.is_ml_ready is False
        assert result.status == "ROUTE_ONLY"

    def test_missing_features_are_mutated_for_trace_handling(self):
        event = _flow_event({"bytes_out": 10.0})
        extractor = RealtimeFeatureExtractor()
        results, route_only = extractor.extract_batch([event])

        assert len(results) == 1
        assert route_only == [event]
        assert event.is_ml_complete is False
        assert event.validation_status.value == "FEATURE_INCOMPLETE"
        assert event.validation_errors
