"""Unit tests for Multi-source Quality Gate.

Validates Issue #91 for NetFlow Sentinel v2.0.
"""

from datetime import datetime, timezone

from network_anomaly.canonical.event import CanonicalSecurityEvent, EventKind, RawProvenance
from network_anomaly.data.quality_gate import MultiSourceQualityGate


def create_sample_event(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int = 12345,
    dst_port: int = 80,
    ts_sec: int = 1600000000,
    label: str = "Benign",
) -> CanonicalSecurityEvent:
    return CanonicalSecurityEvent(
        event_timestamp=datetime.fromtimestamp(ts_sec, tz=timezone.utc),
        event_kind=EventKind.FLOW,
        source_id="test_source",
        source_ip=src_ip,
        dest_ip=dst_ip,
        source_port=src_port,
        dest_port=dst_port,
        protocol="TCP",
        attack_category=label,
        raw_provenance=RawProvenance(
            source_file="test_sample.csv", adapter_name="TestQualityGateAdapter"
        ),
    )


class TestQualityGate:
    def test_valid_data_passes(self):
        gate = MultiSourceQualityGate()
        events = [
            create_sample_event(src_ip=f"192.168.1.{i}", ts_sec=1600000000 + i) for i in range(10)
        ]
        report = gate.evaluate_events(events, source_id="test_pass")
        assert report.status == "PASS"
        assert report.metrics.total_records == 10
        assert report.metrics.valid_records == 10
        assert report.metrics.duplicate_records == 0
        assert report.metrics.label_conflict_records == 0

    def test_duplicate_proxy_key_detection(self):
        gate = MultiSourceQualityGate(max_duplicate_rate=0.01)
        # 2 events with identical proxy key
        events = [
            create_sample_event(src_ip="192.168.1.100", ts_sec=1600000000),
            create_sample_event(src_ip="192.168.1.100", ts_sec=1600000000),
        ]
        report = gate.evaluate_events(events, source_id="test_dups")
        assert report.metrics.duplicate_records == 1
        assert report.status == "FAIL"

    def test_label_conflict_detection_and_rejection(self):
        gate = MultiSourceQualityGate(allow_label_conflicts=False)
        # Same proxy key, but one is Benign, one is Exploits
        events = [
            create_sample_event(src_ip="192.168.1.100", ts_sec=1600000000, label="Benign"),
            create_sample_event(src_ip="192.168.1.100", ts_sec=1600000000, label="Exploits"),
        ]
        report = gate.evaluate_events(events, source_id="test_conflict")
        assert report.metrics.label_conflict_records == 1
        assert report.status == "FAIL"
        assert "severe label conflicts" in report.rejection_reason

    def test_missing_required_fields_rejection(self):
        gate = MultiSourceQualityGate(max_missing_rate=0.05)
        events = [create_sample_event(src_ip="0.0.0.0", ts_sec=1600000000 + i) for i in range(10)]
        report = gate.evaluate_events(events, source_id="test_missing")
        assert report.metrics.missing_required_fields == 10
        assert report.status == "FAIL"

    def test_allow_degraded_mode(self):
        gate = MultiSourceQualityGate(max_missing_rate=0.05, allow_degraded=True)
        events = [create_sample_event(src_ip="0.0.0.0", ts_sec=1600000000 + i) for i in range(10)]
        report = gate.evaluate_events(events, source_id="test_degraded")
        assert report.status == "PASS_DEGRADED"
        assert "Degraded mode permitted" in report.rejection_reason
