"""Unit and benchmark tests for Behavioral Vector Engine (Issues #101, #102, #103, #104)."""

from datetime import datetime, timedelta, timezone
import pytest
import numpy as np

from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.behavioral.sessionizer import EventSessionizer
from network_anomaly.behavioral.vector import BehavioralVectorBuilder
from network_anomaly.behavioral.similarity import (
    BehavioralSimilarityCalculator,
    SimilarityMetric,
)
from network_anomaly.behavioral.correlation import IPSpoofingSessionCorrelator


def test_sessionization_and_vector_construction():
    now = datetime(2026, 11, 17, 10, 0, 0, tzinfo=timezone.utc)
    events = []

    # Create 5 events within a 2-minute span (session 1)
    for i in range(5):
        ts = now + timedelta(seconds=i * 20)
        ev = CanonicalSecurityEvent(
            event_timestamp=ts,
            event_kind=EventKind.FLOW,
            source_id="test",
            entity_id="attacker-campaign-01",
            source_ip="192.168.1.50",
            source_port=10000 + i,
            dest_ip="10.0.0.1",
            dest_port=80,
            protocol="TCP",
            flow_metrics=FlowMetrics(
                duration_ms=500.0,
                bytes_in=1000 * (i + 1),
                bytes_out=2000 * (i + 1),
                pkts_in=10,
                pkts_out=15,
                tcp_flags=2,  # SYN
            ),
            raw_provenance=RawProvenance(source_file="test.pcap", adapter_name="test"),
        )
        events.append(ev)

    sessionizer = EventSessionizer(session_timeout_seconds=300.0)
    sessions = sessionizer.sessionize(events)

    assert len(sessions) == 1
    sess = sessions[0]
    assert sess.event_count == 5
    assert sess.bytes_in == sum(1000 * (i + 1) for i in range(5))
    assert sess.syn_flag_count == 5

    # Build 16-D Behavioral Vector
    builder = BehavioralVectorBuilder()
    b_vec = builder.build_vector(sess)

    assert b_vec.dimensions == 16
    assert len(b_vec.features) == 16
    assert b_vec.version == "2.0.0"
    assert b_vec.sha256_hash != ""

    # Verify L2-normalization
    norm = np.linalg.norm(b_vec.to_numpy())
    assert pytest.approx(norm, 1e-3) == 1.0


def test_similarity_metrics():
    calc = BehavioralSimilarityCalculator()
    v1 = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    v2 = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    v3 = np.array([0.0, 1.0, 0.0, 0.0], dtype=np.float32)

    assert pytest.approx(calc.cosine_similarity(v1, v2)) == 1.0
    assert pytest.approx(calc.cosine_similarity(v1, v3)) == 0.0

    assert pytest.approx(calc.normalized_euclidean_similarity(v1, v2)) == 1.0
    assert calc.normalized_euclidean_similarity(v1, v3) < 1.0


def test_ip_independent_session_correlation():
    """Verify that attacker rotating IP addresses is successfully correlated by Behavioral Vector."""
    builder = BehavioralVectorBuilder()
    now = datetime(2026, 11, 17, 12, 0, 0, tzinfo=timezone.utc)

    def make_burst_events(entity_id: str, ip: str, start_time: datetime, n_bytes: int):
        evs = []
        for i in range(4):
            evs.append(
                CanonicalSecurityEvent(
                    event_timestamp=start_time + timedelta(seconds=i * 10),
                    event_kind=EventKind.FLOW,
                    source_id="test",
                    entity_id=entity_id,
                    source_ip=ip,  # Spoofed / rotated IP
                    dest_ip="10.0.0.99",
                    dest_port=443,
                    protocol="TCP",
                    flow_metrics=FlowMetrics(
                        duration_ms=200.0,
                        bytes_in=n_bytes,
                        bytes_out=n_bytes * 3,
                        pkts_in=5,
                        pkts_out=10,
                        tcp_flags=2,
                    ),
                    raw_provenance=RawProvenance(source_file="test.log", adapter_name="test"),
                )
            )
        return evs

    sessionizer = EventSessionizer()

    # Same attacker performing 3 sessions under 3 DIFFERENT IPs
    s1_events = make_burst_events("attacker-X", "198.51.100.1", now, 2500)
    s2_events = make_burst_events("attacker-X", "203.0.113.88", now + timedelta(minutes=10), 2500)
    s3_events = make_burst_events("attacker-X", "192.0.2.77", now + timedelta(minutes=20), 2500)

    # Different benign entity performing normal traffic
    b_events = make_burst_events("user-benign", "10.1.1.5", now, 50)

    sess1 = sessionizer.sessionize(s1_events)[0]
    sess2 = sessionizer.sessionize(s2_events)[0]
    sess3 = sessionizer.sessionize(s3_events)[0]
    sess_b = sessionizer.sessionize(b_events)[0]

    vec1 = builder.build_vector(sess1)
    vec2 = builder.build_vector(sess2)
    vec3 = builder.build_vector(sess3)
    vec_b = builder.build_vector(sess_b)

    ground_truth = {"attacker-X": [vec1, vec2, vec3]}
    session_ip_map = {
        vec1.vector_id: "198.51.100.1",
        vec2.vector_id: "203.0.113.88",
        vec3.vector_id: "192.0.2.77",
        vec_b.vector_id: "10.1.1.5",
    }

    correlator = IPSpoofingSessionCorrelator(match_threshold=0.85)
    bench_results = correlator.evaluate_ip_independence_benchmark(ground_truth, session_ip_map)

    # Strategy A (IP match) gets 0% recall because IPs were changed
    assert bench_results["strategy_a_ip_matching"]["correlation_recall"] == 0.0

    # Strategy B (Behavioral Vector) achieves 100% recall
    assert bench_results["strategy_b_behavioral_vector"]["correlation_recall"] >= 0.85
    assert bench_results["hypothesis_confirmed"] is True
