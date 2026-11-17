"""Integration tests for Live Telemetry Orchestration and Multi-Mode Execution.

Validates Issues #134, #135, #136, #137 for NetFlow Sentinel v2.0.
"""

from datetime import datetime, timezone

from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.streaming.live_orchestrator import LiveSystemOrchestrator
from network_anomaly.telemetry.modes import ModeOrchestrator, MonitoringMode


class _NoInferenceEngine:
    """Stub used by memory/bounds tests that do not exercise model inference."""

    def infer_event(self, event, feature_dict, feature_vector=None):
        return None


class TestLiveTelemetryFlow:
    def test_live_orchestrator_complete_pipeline(self, baseline_features):
        features = baseline_features()
        orchestrator = LiveSystemOrchestrator()

        event = CanonicalSecurityEvent(
            event_timestamp=datetime.now(timezone.utc),
            event_kind=EventKind.FLOW,
            source_id="live_probe",
            source_ip="192.168.1.50",
            dest_ip="10.0.0.1",
            dest_port=80,
            protocol="TCP",
            flow_metrics=FlowMetrics(
                duration_ms=100.0,
                bytes_in=1000,
                bytes_out=2000,
                pkts_in=5,
                pkts_out=10,
                tcp_flags=24,
            ),
            raw_provenance=RawProvenance(source_file="probe.pcap", adapter_name="ProbeAdapter"),
            is_ml_complete=True,
            ml_features=features,
        )

        res = orchestrator.process_event(event)
        assert res.event_id == event.event_id
        assert res.is_ml_flow is True
        assert res.feature_status == "MODEL_READY"
        assert res.inference_decision is not None
        assert res.inference_decision.inference_mode in {"REAL_MODELS", "UNAVAILABLE"}
        if res.inference_decision.inference_mode == "REAL_MODELS":
            assert len(res.inference_decision.model_predictions) == 4
        else:
            # No artifact means no fabricated score.
            assert res.inference_decision.model_predictions == {}
            assert res.inference_decision.participating_models == []
        assert 0.0 <= res.risk_score <= 100.0
        assert res.behavioral_vector is not None

    def test_mode_orchestrator_replay(self, baseline_features):
        orchestrator = LiveSystemOrchestrator()
        mode_mgr = ModeOrchestrator(orchestrator=orchestrator)
        features = baseline_features()

        events = [
            CanonicalSecurityEvent(
                event_timestamp=datetime.now(timezone.utc),
                event_kind=EventKind.FLOW,
                source_id="replay_source",
                source_ip="192.168.1.100",
                raw_provenance=RawProvenance(
                    source_file="replay.pcap", adapter_name="ReplayAdapter"
                ),
                is_ml_complete=True,
                ml_features=features,
            )
            for _ in range(5)
        ]

        summary = mode_mgr.run_replay_scenario(
            events, source_name="test_replay", speed_factor=float("inf")
        )
        assert summary.mode == MonitoringMode.REPLAY
        assert summary.total_events_processed == 5
        assert summary.throughput_events_per_sec > 0.0

    def test_memory_stability_under_volume(self, baseline_features):
        # Process 500 events across distinct entities with bounded LRU eviction.
        # A stub engine keeps this a memory-bound test rather than a benchmark.
        orchestrator = LiveSystemOrchestrator(
            max_active_entities=50, inference_engine=_NoInferenceEngine()
        )
        features = baseline_features()

        for i in range(500):
            ev = CanonicalSecurityEvent(
                event_timestamp=datetime.now(timezone.utc),
                event_kind=EventKind.FLOW,
                source_id="stress_test",
                source_ip=f"10.0.{(i // 256)}.{i % 256}",
                raw_provenance=RawProvenance(
                    source_file="stress.pcap", adapter_name="StressAdapter"
                ),
                is_ml_complete=True,
                ml_features=features,
            )
            orchestrator.process_event(ev)

        # Ensure active tracked entities bounded at max_active_entities
        assert len(orchestrator._entity_access_times) <= 50
        assert len(orchestrator._entity_events) <= 50
