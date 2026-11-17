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
from network_anomaly.canonical.feature_contract import get_baseline_47_feature_contract
from network_anomaly.streaming.live_orchestrator import LiveSystemOrchestrator
from network_anomaly.telemetry.modes import ModeOrchestrator, MonitoringMode


class TestLiveTelemetryFlow:
    def test_live_orchestrator_complete_pipeline(self):
        contract = get_baseline_47_feature_contract()
        orchestrator = LiveSystemOrchestrator()

        # Regular flow event
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
            raw_provenance=RawProvenance(source_file="live.pcap", adapter_name="LiveAdapter"),
            is_ml_complete=True,
            ml_features={k: 1.0 for k in contract.feature_names},
        )

        res = orchestrator.process_event(event)
        assert res.event_id == event.event_id
        assert res.is_ml_flow is True
        assert res.inference_decision is not None
        assert res.risk_score >= 0.0

    def test_mode_orchestrator_replay(self):
        contract = get_baseline_47_feature_contract()
        orchestrator = LiveSystemOrchestrator()
        mode_mgr = ModeOrchestrator(orchestrator=orchestrator)

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
                ml_features={k: 1.0 for k in contract.feature_names},
            )
            for _ in range(5)
        ]

        summary = mode_mgr.run_replay_scenario(
            events, source_name="test_replay", speed_factor=float("inf")
        )
        assert summary.mode == MonitoringMode.REPLAY
        assert summary.total_events_processed == 5
        assert summary.throughput_events_per_sec > 0.0

    def test_memory_stability_under_volume(self):
        # Process 500 events across distinct entities with bounded LRU eviction
        orchestrator = LiveSystemOrchestrator(max_active_entities=50)
        contract = get_baseline_47_feature_contract()

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
                ml_features={k: 1.0 for k in contract.feature_names},
            )
            orchestrator.process_event(ev)

        # Ensure active tracked entities bounded at max_active_entities
        assert len(orchestrator._entity_access_times) <= 50
        assert len(orchestrator._entity_events) <= 50
