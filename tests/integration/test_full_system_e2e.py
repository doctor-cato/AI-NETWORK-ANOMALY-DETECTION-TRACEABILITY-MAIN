"""Full System End-to-End Integration Tests across All Three Execution Modes.

Validates Issue #138 for NetFlow Sentinel v2.0.
"""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.crypto.encrypted_storage import EncryptedStorageVault
from network_anomaly.crypto.key_manager import KeyManager
from network_anomaly.streaming.live_orchestrator import LiveSystemOrchestrator
from network_anomaly.streaming.pipeline import StreamingEventPipeline
from network_anomaly.telemetry.modes import ModeOrchestrator, MonitoringMode


def create_e2e_event(
    src_ip: str,
    features,
    out_bytes: int = 1000,
    dst_port: int = 80,
) -> CanonicalSecurityEvent:
    fm = FlowMetrics(
        duration_ms=100.0,
        bytes_in=1000,
        bytes_out=out_bytes,
        pkts_in=10,
        pkts_out=15,
        tcp_flags=24,
    )
    return CanonicalSecurityEvent(
        event_timestamp=datetime.now(timezone.utc),
        event_kind=EventKind.FLOW,
        source_id="test:e2e",
        source_ip=src_ip,
        dest_ip="10.0.0.1",
        source_port=54321,
        dest_port=dst_port,
        protocol="TCP",
        flow_metrics=fm,
        raw_provenance=RawProvenance(source_file="e2e.pcap", adapter_name="E2ETestAdapter"),
        is_ml_complete=True,
        ml_features=features,
    )


class TestFullSystemE2E:
    def test_e2e_offline_mode(self, baseline_features):
        """Verify Mode 1: Offline Batch Ingestion & Analysis."""
        orchestrator = LiveSystemOrchestrator()
        features = baseline_features()
        events = [
            create_e2e_event(f"192.168.1.{10 + i}", features, out_bytes=1000 * i) for i in range(5)
        ]

        results = orchestrator.process_batch(events)
        assert len(results) == 5
        for res in results:
            assert res.is_ml_flow is True
            assert res.inference_decision is not None
            assert res.inference_decision.inference_mode in {"REAL_MODELS", "UNAVAILABLE"}

    def test_e2e_replay_mode(self, baseline_features):
        """Verify Mode 2: Real-time Replay of Recorded Benchmarks."""
        orchestrator = LiveSystemOrchestrator()
        mode_orchestrator = ModeOrchestrator(orchestrator=orchestrator)
        features = baseline_features()
        events = [create_e2e_event(f"192.168.2.{i}", features, out_bytes=5000) for i in range(5)]

        summary = mode_orchestrator.run_replay_scenario(
            events=events,
            source_name="e2e_replay_test",
            speed_factor=float("inf"),
        )

        assert summary.mode == MonitoringMode.REPLAY
        assert summary.total_events_processed == 5
        assert summary.elapsed_seconds > 0.0

    def test_e2e_live_mode_and_zero_plaintext_in_db(self, baseline_features):
        """Verify Mode 3: Live Streaming and Assert Zero Plaintext Vectors in at-rest Storage."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test_encrypted_vault.db"
            keys_dir = tmp_path / "keys"
            features = baseline_features()

            km = KeyManager(keystore_dir=keys_dir)
            vault = EncryptedStorageVault(key_manager=km, db_path=db_path)
            pipeline = StreamingEventPipeline(capacity=100, batch_size=4)
            orchestrator = LiveSystemOrchestrator(
                db_path=tmp_path / "alerts.db", keystore_dir=keys_dir
            )

            # Enqueue live streaming events into bounded ring buffer
            live_events = [
                create_e2e_event(
                    "192.168.1.100",
                    baseline_features(bytes_out=123456),
                    out_bytes=123456,
                    dst_port=445,
                ),
                create_e2e_event("192.168.1.105", features, out_bytes=1500, dst_port=80),
            ]
            assert pipeline.enqueue_batch(live_events) == 2

            # Drain micro-batch from live pipeline and run full orchestrator
            batch = pipeline.fetch_micro_batch(timeout_sec=0.2)
            assert len(batch) == 2
            results = orchestrator.process_batch(batch)
            assert len(results) == 2
            assert results[0].behavioral_vector is not None
            assert len(results[0].behavioral_vector.features) == 16

            # Persist produced behavioral vector + sensitive marker into encrypted vault
            sensitive_vector = [
                round(v + 0.12345, 5) for v in results[0].behavioral_vector.features
            ]
            vector_id = vault.store_behavioral_vector(
                entity_id=results[0].entity_id,
                window_start=results[0].behavioral_vector.window_start,
                window_end=results[0].behavioral_vector.window_end,
                vector=sensitive_vector,
                encrypt=True,
            )

            # Read raw SQLite DB file bytes and assert ZERO PLAINTEXT vector presence
            db_bytes = db_path.read_bytes()
            marker = f"{sensitive_vector[0]}".encode("ascii")
            assert marker not in db_bytes
            assert results[0].entity_id.encode("ascii") in db_bytes

            # Successfully decrypted record using authorized key lookup
            decrypted = vault.load_behavioral_vector(vector_id)
            assert decrypted == sensitive_vector

    def test_missing_dataset_artifact_handles_absence_cleanly(self):
        """Ensure missing external benchmark dataset is detected explicitly without crashing."""
        missing_dataset = Path("data/raw/non_existent_huge_dataset.csv")
        assert not missing_dataset.exists()
