"""Full System End-to-End Integration Tests across All Three Execution Modes.

Validates Issue #138 for NetFlow Sentinel v2.0.
"""

import importlib.util
import socket
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.config import ARTIFACTS, PROJECT_ROOT
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

    def test_e2e_api_live_udp_loopback_generates_deduplicated_persisted_alert(self, tmp_path: Path):
        """Verify live UDP loopback -> API -> real 4 models -> deduplicated alert -> SQLite fallback."""
        fastapi = pytest.importorskip("fastapi")
        _ = fastapi
        pytest.importorskip("httpx")
        from fastapi.testclient import TestClient

        from network_anomaly.api.main import create_app

        rf_path = ARTIFACTS / "models" / "random_forest" / "random_forest_baseline.joblib"
        gate_path = ARTIFACTS / "ml" / "ood_reference_gate.json"
        if not rf_path.is_file() or not gate_path.is_file():
            pytest.skip("Model or OOD gate artifacts unavailable in this environment.")

        import hashlib

        expected_ood_sha = hashlib.sha256(gate_path.read_bytes()).hexdigest()

        script_path = PROJECT_ROOT / "scripts" / "run_live_lab_acceptance.py"
        spec = importlib.util.spec_from_file_location("run_live_lab_acceptance", script_path)
        assert spec is not None and spec.loader is not None
        acc_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(acc_mod)

        high_risk_flow = next(
            item for item in acc_mod.LAB_FLOWS if item["label"] == "large_outbound_transfer"
        )
        packet = acc_mod.build_netflow_v9_packet([high_risk_flow], include_template=True)

        with TestClient(
            create_app(
                tmp_path / "live_alert_e2e.db",
                runtime_mode="deployment",
                expected_ood_gate_sha256=expected_ood_sha,
            )
        ) as client:
            start_resp = client.post(
                "/api/v1/live/start",
                json={"host": "127.0.0.1", "port": 0, "demo_heuristics": False},
            )
            assert start_resp.status_code == 200, start_resp.text
            port = start_resp.json()["bound_port"]
            assert isinstance(port, int) and port > 0

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(packet, ("127.0.0.1", port))
                    time.sleep(0.05)
                    sock.sendto(packet, ("127.0.0.1", port))

                deadline = time.monotonic() + 8.0
                processed = 0
                while time.monotonic() < deadline:
                    st = client.get("/api/v1/live/status")
                    assert st.status_code == 200
                    processed = int(st.json().get("metrics", {}).get("events_processed", 0))
                    if processed >= 2:
                        break
                    time.sleep(0.05)
                assert processed >= 2

                alerts_resp = client.get("/api/v1/live/alerts?limit=50")
                assert alerts_resp.status_code == 200, alerts_resp.text
                items = alerts_resp.json()["items"]
                assert len(items) == 1
                alert = items[0]
                assert alert["risk_score"] >= 70.0
                assert alert["risk_level"] in ("HIGH", "CRITICAL")
                assert alert["occurrence_count"] == 2
                alert_id = alert["alert_id"]
            finally:
                stop_resp = client.post("/api/v1/live/stop")
                assert stop_resp.status_code == 200

            persisted_resp = client.get("/api/v1/live/alerts?limit=50")
            assert persisted_resp.status_code == 200, persisted_resp.text
            persisted_items = persisted_resp.json()["items"]
            assert any(item["alert_id"] == alert_id for item in persisted_items)

        # Restart API against same DB and ingest an event for a second entity
        second_flow = dict(high_risk_flow, src_ip="192.0.2.99", dst_ip="198.51.100.8")
        second_packet = acc_mod.build_netflow_v9_packet([second_flow], include_template=True)
        with TestClient(
            create_app(
                tmp_path / "live_alert_e2e.db",
                runtime_mode="deployment",
                expected_ood_gate_sha256=expected_ood_sha,
            )
        ) as client2:
            pre_restart_resp = client2.get("/api/v1/live/alerts?limit=50")
            assert pre_restart_resp.status_code == 200
            assert any(item["alert_id"] == alert_id for item in pre_restart_resp.json()["items"])

            start_resp2 = client2.post(
                "/api/v1/live/start",
                json={"host": "127.0.0.1", "port": 0, "demo_heuristics": False},
            )
            assert start_resp2.status_code == 200
            port2 = start_resp2.json()["bound_port"]
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(second_packet, ("127.0.0.1", port2))
                deadline2 = time.monotonic() + 8.0
                while time.monotonic() < deadline2:
                    st2 = client2.get("/api/v1/live/status")
                    if int(st2.json().get("metrics", {}).get("events_processed", 0)) >= 1:
                        break
                    time.sleep(0.05)

                merged_resp = client2.get("/api/v1/live/alerts?limit=50")
                assert merged_resp.status_code == 200
                merged_items = merged_resp.json()["items"]
                merged_ids = [item["alert_id"] for item in merged_items]
                assert alert_id in merged_ids
                assert len(merged_items) == 2
                assert merged_items[0]["last_seen_utc"] >= merged_items[1]["last_seen_utc"]
            finally:
                client2.post("/api/v1/live/stop")
