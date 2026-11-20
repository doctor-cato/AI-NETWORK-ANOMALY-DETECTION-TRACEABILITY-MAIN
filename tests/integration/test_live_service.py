"""Integration test for the live telemetry service (UDP → pipeline → orchestrator)."""

from __future__ import annotations

import socket
import struct

from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.streaming.live_service import LiveTelemetryService
from network_anomaly.telemetry.collector import LAB_ENTERPRISE_FIELD_BASE


def _build_v9_packet(features_list, template_id=256):
    standard = [
        (8, 4),
        (12, 4),
        (7, 2),
        (11, 2),
        (4, 1),
        (1, 4),
        (23, 4),
        (2, 4),
        (24, 4),
        (6, 1),
        (22, 4),
        (21, 4),
    ]
    lab = [(LAB_ENTERPRISE_FIELD_BASE + i, 8) for i in range(len(ML_FEATURE_COLUMNS))]
    fields = standard + lab

    template = struct.pack("!HH", template_id, len(fields))
    for ftype, flen in fields:
        template += struct.pack("!HH", ftype, flen)
    payload = struct.pack("!HH", 0, 4 + len(template)) + template

    records = bytearray()
    for index, features in enumerate(features_list):
        start = 1_000_000 - 1000 - index
        records += (
            socket.inet_aton("192.0.2.10")
            + socket.inet_aton("192.0.2.20")
            + struct.pack(
                "!HHBIIIIBII",
                45000 + index,
                443,
                int(features["protocol_num"]),
                int(features["bytes_in"]),
                int(features["bytes_out"]),
                int(features["pkts_in"]),
                int(features["pkts_out"]),
                24,
                start,
                start + 34,
            )
        )
        records += b"".join(struct.pack("!d", features[name]) for name in ML_FEATURE_COLUMNS)
    payload += struct.pack("!HH", template_id, 4 + len(records)) + bytes(records)
    return struct.pack("!HHIIII", 9, 1, 1_000_000, 1_700_000_000, 1, 1) + bytes(payload)


class TestLiveTelemetryService:
    def test_udp_packet_reaches_orchestrator_with_real_contract(self, tmp_path, baseline_features):
        service = LiveTelemetryService(
            host="127.0.0.1",
            port=0,
            db_path=tmp_path / "live.db",
            keystore_dir=tmp_path / "keys",
            batch_size=4,
            queue_capacity=64,
        )
        service.start()
        try:
            assert service.is_running is True
            status = service.status()
            assert status["mode"] == "LIVE"
            assert status["bound_port"] == service.bound_port

            features_a = baseline_features()
            features_b = baseline_features(bytes_out=150_000.0, bytes_in=5000.0)
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sender.sendto(
                    _build_v9_packet([features_a, features_b]),
                    ("127.0.0.1", service.bound_port),
                )
            finally:
                sender.close()

            assert service.wait_until_processed(2, timeout_s=20.0) == 2
            results = service.recent_results()
            assert len(results) == 2
            for result in results:
                assert result["feature_status"] == "MODEL_READY"
                assert result["is_ml_flow"] is True
                assert result["inference"]["inference_mode"] in {
                    "REAL_MODELS",
                    "UNAVAILABLE",
                }
                assert result["behavioral_vector_encrypted"] is True
                assert result["provenance"]["source_id"].startswith("collector:netflow-v9:")
            assert results[1]["risk_score"] > results[0]["risk_score"]

            final = service.stop()
            assert final["mode"] == "STOPPED"
            assert final["collector"]["datagrams_received"] == 1
            assert final["pipeline"]["total_processed"] == 2
            assert final["metrics"]["events_processed"] == 2
        finally:
            service.stop()

    def test_service_reports_stopped_before_start(self, tmp_path):
        service = LiveTelemetryService(
            host="127.0.0.1",
            port=0,
            db_path=tmp_path / "live.db",
            keystore_dir=tmp_path / "keys",
        )
        status = service.status()
        assert status["mode"] == "STOPPED"
        assert status["running"] is False
        assert status["inference"]["inference_mode"] in {"REAL_MODELS", "UNAVAILABLE"}
