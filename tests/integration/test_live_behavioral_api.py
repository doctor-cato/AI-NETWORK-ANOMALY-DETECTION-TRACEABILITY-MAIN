"""Integration tests for FastAPI /api/v1/live/* and /api/v1/behavioral/* endpoints."""

from __future__ import annotations

import socket
import struct
import time

from fastapi.testclient import TestClient

from network_anomaly.api.main import create_app
from network_anomaly.behavioral.vector import BehavioralVectorBuilder
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.telemetry.collector import LAB_ENTERPRISE_FIELD_BASE


def _build_v9_packet(features_list, src_ip: str = "192.0.2.10", template_id: int = 256) -> bytes:
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
            socket.inet_aton(src_ip)
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


def test_live_and_behavioral_api_end_to_end(tmp_path, monkeypatch, baseline_features):
    monkeypatch.setenv("NETWORK_ANOMALY_API_TOKEN", "live-api-test-token")
    headers = {"X-Sentinel-Session-Token": "live-api-test-token"}
    app = create_app(db_path=tmp_path / "live_api.db")

    with TestClient(app) as client:
        # 1. Before start: STOPPED / DISCONNECTED, no fake live data
        st0 = client.get("/api/v1/live/status", headers=headers)
        assert st0.status_code == 200
        assert st0.json()["mode"] == "STOPPED"
        assert st0.json()["running"] is False
        assert st0.json()["data_status"] == "DISCONNECTED"

        # Behavioral list is EMPTY when nothing has been processed yet
        b_empty = client.get("/api/v1/behavioral/vectors", headers=headers)
        assert b_empty.status_code == 200
        assert b_empty.json()["data_status"] == "EMPTY"
        assert b_empty.json()["total"] == 0

        # 2. Start live UDP collector
        start_resp = client.post(
            "/api/v1/live/start",
            headers=headers,
            json={"host": "127.0.0.1", "port": 0, "demo_heuristics": False, "batch_size": 2},
        )
        assert start_resp.status_code == 200
        start_data = start_resp.json()
        assert start_data["mode"] == "LIVE"
        assert start_data["running"] is True
        bound_port = start_data["bound_port"]
        assert isinstance(bound_port, int) and bound_port > 0

        # 3. Send real NetFlow v9 UDP packets from two entities
        f1 = baseline_features()
        f2 = baseline_features(bytes_out=180_000.0, bytes_in=4_000.0)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(_build_v9_packet([f1], src_ip="192.0.2.10"), ("127.0.0.1", bound_port))
            sock.sendto(_build_v9_packet([f2], src_ip="192.0.2.11"), ("127.0.0.1", bound_port))
        finally:
            sock.close()

        deadline = time.monotonic() + 15.0
        live_status = {}
        while time.monotonic() < deadline:
            r = client.get("/api/v1/live/status", headers=headers)
            live_status = r.json()
            if live_status.get("metrics", {}).get("events_processed", 0) >= 2:
                break
            time.sleep(0.05)

        assert live_status["metrics"]["events_processed"] >= 2
        assert live_status["data_status"] == "CONNECTED"
        assert live_status["collector"]["flows_decoded"] >= 2

        results_resp = client.get("/api/v1/live/results?limit=10", headers=headers)
        assert results_resp.status_code == 200
        results_json = results_resp.json()
        assert results_json["total"] >= 2
        assert all(item["feature_status"] == "MODEL_READY" for item in results_json["items"])

        graph_resp = client.get("/api/v1/live/graph", headers=headers)
        assert graph_resp.status_code == 200
        assert graph_resp.json()["node_count"] >= 2

        # 4. Behavioral vectors persisted encrypted at rest, decrypted on detail query
        vec_list = client.get("/api/v1/behavioral/vectors", headers=headers)
        assert vec_list.status_code == 200
        vec_data = vec_list.json()
        assert vec_data["data_status"] == "CONNECTED"
        assert vec_data["total"] >= 2
        vec_id_a = vec_data["items"][0]["vector_id"]
        vec_id_b = vec_data["items"][1]["vector_id"]

        detail = client.get(f"/api/v1/behavioral/vectors/{vec_id_a}", headers=headers)
        assert detail.status_code == 200
        detail_json = detail.json()
        assert detail_json["dimensions"] == 16
        assert len(detail_json["features"]) == 16
        assert detail_json["feature_names"] == list(BehavioralVectorBuilder.FEATURE_NAMES)
        assert detail_json["is_encrypted_at_rest"] is True

        sim = client.get(
            f"/api/v1/behavioral/similarity?vector_a_id={vec_id_a}&vector_b_id={vec_id_b}",
            headers=headers,
        )
        assert sim.status_code == 200
        sim_json = sim.json()
        assert sim_json["comparable"] is True
        assert sim_json["cosine_similarity"] is not None
        assert sim_json["euclidean_distance"] is not None
        assert sim_json["manhattan_distance"] is not None

        corr = client.get("/api/v1/behavioral/correlate?match_threshold=0.75", headers=headers)
        assert corr.status_code == 200
        corr_json = corr.json()
        assert corr_json["data_status"] == "CONNECTED"
        assert corr_json["total_vectors_evaluated"] >= 2
        assert len(corr_json["clusters"]) >= 1

        # 5. Trace timeline and crypto status reflect live data without secret leakage
        tl = client.get("/api/v1/trace/timeline", headers=headers)
        assert tl.status_code == 200
        assert tl.json()["data_status"] == "CONNECTED"
        assert tl.json()["total_stages"] >= 1

        crypto = client.get("/api/v1/crypto/status?domain=general", headers=headers)
        assert crypto.status_code == 200
        crypto_json = crypto.json()
        assert crypto_json["data_status"] == "CONNECTED"
        assert "master_key_protection" in crypto_json["storage_protection_status"]
        assert "raw_key" not in str(crypto_json).lower()

        # 6. Stop live service cleanly
        stop_resp = client.post("/api/v1/live/stop", headers=headers)
        assert stop_resp.status_code == 200
        assert stop_resp.json()["mode"] == "STOPPED"
        assert stop_resp.json()["running"] is False
