"""Contract and API security tests for Trace & Crypto endpoints (Issue #115)."""

import pytest
from fastapi.testclient import TestClient

from network_anomaly.api.main import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test_api.db"
    # Set session token in env for loopback auth via monkeypatch so it cleans up
    monkeypatch.setenv("NETWORK_ANOMALY_API_TOKEN", "test-session-secret-token-12345")
    app = create_app(db_path=db_path)
    return TestClient(app)


def test_auth_guard_fail_closed(client):
    """Requests without X-Sentinel-Session-Token must be rejected with 401."""
    resp = client.get("/api/v1/trace/timeline")
    assert resp.status_code == 401

    resp_bad = client.get(
        "/api/v1/trace/timeline", headers={"X-Sentinel-Session-Token": "wrong-token"}
    )
    assert resp_bad.status_code == 401


def test_get_attack_timeline_endpoint(client):
    headers = {"X-Sentinel-Session-Token": "test-session-secret-token-12345"}
    # Empty database must report EMPTY rather than fabricating seed events
    empty_resp = client.get("/api/v1/trace/timeline?campaign_name=Test-Campaign", headers=headers)
    assert empty_resp.status_code == 200
    empty_data = empty_resp.json()
    assert empty_data["data_status"] == "EMPTY"
    assert empty_data["total_stages"] == 0
    assert empty_data["stages"] == []

    # Ingest real events and create a real incident, then verify timeline reconstruction
    ingest = client.post(
        "/api/v1/ingest",
        headers=headers,
        json={
            "session_id": "sess-trace-1",
            "events": [
                {
                    "event_id": "ev-trace-1",
                    "timestamp": "2026-11-17T10:00:00Z",
                    "source_ip": "198.51.100.10",
                    "dest_ip": "10.0.0.5",
                    "source_port": 51234,
                    "dest_port": 443,
                    "protocol": "TCP",
                    "features": {"IN_BYTES": 1200},
                }
            ],
        },
    )
    assert ingest.status_code == 200
    inc = client.post(
        "/api/v1/incidents",
        headers=headers,
        json={
            "title": "Reconnaissance probe",
            "severity": "HIGH",
            "anomaly_score": 0.91,
            "attack_type": "Reconnaissance",
            "event_id": "ev-trace-1",
            "session_id": "sess-trace-1",
        },
    )
    assert inc.status_code == 201
    inc_id = inc.json()["incident_id"]

    resp = client.get(f"/api/v1/trace/timeline?campaign_name={inc_id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["campaign_name"] == inc_id
    assert data["data_status"] == "CONNECTED"
    assert len(data["stages"]) >= 1
    assert inc_id in data["available_campaigns"]


def test_get_entity_graph_endpoint(client):
    headers = {"X-Sentinel-Session-Token": "test-session-secret-token-12345"}
    empty_resp = client.get("/api/v1/trace/graph?entity_id=10.0.0.5&depth=2", headers=headers)
    assert empty_resp.status_code == 200
    assert empty_resp.json()["data_status"] == "EMPTY"
    assert empty_resp.json()["node_count"] == 0

    ingest = client.post(
        "/api/v1/ingest",
        headers=headers,
        json={
            "events": [
                {
                    "event_id": "ev-graph-1",
                    "timestamp": "2026-11-17T10:05:00Z",
                    "source_ip": "198.51.100.25",
                    "dest_ip": "10.0.0.5",
                    "source_port": 41000,
                    "dest_port": 443,
                    "protocol": "TCP",
                    "features": {"IN_BYTES": 800},
                }
            ]
        },
    )
    assert ingest.status_code == 200

    resp = client.get("/api/v1/trace/graph?entity_id=10.0.0.5&depth=2", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["data_status"] == "CONNECTED"
    assert data["node_count"] >= 2
    assert data["edge_count"] >= 1
    assert any(n["node_id"] == "10.0.0.5" for n in data["nodes"])


def test_generate_investigation_report_endpoint(client):
    headers = {"X-Sentinel-Session-Token": "test-session-secret-token-12345"}
    payload = {
        "incident_id": "INC-TEST-001",
        "title": "Brute Force and Lateral Movement",
        "severity": "CRITICAL",
        "root_cause_summary": "Exposed SSH service brute-forced by external actor.",
        "events": [
            {
                "timestamp": "2026-11-17T11:00:00Z",
                "source_ip": "198.51.100.2",
                "dest_ip": "10.0.0.2",
                "attack_type": "Exploits",
                "dest_port": 22,
                "confidence": 0.99,
            }
        ],
        "evidence_records": [
            {
                "evidence_id": "ev-01",
                "source_file": "auth.log",
                "line": 102,
                "sha256": "1234567890abcdef",
            }
        ],
    }
    resp = client.post("/api/v1/trace/investigation/generate", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["incident_id"] == "INC-TEST-001"
    assert data["artifact_hash"] != ""
    assert "# Incident Investigation Report" in data["markdown_content"]


def test_get_crypto_status_endpoint(client):
    headers = {"X-Sentinel-Session-Token": "test-session-secret-token-12345"}
    resp = client.get("/api/v1/crypto/status?domain=general", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "active_key_id" in data
    assert data["algorithm"] == "AES-256-GCM"
    assert data["rotation_interval_minutes"] == 30.0
    assert data["adaptive_risk_threshold"] == 85.0
    assert data["data_status"] == "CONNECTED"
    assert "master_key_protection" in data["storage_protection_status"]
