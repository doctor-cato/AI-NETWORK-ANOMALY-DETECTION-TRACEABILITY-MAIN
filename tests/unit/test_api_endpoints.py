"""Unit tests for FastAPI REST endpoints and client SDK."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from network_anomaly.api.client import NetworkAnomalyApiClient
from network_anomaly.api.main import create_app


@pytest.fixture
def client(tmp_path: Path):
    """Provide TestClient with isolated SQLite database."""
    db_file = tmp_path / "endpoint_test.db"
    app = create_app(db_path=db_file)
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client: TestClient):
    """Verify /health and /api/v1/health endpoints."""
    res1 = client.get("/health")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["process_alive"] is True
    assert data1["db_ready"] is True
    assert "model_ready" in data1
    assert "version" in data1

    res2 = client.get("/api/v1/health")
    assert res2.status_code == 200
    assert res2.json()["version"] == data1["version"]


def test_ingest_endpoint_and_idempotency_header(client: TestClient):
    """Verify /api/v1/ingest with X-Idempotency-Key."""
    payload = {
        "events": [
            {
                "timestamp": "2026-10-20T10:15:00Z",
                "source_ip": "10.0.0.2",
                "dest_ip": "10.0.0.3",
                "source_port": 44321,
                "dest_port": 80,
                "protocol": "TCP",
                "features": {"IN_BYTES": 1500, "OUT_BYTES": 3000},
            }
        ],
        "session_id": "sess_api_test",
    }

    # 1. Ingest with idempotency key
    res = client.post(
        "/api/v1/ingest",
        json=payload,
        headers={"X-Idempotency-Key": "idem_hdr_123"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["ingested_count"] == 1
    assert len(body["event_ids"]) == 1

    # 2. Re-send with identical idempotency key
    res2 = client.post(
        "/api/v1/ingest",
        json=payload,
        headers={"X-Idempotency-Key": "idem_hdr_123"},
    )
    assert res2.status_code == 200
    body2 = res2.json()
    assert body2["event_ids"] == body["event_ids"]


def test_analyze_endpoint(client: TestClient):
    """Verify /api/v1/analyze processes batch and returns structured results."""
    payload = {
        "events": [
            {"features": {"IN_BYTES": 400, "OUT_BYTES": 400}},
            {"features": {"IN_BYTES": 5_000_000, "OUT_BYTES": 0}},
        ],
        "model_name": "random_forest",
        "threshold": 0.5,
        "create_incidents": True,
    }

    res = client.post("/api/v1/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 2
    assert len(data["results"]) == 2
    assert data["anomalies_detected"] >= 1
    assert data["results"][1]["is_anomaly"] is True
    assert data["results"][1]["incident_created"] is True


def test_incidents_crud_and_pagination(client: TestClient):
    """Verify incident creation, retrieval, patch update, and pagination."""
    # 1. Create incident
    create_payload = {
        "title": "Suspicious Port Scan",
        "severity": "HIGH",
        "anomaly_score": 0.88,
        "attack_type": "Reconnaissance",
        "description": "Sequential SYN scanning detected.",
    }
    res_post = client.post("/api/v1/incidents", json=create_payload)
    assert res_post.status_code == 201
    inc = res_post.json()
    inc_id = inc["incident_id"]
    assert inc["title"] == "Suspicious Port Scan"
    assert inc["status"] == "OPEN"

    # 2. Get incident by ID
    res_get = client.get(f"/api/v1/incidents/{inc_id}")
    assert res_get.status_code == 200
    assert res_get.json()["incident_id"] == inc_id

    # 3. Patch incident status to RESOLVED
    res_patch = client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"status": "RESOLVED", "description": "Remediated by analyst"},
    )
    assert res_patch.status_code == 200
    assert res_patch.json()["status"] == "RESOLVED"
    assert res_patch.json()["description"] == "Remediated by analyst"

    # 4. Query paginated incidents
    res_list = client.get("/api/v1/incidents?limit=10&offset=0")
    assert res_list.status_code == 200
    paginated = res_list.json()
    assert paginated["total"] >= 1
    assert len(paginated["items"]) >= 1
    assert paginated["has_more"] is False


def test_timeline_endpoint_pagination(client: TestClient):
    """Verify /api/v1/timeline returns paginated timeline entries."""
    res = client.get("/api/v1/timeline?limit=5&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert "has_more" in data


def test_key_rotation_and_keys_metadata_endpoints(client: TestClient):
    """Verify /api/v1/rotation, /api/v1/rotation/audit, and /api/v1/keys."""
    # 1. Trigger rotation
    rot_payload = {
        "triggered_by": "test_operator",
        "dry_run": True,
        "reason": "Integration test",
    }
    res_rot = client.post("/api/v1/rotation", json=rot_payload)
    assert res_rot.status_code == 200
    rot = res_rot.json()
    assert rot["status"] == "SUCCESS"
    assert rot["dry_run"] is True

    # 2. Query rotation audit log
    res_audit = client.get("/api/v1/rotation/audit?limit=10&offset=0")
    assert res_audit.status_code == 200
    audits = res_audit.json()
    assert audits["total"] >= 1

    # 3. List keys metadata
    res_keys = client.get("/api/v1/keys")
    assert res_keys.status_code == 200
    keys = res_keys.json()
    assert len(keys) >= 1
    # Verify no secret material is present
    for k in keys:
        assert "secret" not in k
        assert "key_material" not in k
        assert "raw_key" not in k
        assert "algorithm" in k
        assert "status" in k


def test_thin_client_sdk_integration(tmp_path: Path):
    """Verify NetworkAnomalyApiClient communicates with FastAPI service correctly."""
    db_file = tmp_path / "sdk_test.db"
    app = create_app(db_path=db_file)

    # Use TestClient as HTTP transport for SDK
    with TestClient(app) as test_client:
        client = NetworkAnomalyApiClient(client=test_client)

        health = client.get_health()
        assert health["process_alive"] is True

        ingest_res = client.ingest_events(
            events=[{"features": {"IN_BYTES": 1200}}],
            session_id="sdk_session_1",
        )
        assert ingest_res["ingested_count"] == 1

        analysis = client.analyze(
            events=[{"features": {"IN_BYTES": 500}}],
            threshold=0.5,
        )
        assert analysis["count"] == 1

        incidents = client.list_incidents(limit=5)
        assert "items" in incidents

        timeline = client.get_timeline(limit=5)
        assert "items" in timeline

        keys = client.list_keys()
        assert len(keys) >= 1
