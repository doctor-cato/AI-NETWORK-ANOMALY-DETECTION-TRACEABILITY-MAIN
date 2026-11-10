"""Unit tests for schema validation, sanitized error handling, and zero secret leakage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from network_anomaly.api.main import create_app


@pytest.fixture
def client(tmp_path: Path):
    """Provide TestClient with temporary SQLite database."""
    db_file = tmp_path / "security_test.db"
    app = create_app(db_path=db_file)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def test_schema_validation_rejects_out_of_range_ports(client: TestClient):
    """Verify ports exceeding 65535 or negative ports are rejected with 422."""
    payload = {
        "events": [
            {
                "source_port": 70000,  # Invalid port
                "dest_port": 80,
                "features": {},
            }
        ]
    }
    res = client.post("/api/v1/ingest", json=payload)
    assert res.status_code == 422
    data = res.json()
    assert data["error"] == "ValidationError"
    assert "source_port" in data["detail"]


def test_schema_validation_rejects_invalid_incident_severity_and_score(client: TestClient):
    """Verify invalid severity level and out-of-range anomaly score are rejected with 422."""
    # Invalid severity
    res1 = client.post(
        "/api/v1/incidents",
        json={"title": "Test Alert", "severity": "EXTREME", "anomaly_score": 0.5},
    )
    assert res1.status_code == 422

    # Out of range score (> 1.0)
    res2 = client.post(
        "/api/v1/incidents",
        json={"title": "Test Alert", "severity": "HIGH", "anomaly_score": 1.5},
    )
    assert res2.status_code == 422


def test_error_handlers_do_not_leak_stack_traces_or_secrets(client: TestClient):
    """Verify 500 errors are sanitized and never expose Python tracebacks or secrets."""
    # Trigger an unhandled error inside an endpoint by patching service
    with patch.object(
        client.app.state.service,
        "check_health",
        side_effect=RuntimeError(
            "Secret DB token leaked: super_secret_pass_123 in /Users/private/app.py:42"
        ),
    ):
        res = client.get("/health")
        assert res.status_code == 500
        data = res.json()
        assert data["error"] == "InternalServerError"
        # Assert no traceback or secret is present
        assert "super_secret_pass_123" not in data["detail"]
        assert "traceback" not in data["detail"].lower()
        assert "file " not in data["detail"].lower()


def test_key_metadata_endpoints_never_expose_secrets(client: TestClient):
    """Verify cryptographic key endpoints contain only non-sensitive metadata."""
    res = client.get("/api/v1/keys")
    assert res.status_code == 200
    keys = res.json()
    assert len(keys) >= 1
    for k in keys:
        assert "secret" not in k
        assert "private_key" not in k
        assert "key_material" not in k
        assert "raw_bytes" not in k
        assert set(k.keys()) <= {
            "key_id",
            "algorithm",
            "version",
            "status",
            "created_at",
            "retired_at",
        }
