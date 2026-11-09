"""Unit tests for ApiService business logic, health check behavior, and lifecycle management."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from network_anomaly.api.db import DatabaseManager
from network_anomaly.api.service import ApiService


@pytest.fixture
def api_service(tmp_path: Path) -> ApiService:
    """Fixture providing ApiService backed by an isolated SQLite database."""
    db_path = tmp_path / "test_service.db"
    db = DatabaseManager(db_path)
    return ApiService(db)


def test_health_check_fails_safe_when_artifacts_absent(api_service: ApiService):
    """Verify health check never claims model/data ready when artifacts are missing."""
    with patch("network_anomaly.api.service.ARTIFACTS", Path("/non_existent_artifacts_dir")):
        health = api_service.check_health()
        assert health.process_alive is True
        assert health.db_ready is True
        # CRITICAL ACCEPTANCE CRITERIA:
        assert health.model_ready is False
        assert health.preprocessor_ready is False
        assert health.status == "degraded"


def test_health_check_reports_healthy_when_artifacts_present(
    api_service: ApiService, tmp_path: Path
):
    """Verify health check reports healthy when artifacts exist."""
    fake_artifacts = tmp_path / "fake_artifacts"
    (fake_artifacts / "models" / "random_forest").mkdir(parents=True)
    (fake_artifacts / "preprocessing").mkdir(parents=True)

    fake_model = fake_artifacts / "models" / "random_forest" / "random_forest_baseline.joblib"
    fake_model.write_text("model placeholder")

    fake_prep = fake_artifacts / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
    fake_prep.write_text("preprocessor placeholder")

    with patch("network_anomaly.api.service.ARTIFACTS", fake_artifacts):
        health = api_service.check_health()
        assert health.process_alive is True
        assert health.model_ready is True
        assert health.preprocessor_ready is True
        assert health.status == "healthy"


def test_ingest_events_atomicity_and_idempotency(api_service: ApiService):
    """Verify event ingestion persists records and deduplicates with idempotency key."""
    events = [
        {
            "timestamp": "2026-10-20T10:00:00Z",
            "source_ip": "192.168.1.50",
            "dest_ip": "10.0.0.5",
            "features": {"IN_BYTES": 4096, "OUT_BYTES": 8192},
        },
        {
            "timestamp": "2026-10-20T10:00:01Z",
            "source_ip": "192.168.1.51",
            "dest_ip": "10.0.0.5",
            "features": {"IN_BYTES": 512, "OUT_BYTES": 256},
        },
    ]

    # First ingest
    count, ids, sess = api_service.ingest_events(
        events, session_id="sess_batch_1", idempotency_key="idempotent_ingest_1"
    )
    assert count == 2
    assert len(ids) == 2
    assert sess == "sess_batch_1"

    # Second ingest with same idempotency key must return cached result
    # without inserting duplicate rows
    count2, ids2, sess2 = api_service.ingest_events(
        events, session_id="sess_batch_1", idempotency_key="idempotent_ingest_1"
    )
    assert count2 == 2
    assert ids2 == ids

    # Check total events in database is strictly 2
    with api_service.db.transaction() as conn:
        from network_anomaly.api.repositories import EventRepository

        assert EventRepository.count(conn) == 2


def test_analyze_flows_with_heuristic_and_incident_creation(api_service: ApiService):
    """Verify analysis creates incident alert and evidence when threshold is met."""
    flows = [
        # Normal flow
        {"features": {"IN_BYTES": 500, "OUT_BYTES": 500, "IN_PKTS": 5, "OUT_PKTS": 5}},
        # Abnormal high-volume flooding flow
        {"features": {"IN_BYTES": 2_500_000, "OUT_BYTES": 100, "IN_PKTS": 2500, "OUT_PKTS": 0}},
    ]

    res = api_service.analyze_flows(flows, threshold=0.5, create_incidents=True)
    assert res.count == 2
    assert res.anomalies_detected == 1
    assert res.results[0].is_anomaly is False
    assert res.results[1].is_anomaly is True
    assert res.results[1].incident_created is True
    assert res.results[1].incident_id is not None

    # Check that incident is stored in repository
    incidents = api_service.list_incidents(limit=10)
    assert incidents.total == 1
    assert incidents.items[0].incident_id == res.results[1].incident_id


def test_key_rotation_lifecycle_cooldown_and_idempotency(api_service: ApiService):
    """Verify key rotation enforces cooldown and records audit log."""
    # Rotation 1: Successful
    rot1 = api_service.rotate_key(
        triggered_by="operator_alice",
        dry_run=True,
        reason="Scheduled test rotation",
        idempotency_key="rot_key_alpha",
    )
    assert rot1.status == "SUCCESS"
    assert rot1.dry_run is True
    assert rot1.new_key_id is not None

    # Immediate Rotation 2 (different key): rejected by cooldown
    with pytest.raises(ValueError, match="minimum cooldown interval"):
        api_service.rotate_key(triggered_by="operator_bob", dry_run=True)

    # Calling again with same idempotency key: succeeds by returning cached result
    rot_cached = api_service.rotate_key(
        triggered_by="operator_alice",
        dry_run=True,
        reason="Scheduled test rotation",
        idempotency_key="rot_key_alpha",
    )
    assert rot_cached.rotation_id == rot1.rotation_id
    assert rot_cached.new_key_id == rot1.new_key_id

    # Verify audit log recorded both SUCCESS and BLOCKED_COOLDOWN
    audits = api_service.list_rotation_audits(limit=10)
    assert audits.total >= 2


def test_timeline_chronological_ordering(api_service: ApiService):
    """Verify timeline aggregates and orders events chronologically descending."""
    # 1. Ingest event
    api_service.ingest_events(
        [{"timestamp": "2026-10-20T08:00:00Z", "features": {"IN_BYTES": 100}}],
        session_id="sess_time_1",
    )
    # 2. Add incident
    with api_service.db.transaction() as conn:
        from network_anomaly.api.repositories import IncidentRepository

        IncidentRepository.create(
            conn,
            {
                "incident_id": "inc_timeline_1",
                "title": "Alert at 09:00",
                "severity": "HIGH",
                "anomaly_score": 0.9,
                "created_at": "2026-10-20T09:00:00Z",
            },
        )

    timeline = api_service.get_timeline(limit=10)
    assert timeline.total >= 2
    # Verify descending ordering
    timestamps = [item.timestamp for item in timeline.items]
    assert timestamps == sorted(timestamps, reverse=True)
