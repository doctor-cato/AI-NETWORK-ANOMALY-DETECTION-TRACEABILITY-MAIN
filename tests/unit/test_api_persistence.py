"""Unit tests for SQLite persistence, transactions, restart durability, and repositories."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("pydantic")

from network_anomaly.api.db import DatabaseManager
from network_anomaly.api.repositories import (
    EventRepository,
    IdempotencyRepository,
    IncidentRepository,
    KeyMetadataRepository,
    RotationAuditRepository,
)


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    """Provide a temporary file path for SQLite database."""
    return tmp_path / "test_persistence.db"


def test_database_manager_initialization_and_health(temp_db_path: Path):
    """Verify DatabaseManager creates tables and responds healthy."""
    db = DatabaseManager(temp_db_path)
    assert db.is_healthy() is True
    assert temp_db_path.is_file()
    db.close()


def test_transaction_commit_and_atomicity(temp_db_path: Path):
    """Verify successful transaction commits changes atomically."""
    db = DatabaseManager(temp_db_path)

    with db.transaction() as conn:
        event_id = EventRepository.insert(
            conn,
            {
                "event_id": "evt_tx_001",
                "timestamp": "2026-10-20T10:00:00Z",
                "source_ip": "192.168.1.10",
                "dest_ip": "10.0.0.1",
                "features": {"IN_BYTES": 1200},
            },
        )
        assert event_id == "evt_tx_001"

    # Query in a new transaction to confirm commit
    with db.transaction() as conn:
        fetched = EventRepository.get_by_id(conn, "evt_tx_001")
        assert fetched is not None
        assert fetched["source_ip"] == "192.168.1.10"
        assert fetched["features"]["IN_BYTES"] == 1200

    db.close()


def test_transaction_rollback_on_error(temp_db_path: Path):
    """Verify failed transaction rolls back completely with zero partial writes."""
    db = DatabaseManager(temp_db_path)

    with pytest.raises(RuntimeError):
        with db.transaction() as conn:
            EventRepository.insert(
                conn,
                {
                    "event_id": "evt_rollback_001",
                    "timestamp": "2026-10-20T10:00:00Z",
                    "features": {"IN_BYTES": 500},
                },
            )
            # Simulate unexpected failure
            raise RuntimeError("Forced transaction failure")

    # Verify evt_rollback_001 was rolled back
    with db.transaction() as conn:
        fetched = EventRepository.get_by_id(conn, "evt_rollback_001")
        assert fetched is None

    db.close()


def test_restart_durability(temp_db_path: Path):
    """Verify database persistence persists across process/connection restarts."""
    # Phase 1: Write data and close database
    db1 = DatabaseManager(temp_db_path)
    with db1.transaction() as conn:
        EventRepository.insert(
            conn,
            {
                "event_id": "evt_restart_test",
                "timestamp": "2026-10-20T12:00:00Z",
                "features": {"PROTOCOL": 6},
            },
        )
        IncidentRepository.create(
            conn,
            {
                "incident_id": "inc_restart_test",
                "title": "Persistent Alert",
                "severity": "HIGH",
                "anomaly_score": 0.95,
            },
        )
        KeyMetadataRepository.create_key(
            conn,
            {
                "key_id": "key_restart_test",
                "algorithm": "AES-256-GCM",
                "version": 4,
            },
        )
    db1.close()

    # Phase 2: Reopen with new DatabaseManager instance (simulating server restart)
    db2 = DatabaseManager(temp_db_path)
    with db2.transaction() as conn:
        evt = EventRepository.get_by_id(conn, "evt_restart_test")
        inc = IncidentRepository.get_by_id(conn, "inc_restart_test")
        key = KeyMetadataRepository.get_key(conn, "key_restart_test")

        assert evt is not None
        assert evt["features"]["PROTOCOL"] == 6

        assert inc is not None
        assert inc["title"] == "Persistent Alert"
        assert inc["severity"] == "HIGH"

        assert key is not None
        assert key["version"] == 4
        assert key["status"] == "ACTIVE"

    db2.close()


def test_idempotency_repository(temp_db_path: Path):
    """Verify IdempotencyRepository accurately caches and retrieves responses."""
    db = DatabaseManager(temp_db_path)
    with db.transaction() as conn:
        cached = IdempotencyRepository.get_record(conn, "idem_key_1", "/api/v1/ingest")
        assert cached is None

        IdempotencyRepository.save_record(
            conn,
            idempotency_key="idem_key_1",
            endpoint="/api/v1/ingest",
            status_code=200,
            response_body={"status": "ok", "ingested_count": 5},
        )

    with db.transaction() as conn:
        cached = IdempotencyRepository.get_record(conn, "idem_key_1", "/api/v1/ingest")
        assert cached is not None
        assert cached["status_code"] == 200
        assert cached["response_body"]["ingested_count"] == 5

    db.close()


def test_key_rotation_audit_repository(temp_db_path: Path):
    """Verify RotationAuditRepository records rotation log with pagination."""
    db = DatabaseManager(temp_db_path)
    with db.transaction() as conn:
        for i in range(15):
            RotationAuditRepository.log_rotation(
                conn,
                {
                    "rotation_id": f"rot_{i:03d}",
                    "triggered_by": "test_suite",
                    "old_key_id": f"key_v{i}",
                    "new_key_id": f"key_v{i + 1}",
                    "dry_run": True,
                    "status": "SUCCESS",
                },
            )

        total = RotationAuditRepository.count(conn)
        assert total == 15

        page1 = RotationAuditRepository.list_rotations(conn, limit=10, offset=0)
        assert len(page1) == 10

        page2 = RotationAuditRepository.list_rotations(conn, limit=10, offset=10)
        assert len(page2) == 5

    db.close()
