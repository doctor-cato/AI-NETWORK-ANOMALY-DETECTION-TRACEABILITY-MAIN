"""Integration tests for v1.0.0 -> v2.0.0 database migration (Issue #80)."""

import sqlite3
from pathlib import Path

from network_anomaly.api.db import SCHEMA_SQL
from scripts.migrate_v1_to_v2 import migrate_database


def test_v1_to_v2_migration_lifecycle(tmp_path: Path):
    db_path = tmp_path / "sentinel_test.db"

    # 1. Initialize v1.0.0 Schema and insert sample rows
    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA_SQL)
    with conn:
        conn.execute(
            "INSERT INTO events (event_id, timestamp, source_ip, dest_ip, features, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?);",
            ("evt-1", "2026-11-16T10:00:00Z", "1.1.1.1", "2.2.2.2", "{}", "2026-11-16T10:00:00Z"),
        )
        conn.execute(
            "INSERT INTO incidents (incident_id, title, severity, anomaly_score, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?);",
            (
                "inc-1",
                "DDoS Detected",
                "HIGH",
                0.95,
                "2026-11-16T10:00:00Z",
                "2026-11-16T10:00:00Z",
            ),
        )
        conn.execute(
            "INSERT INTO key_metadata (key_id, algorithm, version, status, created_at) "
            "VALUES (?, ?, ?, ?, ?);",
            ("k-v1-001", "AES-256-GCM", 1, "ACTIVE", "2026-11-16T10:00:00Z"),
        )
    conn.close()

    # 2. Test Dry-Run: should not create v2 tables
    res_dry = migrate_database(db_path, dry_run=True, create_backup=False)
    assert res_dry is True

    conn = sqlite3.connect(str(db_path))
    tables = [
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
    ]
    conn.close()
    assert "schema_version" not in tables
    assert "unified_security_events" not in tables

    # 3. Test Actual Migration
    res_mig = migrate_database(db_path, dry_run=False, create_backup=True)
    assert res_mig is True

    # Verify backup exists
    backups = list(tmp_path.glob("*_backup_*.db"))
    assert len(backups) == 1

    # Verify v2 tables exist and integrity is ok
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute("PRAGMA integrity_check;")
    assert cursor.fetchone()[0] == "ok"

    tables = [
        r[0]
        for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
    ]
    assert "schema_version" in tables
    assert "unified_security_events" in tables
    assert "behavioral_vectors" in tables
    assert "encrypted_vault" in tables

    # Verify existing v1.0.0 rows remain completely intact
    cursor.execute("SELECT event_id, source_ip FROM events WHERE event_id = 'evt-1';")
    row = cursor.fetchone()
    assert row == ("evt-1", "1.1.1.1")

    cursor.execute("SELECT incident_id, severity FROM incidents WHERE incident_id = 'inc-1';")
    assert cursor.fetchone() == ("inc-1", "HIGH")

    cursor.execute("SELECT key_id FROM key_metadata WHERE key_id = 'k-v1-001';")
    assert cursor.fetchone() == ("k-v1-001",)

    # Verify schema_version table
    cursor.execute("SELECT version FROM schema_version;")
    assert cursor.fetchone() == ("2.0.0",)
    conn.close()

    # 4. Test Idempotency: running migration again succeeds with no errors
    res_again = migrate_database(db_path, dry_run=False, create_backup=False)
    assert res_again is True
