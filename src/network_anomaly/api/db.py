"""SQLite database manager and connection pool for network anomaly detection.

Provides atomic transactions, schema initialization, restart durability,
and fail-safe persistence for events, sessions, incidents, evidence,
key metadata, and rotation audit records.
"""

from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path
from typing import Generator, Optional, Union

from network_anomaly.config import PROJECT_ROOT

# Default persistent SQLite database path
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "network_anomaly.db"

# ponytail: SQLite is the zero-dependency CI and local persistence default.
# For high-throughput distributed deployments, a PostgreSQL adapter implementing
# the same repository interface can be plugged in without changing domain logic.


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    dest_ip TEXT,
    source_port INTEGER,
    dest_port INTEGER,
    protocol TEXT,
    features TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    start_time TEXT NOT NULL,
    end_time TEXT,
    source_ip TEXT,
    dest_ip TEXT,
    event_count INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    anomaly_score REAL NOT NULL,
    attack_type TEXT,
    description TEXT,
    event_id TEXT,
    session_id TEXT,
    evidence_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

CREATE TABLE IF NOT EXISTS evidences (
    evidence_id TEXT PRIMARY KEY,
    incident_id TEXT,
    artifact_name TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidences_incident_id ON evidences(incident_id);

CREATE TABLE IF NOT EXISTS key_metadata (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
    version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TEXT NOT NULL,
    retired_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_key_metadata_status ON key_metadata(status);

CREATE TABLE IF NOT EXISTS rotation_audit (
    rotation_id TEXT PRIMARY KEY,
    triggered_by TEXT NOT NULL,
    old_key_id TEXT,
    new_key_id TEXT NOT NULL,
    dry_run INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'SUCCESS',
    reason TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rotation_audit_created_at ON rotation_audit(created_at);

CREATE TABLE IF NOT EXISTS idempotency_records (
    idempotency_key TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_idempotency_endpoint ON idempotency_records(endpoint);
"""


class DatabaseManager:
    """Manages SQLite connections, transactions, and schema setup."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        """Initialize DatabaseManager with explicit or default SQLite file path.

        Parameters
        ----------
        db_path : str or Path, optional
            Path to SQLite database file. If ':memory:', creates in-memory database.
            Defaults to DEFAULT_DB_PATH.
        """
        if db_path is None:
            self.db_path: Union[str, Path] = DEFAULT_DB_PATH
        elif str(db_path) == ":memory:":
            self.db_path = ":memory:"
        else:
            self.db_path = Path(db_path)

        # For in-memory database, hold persistent connection so schema isn't discarded
        self._memory_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._memory_conn = self._create_connection()

        self.initialize_schema()

    def _create_connection(self) -> sqlite3.Connection:
        """Create and configure a new SQLite connection."""
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        else:
            conn = sqlite3.connect(":memory:", timeout=15.0)

        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        if self.db_path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    def get_connection(self) -> sqlite3.Connection:
        """Get an open connection."""
        if self.db_path == ":memory:" and self._memory_conn is not None:
            return self._memory_conn
        return self._create_connection()

    @contextlib.contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing an atomic database transaction.

        Commits on successful exit; rolls back on exception.
        """
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if self.db_path != ":memory:":
                conn.close()

    def initialize_schema(self) -> None:
        """Execute DDL statements to ensure all required tables and indices exist."""
        with self.transaction() as conn:
            conn.executescript(SCHEMA_SQL)

    def is_healthy(self) -> bool:
        """Check if SQLite database is accessible and responsive."""
        try:
            with self.transaction() as conn:
                row = conn.execute("SELECT 1 AS alive").fetchone()
                return bool(row and row["alive"] == 1)
        except Exception:
            return False

    def close(self) -> None:
        """Close persistent resources (if any)."""
        if self._memory_conn is not None:
            self._memory_conn.close()
            self._memory_conn = None
