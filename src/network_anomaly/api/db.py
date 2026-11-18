"""SQLite database manager and connection pool for network anomaly detection.

Provides atomic transactions, schema initialization, restart durability,
and fail-safe persistence for events, sessions, incidents, evidence,
key metadata, and rotation audit records (Audit Trail Metadata only;
external KMS integration is required for active payload encryption).
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union

from network_anomaly.config import resolve_default_db_path

# Default persistent SQLite database path
DEFAULT_DB_PATH = resolve_default_db_path()

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

-- Audit Trail Metadata: records key identifier and lifecycle status for audit logging.
-- Does not claim end-to-end AES-256-GCM payload encryption until KMS is integrated.
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

-- C8 / Issue #27: Adaptive security response simulation / dry-run audit history.
-- Stores policy recommendations and simulated key rotation decisions only; never executes OS commands.
CREATE TABLE IF NOT EXISTS security_response_simulations (
    simulation_id TEXT PRIMARY KEY,
    analysis_id TEXT,
    source_csv_path TEXT,
    source_csv_sha256 TEXT,
    model_key TEXT NOT NULL,
    model_type TEXT NOT NULL,
    run_id TEXT,
    triggered_by TEXT NOT NULL,
    execution_mode TEXT NOT NULL DEFAULT 'DRY_RUN_SIMULATION',
    action_status TEXT NOT NULL DEFAULT 'SIMULATED',
    recommendation_status TEXT NOT NULL DEFAULT 'RECOMMENDED',
    executed INTEGER NOT NULL DEFAULT 0,
    overall_recommendation TEXT NOT NULL,
    overall_severity TEXT NOT NULL,
    total_flows INTEGER NOT NULL DEFAULT 0,
    evaluated_flows INTEGER NOT NULL DEFAULT 0,
    ood_abstained_flows INTEGER NOT NULL DEFAULT 0,
    provenance_verification TEXT NOT NULL,
    action_counts_json TEXT NOT NULL,
    key_rotation_json TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    recommendations_json TEXT NOT NULL,
    policy_summary TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sec_sim_created_at
    ON security_response_simulations(created_at);
CREATE INDEX IF NOT EXISTS idx_sec_sim_analysis_id
    ON security_response_simulations(analysis_id);
"""

# NetFlow Sentinel v2.0 extension tables applied automatically by DatabaseManager
# and kept separate from SCHEMA_SQL so v1 -> v2 migration tests can verify upgrade from v1.0.0.
V2_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS unified_security_events (
    event_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL DEFAULT '2.0.0',
    event_timestamp TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    source_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    source_ip TEXT,
    dest_ip TEXT,
    source_port INTEGER,
    dest_port INTEGER,
    protocol TEXT,
    is_ml_complete INTEGER NOT NULL DEFAULT 0,
    validation_status TEXT NOT NULL DEFAULT 'VALID',
    raw_provenance TEXT NOT NULL DEFAULT '{}',
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_use_ts ON unified_security_events(event_timestamp);
CREATE INDEX IF NOT EXISTS idx_use_entity ON unified_security_events(entity_id);

CREATE TABLE IF NOT EXISTS behavioral_vectors (
    vector_id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    vector_version TEXT NOT NULL DEFAULT '2.0',
    dimensions INTEGER NOT NULL DEFAULT 16,
    vector_json TEXT,
    is_encrypted INTEGER NOT NULL DEFAULT 0,
    key_id TEXT,
    ciphertext BLOB,
    nonce BLOB,
    tag BLOB,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bv_entity_win ON behavioral_vectors(entity_id, window_start);

CREATE TABLE IF NOT EXISTS encrypted_vault (
    vault_id TEXT PRIMARY KEY,
    item_type TEXT NOT NULL,
    key_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    tag BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL
);
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
            env_db_path = os.environ.get("NETWORK_ANOMALY_DB_PATH", "").strip()
            if env_db_path == ":memory:":
                self.db_path: Union[str, Path] = ":memory:"
            elif env_db_path:
                self.db_path = Path(env_db_path)
            else:
                self.db_path = resolve_default_db_path()
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

    def initialize_schema(self, include_v2: bool = True) -> None:
        """Execute DDL statements to ensure all required tables and indices exist."""
        with self.transaction() as conn:
            conn.executescript(SCHEMA_SQL)
            if include_v2:
                conn.executescript(V2_SCHEMA_SQL)

    def is_healthy(self) -> bool:
        """Check if SQLite database is accessible and responsive."""
        try:
            with self.transaction() as conn:
                row = conn.execute("SELECT 1 AS alive").fetchone()
                return bool(row and row["alive"] == 1)
        except Exception:
            return False

    def insert_unified_security_event(self, event_record: Dict[str, Any]) -> str:
        """Persist a canonical unified security event into unified_security_events."""
        event_id = str(event_record["event_id"])
        created_at = str(event_record.get("created_at") or datetime.now(timezone.utc).isoformat())
        payload = event_record.get("payload_json")
        if payload is None:
            payload = json.dumps(event_record, sort_keys=True, default=str)
        elif not isinstance(payload, str):
            payload = json.dumps(payload, sort_keys=True, default=str)

        with self.transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO unified_security_events (
                    event_id, schema_version, event_timestamp, event_kind, source_id, entity_id,
                    source_ip, dest_ip, source_port, dest_port, protocol,
                    is_ml_complete, validation_status, raw_provenance, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event_id,
                    str(event_record.get("schema_version") or "2.0.0"),
                    str(event_record["event_timestamp"]),
                    str(event_record["event_kind"]),
                    str(event_record["source_id"]),
                    str(event_record["entity_id"]),
                    event_record.get("source_ip"),
                    event_record.get("dest_ip"),
                    event_record.get("source_port"),
                    event_record.get("dest_port"),
                    event_record.get("protocol"),
                    int(bool(event_record.get("is_ml_complete", False))),
                    str(event_record.get("validation_status") or "VALID"),
                    json.dumps(
                        event_record.get("raw_provenance") or {}, sort_keys=True, default=str
                    ),
                    payload,
                    created_at,
                ),
            )
        return event_id

    def query_unified_security_events(
        self,
        entity_id: Optional[str] = None,
        event_kind: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query persisted canonical security events ordered newest first."""
        clauses: List[str] = []
        params: List[Any] = []
        if entity_id is not None:
            clauses.append("entity_id = ?")
            params.append(entity_id)
        if event_kind is not None:
            clauses.append("event_kind = ?")
            params.append(event_kind)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT event_id, event_timestamp, event_kind, source_id, entity_id,
                   source_ip, dest_ip, source_port, dest_port, protocol,
                   is_ml_complete, validation_status, payload_json, created_at
            FROM unified_security_events
            {where_sql}
            ORDER BY event_timestamp DESC
            LIMIT ?;
        """
        params.append(int(limit))
        with self.transaction() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        results: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["is_ml_complete"] = bool(item.get("is_ml_complete"))
            results.append(item)
        return results

    def close(self) -> None:
        """Close persistent resources (if any)."""
        if self._memory_conn is not None:
            self._memory_conn.close()
            self._memory_conn = None
