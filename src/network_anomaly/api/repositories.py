"""Repositories for persisting events, sessions, incidents, evidence, key metadata, and audits.

Enforces SQL injection safety via parameter binding, atomic multi-row operations,
deterministic ordering for pagination, and row-level transformation helpers.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc_now_str() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    """Convert sqlite3.Row to standard dict, parsing embedded JSON fields."""
    if row is None:
        return None
    d = dict(row)
    for field in ("features", "metadata", "details"):
        if field in d and d[field] is not None:
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


class EventRepository:
    """Repository handling raw/normalized network flow events."""

    @staticmethod
    def insert(conn: sqlite3.Connection, event: Dict[str, Any]) -> str:
        """Insert a single event record and return its event_id."""
        event_id = event.get("event_id") or f"evt_{uuid.uuid4().hex[:16]}"
        now = _utc_now_str()
        features_json = json.dumps(event.get("features", {}))
        metadata_json = json.dumps(event.get("metadata", {}))

        conn.execute(
            """
            INSERT INTO events (
                event_id, session_id, timestamp, source_ip, dest_ip,
                source_port, dest_port, protocol, features, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                event.get("session_id"),
                event.get("timestamp") or now,
                event.get("source_ip"),
                event.get("dest_ip"),
                event.get("source_port"),
                event.get("dest_port"),
                str(event.get("protocol", "")),
                features_json,
                metadata_json,
                event.get("created_at") or now,
            ),
        )
        return event_id

    @staticmethod
    def insert_batch(conn: sqlite3.Connection, events: List[Dict[str, Any]]) -> List[str]:
        """Atomically insert a batch of events within current transaction."""
        ids = []
        for evt in events:
            evt_id = EventRepository.insert(conn, evt)
            ids.append(evt_id)
        return ids

    @staticmethod
    def get_by_id(conn: sqlite3.Connection, event_id: str) -> Optional[Dict[str, Any]]:
        """Fetch event by event_id."""
        cur = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,))
        return _row_to_dict(cur.fetchone())

    @staticmethod
    def list_events(
        conn: sqlite3.Connection,
        limit: int = 50,
        offset: int = 0,
        session_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List events ordered by timestamp descending with pagination."""
        query = "SELECT * FROM events"
        params: List[Any] = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " ORDER BY timestamp DESC, created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur = conn.execute(query, tuple(params))
        return [_row_to_dict(r) for r in cur.fetchall() if r is not None]  # type: ignore

    @staticmethod
    def count(conn: sqlite3.Connection, session_id: Optional[str] = None) -> int:
        """Count total events."""
        query = "SELECT COUNT(*) AS total FROM events"
        params: List[Any] = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        cur = conn.execute(query, tuple(params))
        row = cur.fetchone()
        return int(row["total"]) if row else 0


class SessionRepository:
    """Repository handling session aggregates."""

    @staticmethod
    def create_or_update(conn: sqlite3.Connection, session: Dict[str, Any]) -> Dict[str, Any]:
        """Insert or update a session record."""
        session_id = session.get("session_id") or f"sess_{uuid.uuid4().hex[:12]}"
        now = _utc_now_str()

        existing = SessionRepository.get_by_id(conn, session_id)
        if existing:
            new_count = existing["event_count"] + session.get("event_count", 1)
            end_time = session.get("end_time") or now
            conn.execute(
                """
                UPDATE sessions
                SET end_time = ?, event_count = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (end_time, new_count, now, session_id),
            )
        else:
            conn.execute(
                """
                INSERT INTO sessions (
                    session_id, start_time, end_time, source_ip, dest_ip,
                    event_count, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    session.get("start_time") or now,
                    session.get("end_time") or now,
                    session.get("source_ip"),
                    session.get("dest_ip"),
                    session.get("event_count", 1),
                    now,
                    now,
                ),
            )
        ret = SessionRepository.get_by_id(conn, session_id)
        return ret or {}

    @staticmethod
    def get_by_id(conn: sqlite3.Connection, session_id: str) -> Optional[Dict[str, Any]]:
        """Fetch session by ID."""
        cur = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        return _row_to_dict(cur.fetchone())

    @staticmethod
    def list_sessions(
        conn: sqlite3.Connection,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List sessions ordered by start_time descending."""
        cur = conn.execute(
            "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [_row_to_dict(r) for r in cur.fetchall() if r is not None]  # type: ignore

    @staticmethod
    def count(conn: sqlite3.Connection) -> int:
        """Count total sessions."""
        cur = conn.execute("SELECT COUNT(*) AS total FROM sessions")
        row = cur.fetchone()
        return int(row["total"]) if row else 0


class IncidentRepository:
    """Repository handling detected and reported security incidents."""

    @staticmethod
    def create(conn: sqlite3.Connection, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new security incident alert."""
        incident_id = incident.get("incident_id") or f"inc_{uuid.uuid4().hex[:12]}"
        now = _utc_now_str()

        conn.execute(
            """
            INSERT INTO incidents (
                incident_id, title, severity, status, anomaly_score,
                attack_type, description, event_id, session_id, evidence_id,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                incident.get("title", "Anomaly Detection Alert"),
                incident.get("severity", "MEDIUM").upper(),
                incident.get("status", "OPEN").upper(),
                float(incident.get("anomaly_score", 0.0)),
                incident.get("attack_type"),
                incident.get("description", ""),
                incident.get("event_id"),
                incident.get("session_id"),
                incident.get("evidence_id"),
                incident.get("created_at") or now,
                incident.get("updated_at") or now,
            ),
        )
        ret = IncidentRepository.get_by_id(conn, incident_id)
        return ret or {}

    @staticmethod
    def get_by_id(conn: sqlite3.Connection, incident_id: str) -> Optional[Dict[str, Any]]:
        """Fetch incident by incident_id."""
        cur = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        return _row_to_dict(cur.fetchone())

    @staticmethod
    def update(
        conn: sqlite3.Connection,
        incident_id: str,
        updates: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Update incident status, severity, or description."""
        existing = IncidentRepository.get_by_id(conn, incident_id)
        if not existing:
            return None

        allowed = {"status", "severity", "description", "title", "attack_type"}
        fields = []
        params = []
        for k, v in updates.items():
            if k in allowed and v is not None:
                fields.append(f"{k} = ?")
                params.append(v.upper() if k in {"status", "severity"} else v)

        if not fields:
            return existing

        now = _utc_now_str()
        fields.append("updated_at = ?")
        params.append(now)
        params.append(incident_id)

        conn.execute(
            f"UPDATE incidents SET {', '.join(fields)} WHERE incident_id = ?", tuple(params)
        )
        return IncidentRepository.get_by_id(conn, incident_id)

    @staticmethod
    def list_incidents(
        conn: sqlite3.Connection,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List incidents with optional filtering and pagination."""
        clauses = []
        params: List[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if status:
            clauses.append("status = ?")
            params.append(status.upper())

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT * FROM incidents{where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur = conn.execute(query, tuple(params))
        return [_row_to_dict(r) for r in cur.fetchall() if r is not None]  # type: ignore

    @staticmethod
    def count(
        conn: sqlite3.Connection,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> int:
        """Count total incidents matching filters."""
        clauses = []
        params: List[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if status:
            clauses.append("status = ?")
            params.append(status.upper())

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT COUNT(*) AS total FROM incidents{where}"
        cur = conn.execute(query, tuple(params))
        row = cur.fetchone()
        return int(row["total"]) if row else 0


class EvidenceRepository:
    """Repository handling evidence references for traceability."""

    @staticmethod
    def create(conn: sqlite3.Connection, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Store evidence link and artifact SHA-256."""
        evidence_id = evidence.get("evidence_id") or f"ev_{uuid.uuid4().hex[:12]}"
        now = _utc_now_str()
        details_json = json.dumps(evidence.get("details", {}))

        conn.execute(
            """
            INSERT INTO evidences (
                evidence_id, incident_id, artifact_name, artifact_sha256,
                evidence_type, details, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                evidence.get("incident_id"),
                evidence.get("artifact_name", ""),
                evidence.get("artifact_sha256", ""),
                evidence.get("evidence_type", "model_prediction"),
                details_json,
                evidence.get("created_at") or now,
            ),
        )
        ret = EvidenceRepository.get_by_id(conn, evidence_id)
        return ret or {}

    @staticmethod
    def get_by_id(conn: sqlite3.Connection, evidence_id: str) -> Optional[Dict[str, Any]]:
        """Fetch evidence by ID."""
        cur = conn.execute("SELECT * FROM evidences WHERE evidence_id = ?", (evidence_id,))
        return _row_to_dict(cur.fetchone())

    @staticmethod
    def list_by_incident(conn: sqlite3.Connection, incident_id: str) -> List[Dict[str, Any]]:
        """List all evidence entries associated with an incident."""
        cur = conn.execute(
            "SELECT * FROM evidences WHERE incident_id = ? ORDER BY created_at ASC",
            (incident_id,),
        )
        return [_row_to_dict(r) for r in cur.fetchall() if r is not None]  # type: ignore


class KeyMetadataRepository:
    """Repository handling cryptographic key metadata without exposing key material."""

    @staticmethod
    def create_key(conn: sqlite3.Connection, key_meta: Dict[str, Any]) -> Dict[str, Any]:
        """Store non-sensitive key metadata (id, algorithm, version, status)."""
        key_id = key_meta.get("key_id") or f"key_{uuid.uuid4().hex[:12]}"
        now = _utc_now_str()

        conn.execute(
            """
            INSERT INTO key_metadata (
                key_id, algorithm, version, status, created_at, retired_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                key_id,
                key_meta.get("algorithm", "AES-256-GCM"),
                key_meta.get("version", 1),
                key_meta.get("status", "ACTIVE").upper(),
                key_meta.get("created_at") or now,
                key_meta.get("retired_at"),
            ),
        )
        ret = KeyMetadataRepository.get_key(conn, key_id)
        return ret or {}

    @staticmethod
    def get_active_key(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
        """Retrieve current active encryption key metadata."""
        cur = conn.execute(
            "SELECT * FROM key_metadata "
            "WHERE status = 'ACTIVE' "
            "ORDER BY version DESC, created_at DESC LIMIT 1"
        )
        return _row_to_dict(cur.fetchone())

    @staticmethod
    def get_key(conn: sqlite3.Connection, key_id: str) -> Optional[Dict[str, Any]]:
        """Fetch key metadata by key_id."""
        cur = conn.execute("SELECT * FROM key_metadata WHERE key_id = ?", (key_id,))
        return _row_to_dict(cur.fetchone())

    @staticmethod
    def list_keys(
        conn: sqlite3.Connection,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List key metadata entries."""
        cur = conn.execute(
            "SELECT * FROM key_metadata ORDER BY version DESC, created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [_row_to_dict(r) for r in cur.fetchall() if r is not None]  # type: ignore

    @staticmethod
    def retire_key(conn: sqlite3.Connection, key_id: str, retired_at: Optional[str] = None) -> bool:
        """Mark a key as retired."""
        now = retired_at or _utc_now_str()
        cur = conn.execute(
            "UPDATE key_metadata SET status = 'RETIRED', retired_at = ? WHERE key_id = ?",
            (now, key_id),
        )
        return cur.rowcount > 0


class RotationAuditRepository:
    """Repository handling key rotation audit trail."""

    @staticmethod
    def log_rotation(conn: sqlite3.Connection, audit: Dict[str, Any]) -> Dict[str, Any]:
        """Record an entry in the key rotation audit table."""
        rotation_id = audit.get("rotation_id") or f"rot_{uuid.uuid4().hex[:12]}"
        now = _utc_now_str()

        conn.execute(
            """
            INSERT INTO rotation_audit (
                rotation_id, triggered_by, old_key_id, new_key_id,
                dry_run, status, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rotation_id,
                audit.get("triggered_by", "system"),
                audit.get("old_key_id"),
                audit.get("new_key_id", ""),
                1 if audit.get("dry_run", True) else 0,
                audit.get("status", "SUCCESS"),
                audit.get("reason", "Scheduled rotation"),
                audit.get("created_at") or now,
            ),
        )
        cur = conn.execute("SELECT * FROM rotation_audit WHERE rotation_id = ?", (rotation_id,))
        row = cur.fetchone()
        return _row_to_dict(row) or {}

    @staticmethod
    def get_last_rotation(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
        """Retrieve most recent key rotation entry."""
        cur = conn.execute("SELECT * FROM rotation_audit ORDER BY created_at DESC LIMIT 1")
        return _row_to_dict(cur.fetchone())

    @staticmethod
    def list_rotations(
        conn: sqlite3.Connection,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List rotation audits with pagination."""
        cur = conn.execute(
            "SELECT * FROM rotation_audit ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [_row_to_dict(r) for r in cur.fetchall() if r is not None]  # type: ignore

    @staticmethod
    def count(conn: sqlite3.Connection) -> int:
        """Count total rotation audit records."""
        cur = conn.execute("SELECT COUNT(*) AS total FROM rotation_audit")
        row = cur.fetchone()
        return int(row["total"]) if row else 0


class IdempotencyRepository:
    """Repository handling idempotency caching to prevent duplicate side effects."""

    @staticmethod
    def get_record(
        conn: sqlite3.Connection,
        idempotency_key: str,
        endpoint: str,
    ) -> Optional[Dict[str, Any]]:
        """Fetch saved idempotent response."""
        cur = conn.execute(
            "SELECT * FROM idempotency_records WHERE idempotency_key = ? AND endpoint = ?",
            (idempotency_key, endpoint),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "idempotency_key": row["idempotency_key"],
            "endpoint": row["endpoint"],
            "status_code": row["status_code"],
            "response_body": json.loads(row["response_json"]),
            "created_at": row["created_at"],
        }

    @staticmethod
    def save_record(
        conn: sqlite3.Connection,
        idempotency_key: str,
        endpoint: str,
        status_code: int,
        response_body: Any,
    ) -> None:
        """Save an idempotent execution response."""
        now = _utc_now_str()
        response_json = json.dumps(response_body)
        conn.execute(
            """
            INSERT OR REPLACE INTO idempotency_records (
                idempotency_key, endpoint, status_code, response_json, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (idempotency_key, endpoint, status_code, response_json, now),
        )
