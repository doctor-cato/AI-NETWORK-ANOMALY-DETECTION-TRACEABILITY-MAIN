"""Database migration utility from NetFlow Sentinel v1.0.0 to v2.0.0.

Provides idempotent schema upgrade, automated pre-migration backup,
dry-run preview, and integrity verification. (Issue #80).
"""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


V2_MIGRATION_SQL = """
PRAGMA foreign_keys = ON;

-- Track schema version
CREATE TABLE IF NOT EXISTS schema_version (
    version TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

-- v2.0: Unified Security Events table
CREATE TABLE IF NOT EXISTS unified_security_events (
    event_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL DEFAULT '2.0.0',
    event_timestamp TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    source_id TEXT NOT NULL,
    entity_id TEXT,
    source_ip TEXT,
    source_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    is_ml_complete INTEGER NOT NULL DEFAULT 0,
    validation_status TEXT NOT NULL DEFAULT 'VALID',
    raw_provenance TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_use_timestamp ON unified_security_events(event_timestamp);
CREATE INDEX IF NOT EXISTS idx_use_entity_id ON unified_security_events(entity_id);
CREATE INDEX IF NOT EXISTS idx_use_kind ON unified_security_events(event_kind);

-- v2.0: Behavioral Vectors table
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

CREATE INDEX IF NOT EXISTS idx_bv_entity_window ON behavioral_vectors(entity_id, window_start);

-- v2.0: Encrypted Vault for sensitive payloads and evidence
CREATE TABLE IF NOT EXISTS encrypted_vault (
    vault_id TEXT PRIMARY KEY,
    item_type TEXT NOT NULL,
    key_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    tag BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vault_key_id ON encrypted_vault(key_id);
CREATE INDEX IF NOT EXISTS idx_vault_item_type ON encrypted_vault(item_type);
"""


def backup_database(db_path: Path) -> Path:
    """Create timestamped backup of the database."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = db_path.with_name(f"{db_path.stem}_backup_{timestamp}{db_path.suffix}")
    shutil.copy2(db_path, backup_path)
    return backup_path


def migrate_database(db_path: Union[str, Path], dry_run: bool = False, create_backup: bool = True) -> bool:
    """Execute v1.0.0 -> v2.0.0 migration idempotently."""
    path = Path(db_path)
    if not path.exists():
        print(f"[!] Database path does not exist: {path}")
        return False

    print(f"[*] Analyzing database for v2.0 migration: {path}")

    # Check current tables
    conn = sqlite3.connect(str(path))
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    existing_tables = set(row[0] for row in cursor.fetchall())

    cursor.execute("PRAGMA integrity_check;")
    integrity = cursor.fetchone()[0]
    if integrity != "ok":
        print(f"[ERROR] Database integrity check failed: {integrity}")
        conn.close()
        return False

    # Check if schema_version exists
    has_v2 = "schema_version" in existing_tables and "unified_security_events" in existing_tables

    if has_v2:
        cursor.execute("SELECT version, applied_at FROM schema_version WHERE version = '2.0.0';")
        v2_row = cursor.fetchone()
        if v2_row:
            print(f"[INFO] Database is already at version 2.0.0 (applied at {v2_row[1]}).")
            conn.close()
            return True

    print(f"[*] Found {len(existing_tables)} existing tables: {', '.join(sorted(existing_tables))}")

    if dry_run:
        print("[DRY-RUN] Schema upgrade preview:")
        print("  - Will add table: schema_version")
        print("  - Will add table: unified_security_events")
        print("  - Will add table: behavioral_vectors")
        print("  - Will add table: encrypted_vault")
        print("  - Will preserve existing tables: events, sessions, incidents, evidences, key_metadata, etc.")
        conn.close()
        return True

    conn.close()

    if create_backup:
        backup = backup_database(path)
        print(f"[+] Backup successfully created at: {backup}")

    # Apply migration in transaction
    conn = sqlite3.connect(str(path))
    try:
        with conn:
            conn.executescript(V2_MIGRATION_SQL)
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT OR REPLACE INTO schema_version (version, description, applied_at) VALUES (?, ?, ?);",
                ("2.0.0", "NetFlow Sentinel v2.0 Multi-source & Cryptographic Upgrade", now_iso),
            )
        print("[SUCCESS] v2.0.0 schema migration successfully applied!")
        return True
    except Exception as e:
        print(f"[ERROR] Migration failed: {e}")
        return False
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="NetFlow Sentinel v1.0.0 -> v2.0.0 DB Migration")
    parser.add_argument("--db-path", type=str, required=True, help="Path to SQLite database")
    parser.add_argument("--dry-run", action="store_true", help="Simulate migration without modifying DB")
    parser.add_argument("--no-backup", action="store_true", help="Skip creating backup")
    args = parser.parse_args()

    success = migrate_database(args.db_path, dry_run=args.dry_run, create_backup=not args.no_backup)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
