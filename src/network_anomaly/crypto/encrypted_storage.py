"""Encrypted storage vault for Behavioral Vectors and Evidence Records.

Implements Issues #118 and #123 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .aead import AESGCMCipher, CiphertextEnvelope
from .key_manager import KeyManager


class EncryptedStorageVault:
    """Manages encryption and persistence of sensitive vectors and evidence."""

    def __init__(self, key_manager: KeyManager, db_path: Path):
        self.key_manager = key_manager
        self.db_path = db_path
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        """Ensure vault and behavioral tables exist."""
        conn = sqlite3.connect(str(self.db_path))
        with conn:
            conn.execute("""
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
                """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS encrypted_vault (
                    vault_id TEXT PRIMARY KEY,
                    item_type TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    tag BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );
                """)
        conn.close()

    def store_behavioral_vector(
        self,
        entity_id: str,
        window_start: str,
        window_end: str,
        vector: List[float],
        encrypt: bool = True,
    ) -> str:
        """Store a behavioral vector. If encrypt=True, store ciphertext and NO plaintext."""
        vector_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()
        domain = "behavioral"

        if encrypt:
            key_id, raw_key = self.key_manager.get_active_key(domain=domain)
            cipher = AESGCMCipher(raw_key, key_id=key_id)
            aad = f"domain:behavioral|entity:{entity_id}|win:{window_start}".encode("utf-8")
            envelope = cipher.encrypt_json(vector, aad=aad)

            nonce_bytes = base64.b64decode(envelope.nonce_b64)
            cipher_bytes = base64.b64decode(envelope.ciphertext_b64)
            tag_bytes = base64.b64decode(envelope.tag_b64)

            conn = sqlite3.connect(str(self.db_path))
            with conn:
                conn.execute(
                    """
                    INSERT INTO behavioral_vectors (
                        vector_id, entity_id, window_start, window_end, vector_version,
                        dimensions, vector_json, is_encrypted, key_id, ciphertext, nonce, tag, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        vector_id,
                        entity_id,
                        window_start,
                        window_end,
                        "2.0",
                        len(vector),
                        None,  # STRICTLY NULL: NO PLAINTEXT AT REST
                        1,
                        key_id,
                        cipher_bytes,
                        nonce_bytes,
                        tag_bytes,
                        now_iso,
                    ),
                )
            conn.close()
            self.key_manager.record_usage(key_id, count=1)
        else:
            # Unencrypted storage for non-sensitive testing only
            conn = sqlite3.connect(str(self.db_path))
            with conn:
                conn.execute(
                    """
                    INSERT INTO behavioral_vectors (
                        vector_id, entity_id, window_start, window_end, vector_version,
                        dimensions, vector_json, is_encrypted, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        vector_id,
                        entity_id,
                        window_start,
                        window_end,
                        "2.0",
                        len(vector),
                        json.dumps(vector),
                        0,
                        now_iso,
                    ),
                )
            conn.close()

        return vector_id

    def store_behavioral_vectors_batch(
        self,
        items: Sequence[Dict[str, Any]],
        encrypt: bool = True,
    ) -> List[str]:
        """Store a batch of behavioral vectors in a single SQLite transaction."""
        if not items:
            return []
        now_iso = datetime.now(timezone.utc).isoformat()
        vector_ids: List[str] = []

        if encrypt:
            key_id, raw_key = self.key_manager.get_active_key(domain="behavioral")
            cipher = AESGCMCipher(raw_key, key_id=key_id)
            rows = []
            for item in items:
                vector_id = str(uuid.uuid4())
                vector_ids.append(vector_id)
                entity_id = str(item["entity_id"])
                window_start = str(item["window_start"])
                window_end = str(item["window_end"])
                vector = list(item["vector"])
                aad = f"domain:behavioral|entity:{entity_id}|win:{window_start}".encode("utf-8")
                envelope = cipher.encrypt_json(vector, aad=aad)
                nonce_bytes = base64.b64decode(envelope.nonce_b64)
                cipher_bytes = base64.b64decode(envelope.ciphertext_b64)
                tag_bytes = base64.b64decode(envelope.tag_b64)
                rows.append(
                    (
                        vector_id,
                        entity_id,
                        window_start,
                        window_end,
                        "2.0",
                        len(vector),
                        None,
                        1,
                        key_id,
                        cipher_bytes,
                        nonce_bytes,
                        tag_bytes,
                        now_iso,
                    )
                )

            conn = sqlite3.connect(str(self.db_path))
            try:
                with conn:
                    conn.executemany(
                        """
                        INSERT INTO behavioral_vectors (
                            vector_id, entity_id, window_start, window_end, vector_version,
                            dimensions, vector_json, is_encrypted, key_id, ciphertext, nonce, tag, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        rows,
                    )
            finally:
                conn.close()
            self.key_manager.record_usage(key_id, count=len(items))
        else:
            rows = []
            for item in items:
                vector_id = str(uuid.uuid4())
                vector_ids.append(vector_id)
                vector = list(item["vector"])
                rows.append(
                    (
                        vector_id,
                        str(item["entity_id"]),
                        str(item["window_start"]),
                        str(item["window_end"]),
                        "2.0",
                        len(vector),
                        json.dumps(vector),
                        0,
                        now_iso,
                    )
                )

            conn = sqlite3.connect(str(self.db_path))
            try:
                with conn:
                    conn.executemany(
                        """
                        INSERT INTO behavioral_vectors (
                            vector_id, entity_id, window_start, window_end, vector_version,
                            dimensions, vector_json, is_encrypted, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        rows,
                    )
            finally:
                conn.close()

        return vector_ids

    def load_behavioral_vector(self, vector_id: str) -> Optional[List[float]]:
        """Retrieve and decrypt behavioral vector by ID using historical key lookup."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT entity_id, window_start, is_encrypted, key_id, ciphertext, nonce, tag, vector_json
            FROM behavioral_vectors WHERE vector_id = ?;
            """,
            (vector_id,),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        entity_id, window_start, is_encrypted, key_id, ciphertext, nonce, tag, vector_json = row

        if not is_encrypted:
            return json.loads(vector_json)

        # Look up key by key_id
        raw_key = self.key_manager.get_key(key_id)
        if not raw_key:
            raise KeyError(
                f"Decryption key '{key_id}' not found in keystore. Cannot decrypt vector '{vector_id}'."
            )

        cipher = AESGCMCipher(raw_key, key_id=key_id)
        envelope = CiphertextEnvelope(
            version="aes-256-gcm-v1",
            key_id=key_id,
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            tag_b64=base64.b64encode(tag).decode("ascii"),
        )
        aad = f"domain:behavioral|entity:{entity_id}|win:{window_start}".encode("utf-8")
        return cipher.decrypt_json(envelope, expected_aad=aad)

    def store_evidence(self, item_type: str, payload: Dict[str, Any]) -> str:
        """Encrypt and store an arbitrary evidence record."""
        vault_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()
        domain = "evidence"

        key_id, raw_key = self.key_manager.get_active_key(domain=domain)
        cipher = AESGCMCipher(raw_key, key_id=key_id)
        aad = f"vault:{vault_id}|type:{item_type}".encode("utf-8")
        envelope = cipher.encrypt_json(payload, aad=aad)

        nonce_bytes = base64.b64decode(envelope.nonce_b64)
        cipher_bytes = base64.b64decode(envelope.ciphertext_b64)
        tag_bytes = base64.b64decode(envelope.tag_b64)

        conn = sqlite3.connect(str(self.db_path))
        with conn:
            conn.execute(
                """
                INSERT INTO encrypted_vault (
                    vault_id, item_type, key_id, nonce, tag, ciphertext, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (vault_id, item_type, key_id, nonce_bytes, tag_bytes, cipher_bytes, now_iso),
            )
        conn.close()
        self.key_manager.record_usage(key_id, count=1)
        return vault_id

    def load_evidence(self, vault_id: str) -> Optional[Dict[str, Any]]:
        """Load and decrypt evidence payload."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute(
            "SELECT item_type, key_id, nonce, tag, ciphertext FROM encrypted_vault WHERE vault_id = ?;",
            (vault_id,),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        item_type, key_id, nonce, tag, ciphertext = row
        raw_key = self.key_manager.get_key(key_id)
        if not raw_key:
            raise KeyError(f"Key '{key_id}' missing for vault item '{vault_id}'")

        cipher = AESGCMCipher(raw_key, key_id=key_id)
        envelope = CiphertextEnvelope(
            version="aes-256-gcm-v1",
            key_id=key_id,
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            tag_b64=base64.b64encode(tag).decode("ascii"),
        )
        aad = f"vault:{vault_id}|type:{item_type}".encode("utf-8")
        return cipher.decrypt_json(envelope, expected_aad=aad)
