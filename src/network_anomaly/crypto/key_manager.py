"""Key lifecycle management, CSPRNG generation, and secure keystore.

Implements Issue #119 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


@dataclass
class KeyMetadata:
    key_id: str
    version: int
    algorithm: str = "AES-256-GCM"
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    retired_at: Optional[str] = None
    records_encrypted_count: int = 0
    domain: str = "general"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "version": self.version,
            "algorithm": self.algorithm,
            "status": self.status.value,
            "created_at": self.created_at,
            "retired_at": self.retired_at,
            "records_encrypted_count": self.records_encrypted_count,
            "domain": self.domain,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> KeyMetadata:
        return cls(
            key_id=data["key_id"],
            version=data["version"],
            algorithm=data.get("algorithm", "AES-256-GCM"),
            status=KeyStatus(data.get("status", "ACTIVE")),
            created_at=data["created_at"],
            retired_at=data.get("retired_at"),
            records_encrypted_count=data.get("records_encrypted_count", 0),
            domain=data.get("domain", "general"),
        )


class KeyManager:
    """Manages active and historical cryptographic keys for AES-256-GCM."""

    KEY_LENGTH_BYTES = 32

    def __init__(self, keystore_dir: Optional[Path] = None, master_key: Optional[bytes] = None):
        self.keystore_dir = keystore_dir or Path("data/keys")
        self.keystore_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory key cache {key_id: raw_bytes}
        self._keys: Dict[str, bytes] = {}
        # Key metadata cache {key_id: KeyMetadata}
        self._metadata: Dict[str, KeyMetadata] = {}
        # Current active key id by domain
        self._active_key_ids: Dict[str, str] = {}

        self._master_key = master_key or self._load_or_create_master_key()
        self._load_all_keys()

    def _load_or_create_master_key(self) -> bytes:
        """Load or create root master key in protected storage."""
        master_file = self.keystore_dir / "master.key"
        if master_file.exists():
            return master_file.read_bytes()
        new_key = os.urandom(self.KEY_LENGTH_BYTES)
        master_file.write_bytes(new_key)
        try:
            # Set restrictive file permission on POSIX if applicable
            os.chmod(master_file, 0o600)
        except Exception:
            pass
        return new_key

    def _load_all_keys(self) -> None:
        """Load keys and metadata from keystore directory."""
        meta_file = self.keystore_dir / "keys_metadata.json"
        if meta_file.exists():
            try:
                data = json.loads(meta_file.read_text(encoding="utf-8"))
                for item in data.get("keys", []):
                    km = KeyMetadata.from_dict(item)
                    self._metadata[km.key_id] = km
                    kfile = self.keystore_dir / f"{km.key_id}.key"
                    if kfile.exists():
                        self._keys[km.key_id] = kfile.read_bytes()
                    if km.status == KeyStatus.ACTIVE:
                        self._active_key_ids[km.domain] = km.key_id
            except Exception:
                pass

    def _save_metadata(self) -> None:
        """Persist metadata ledger."""
        meta_file = self.keystore_dir / "keys_metadata.json"
        data = {
            "keys": [km.to_dict() for km in self._metadata.values()],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        meta_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def derive_key(self, domain: str = "general", key_version: int = 1) -> bytes:
        """Derive domain-separated key using HKDF-SHA256 from master key."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH_BYTES,
            salt=None,
            info=f"sentinel:{domain}:v{key_version}".encode("ascii"),
        )
        return hkdf.derive(self._master_key)

    def generate_key(self, domain: str = "general", version: Optional[int] = None) -> KeyMetadata:
        """Generate a new cryptographic key using CSPRNG and mark as ACTIVE."""
        now = datetime.now(timezone.utc)
        if version is None:
            existing_versions = [
                km.version for km in self._metadata.values() if km.domain == domain
            ]
            version = max(existing_versions, default=0) + 1

        key_id = f"k-{domain}-{now.strftime('%Y%m%d%H%M%S')}-{version}"
        raw_key = os.urandom(self.KEY_LENGTH_BYTES)

        # Retire previously active key for this domain
        prev_active_id = self._active_key_ids.get(domain)
        if prev_active_id and prev_active_id in self._metadata:
            self._metadata[prev_active_id].status = KeyStatus.RETIRED
            self._metadata[prev_active_id].retired_at = now.isoformat()

        # Save new key
        km = KeyMetadata(
            key_id=key_id,
            version=version,
            algorithm="AES-256-GCM",
            status=KeyStatus.ACTIVE,
            created_at=now.isoformat(),
            domain=domain,
        )

        self._metadata[key_id] = km
        self._keys[key_id] = raw_key
        self._active_key_ids[domain] = key_id

        # Persist raw key file
        kfile = self.keystore_dir / f"{key_id}.key"
        kfile.write_bytes(raw_key)
        try:
            os.chmod(kfile, 0o600)
        except Exception:
            pass

        self._save_metadata()
        return km

    def get_active_key(self, domain: str = "general") -> tuple[str, bytes]:
        """Get (key_id, key_bytes) for the currently active key. Generates one if none exists."""
        active_id = self._active_key_ids.get(domain)
        if not active_id or active_id not in self._keys:
            km = self.generate_key(domain=domain)
            active_id = km.key_id
        return active_id, self._keys[active_id]

    def get_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve key bytes by key_id for historical decryption."""
        return self._keys.get(key_id)

    def get_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        return self._metadata.get(key_id)

    def list_keys(self) -> List[KeyMetadata]:
        return list(self._metadata.values())

    def record_usage(self, key_id: str, count: int = 1) -> None:
        """Increment count of records encrypted under this key."""
        if key_id in self._metadata:
            self._metadata[key_id].records_encrypted_count += count
            self._save_metadata()

    def revoke_key(self, key_id: str, active_references: int = 0) -> bool:
        """Revoke key if it has no active references. Guard against breaking active data."""
        if active_references > 0:
            raise ValueError(
                f"Cannot revoke key '{key_id}': key still has {active_references} active encrypted references. Revocation denied."
            )
        if key_id in self._metadata:
            self._metadata[key_id].status = KeyStatus.REVOKED
            if self._active_key_ids.get(self._metadata[key_id].domain) == key_id:
                del self._active_key_ids[self._metadata[key_id].domain]
            self._save_metadata()
            return True
        return False
