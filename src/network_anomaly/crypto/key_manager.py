"""Key lifecycle management, CSPRNG generation, and secure keystore.

Implements Issue #119 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DPAPI_PREFIX = b"NETFLOW_DPAPI_V1:"
POSIX_PREFIX = b"NETFLOW_POSIX_V1:"
WRAPPED_DEK_PREFIX = b"NETFLOW_WRAPPED_DEK_V1:"


def _protect_dpapi(plaintext: bytes, description: str = "NetFlow Sentinel Master Key") -> bytes:
    if sys.platform != "win32":
        return plaintext
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob = _DATA_BLOB(
        len(plaintext), ctypes.cast(ctypes.c_char_p(plaintext), ctypes.POINTER(ctypes.c_char))
    )
    out_blob = _DATA_BLOB()
    desc_p = ctypes.c_wchar_p(description) if description else None
    res = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        desc_p,
        None,
        None,
        None,
        0x01,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(out_blob),
    )
    if not res:
        raise OSError(f"CryptProtectData failed with error {kernel32.GetLastError()}")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _unprotect_dpapi(ciphertext: bytes) -> bytes:
    if sys.platform != "win32":
        return ciphertext
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob = _DATA_BLOB(
        len(ciphertext), ctypes.cast(ctypes.c_char_p(ciphertext), ctypes.POINTER(ctypes.c_char))
    )
    out_blob = _DATA_BLOB()
    res = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0x01,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(out_blob),
    )
    if not res:
        raise OSError(f"CryptUnprotectData failed with error {kernel32.GetLastError()}")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


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
            raw = master_file.read_bytes()
            if raw.startswith(DPAPI_PREFIX):
                return _unprotect_dpapi(raw[len(DPAPI_PREFIX) :])
            if raw.startswith(POSIX_PREFIX):
                return raw[len(POSIX_PREFIX) :]
            return raw

        new_key = os.urandom(self.KEY_LENGTH_BYTES)
        if sys.platform == "win32":
            try:
                encrypted_blob = _protect_dpapi(new_key, "NetFlow Sentinel Master Key")
                master_file.write_bytes(DPAPI_PREFIX + encrypted_blob)
            except Exception:
                master_file.write_bytes(POSIX_PREFIX + new_key)
        else:
            master_file.write_bytes(POSIX_PREFIX + new_key)
            try:
                os.chmod(master_file, 0o600)
            except Exception:
                pass
        return new_key

    def _save_dek_file(self, key_id: str, raw_key: bytes) -> None:
        """Encrypt and persist DEK wrapped under Master KEK (AES-256-GCM)."""
        kfile = self.keystore_dir / f"{key_id}.key"
        nonce = os.urandom(12)
        aesgcm = AESGCM(self._master_key)
        ciphertext = aesgcm.encrypt(nonce, raw_key, key_id.encode("ascii"))
        payload = WRAPPED_DEK_PREFIX + nonce + ciphertext
        kfile.write_bytes(payload)
        try:
            os.chmod(kfile, 0o600)
        except Exception:
            pass

    def _load_dek_file(self, key_id: str) -> Optional[bytes]:
        """Load and unwrap DEK from storage."""
        kfile = self.keystore_dir / f"{key_id}.key"
        if not kfile.exists():
            return None
        raw = kfile.read_bytes()
        if raw.startswith(WRAPPED_DEK_PREFIX):
            payload = raw[len(WRAPPED_DEK_PREFIX) :]
            nonce = payload[:12]
            ciphertext = payload[12:]
            aesgcm = AESGCM(self._master_key)
            return aesgcm.decrypt(nonce, ciphertext, key_id.encode("ascii"))
        return raw

    def _load_all_keys(self) -> None:
        """Load keys and metadata from keystore directory."""
        meta_file = self.keystore_dir / "keys_metadata.json"
        if meta_file.exists():
            try:
                data = json.loads(meta_file.read_text(encoding="utf-8"))
                for item in data.get("keys", []):
                    km = KeyMetadata.from_dict(item)
                    self._metadata[km.key_id] = km
                    raw_key = self._load_dek_file(km.key_id)
                    if raw_key is not None:
                        self._keys[km.key_id] = raw_key
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

        # Persist wrapped key file
        self._save_dek_file(key_id, raw_key)

        self._save_metadata()
        return km

    def get_active_key(self, domain: str = "general") -> Tuple[str, bytes]:
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
