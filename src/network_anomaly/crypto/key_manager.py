"""Key lifecycle management, CSPRNG generation, and fail-closed keystore.

Implements Issues #119, #120 and #124 for NetFlow Sentinel v2.0.

Storage rules enforced by this module:

* On Windows the master key is protected with the Windows Data Protection API
  (DPAPI, current-user scope). If DPAPI is unavailable or fails, key creation
  and loading fail closed with :class:`KeyStorageError`; a plaintext master key
  is never written as a silent fallback.
* On POSIX the master key is protected by file permissions (``0600``) only and
  the limitation is reported by :meth:`KeyManager.storage_protection`.
* DEKs are wrapped with AES-256-GCM under the master KEK. The current format
  (``NETFLOW_WRAPPED_DEK_V2``) authenticates ``key_id|domain|version`` as AAD,
  so moving a wrapped key to another key id or domain fails authentication.
  Version 1 files (AAD = ``key_id``) remain readable for migration.
* Legacy plaintext master keys and plaintext DEKs are never loaded silently.
  They must be migrated with :meth:`KeyManager.migrate_legacy_keystore` (or
  ``python scripts/migrate_keystore.py``).
* All keystore writes are atomic (temporary file + ``os.replace``) so an
  interrupted write cannot truncate a key or the metadata ledger.
* Wrapped-key nonces are issued through a persisted uniqueness registry.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
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
WRAPPED_DEK_PREFIX_V1 = b"NETFLOW_WRAPPED_DEK_V1:"
WRAPPED_DEK_PREFIX = b"NETFLOW_WRAPPED_DEK_V2:"
NONCE_LENGTH_BYTES = 12
NONCE_REGISTRY_FILENAME = "nonce_registry.json"

PROTECTION_DPAPI = "WINDOWS_DPAPI"
PROTECTION_POSIX = "POSIX_FILE_PERMISSIONS"

_SAFE_IDENTIFIER_RE = re.compile(r"\A[A-Za-z0-9._-]+\Z")


def _validate_safe_identifier(value: str, field_name: str) -> str:
    """Validate that ``value`` is a safe identifier without path traversal."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"Invalid {field_name}: must be a non-empty string")
    if ".." in value or value == "." or not _SAFE_IDENTIFIER_RE.fullmatch(value):
        raise ValueError(
            f"Invalid {field_name} {value!r}: must match ^[A-Za-z0-9._-]+$ without '..'"
        )
    return value


class KeyStorageError(RuntimeError):
    """Raised when the keystore cannot be read or written safely."""


class LegacyKeyMigrationRequired(KeyStorageError):
    """Raised when a legacy plaintext key was found and migration is required."""


def _protect_dpapi(plaintext: bytes, description: str = "NetFlow Sentinel Master Key") -> bytes:
    """Protect ``plaintext`` with DPAPI (current user). Raises on any failure."""
    if sys.platform != "win32":
        raise KeyStorageError("Windows DPAPI is not available on this platform")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buffer = ctypes.create_string_buffer(plaintext, len(plaintext))
    in_blob = _DATA_BLOB(len(plaintext), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
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
        raise KeyStorageError(f"CryptProtectData failed with error {kernel32.GetLastError()}")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _unprotect_dpapi(ciphertext: bytes) -> bytes:
    """Unprotect a DPAPI blob. Raises on any failure."""
    if sys.platform != "win32":
        raise KeyStorageError("Windows DPAPI is not available on this platform")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buffer = ctypes.create_string_buffer(ciphertext, len(ciphertext))
    in_blob = _DATA_BLOB(len(ciphertext), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
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
        raise KeyStorageError(f"CryptUnprotectData failed with error {kernel32.GetLastError()}")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def dpapi_available() -> bool:
    """Whether the running platform provides Windows DPAPI."""
    return sys.platform == "win32"


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` atomically with restrictive permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.tmp-{os.getpid()}-{os.urandom(6).hex()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(temp_path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_path, mode)
        except OSError:
            pass
        os.replace(temp_path, path)
    except BaseException:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def _harden_windows_acl(path: Path) -> str:
    """Best-effort removal of inherited ACLs on the keystore directory.

    Returns a status string for :meth:`KeyManager.storage_protection`. The
    current user keeps full control; no other principal is granted access.
    """
    if sys.platform != "win32":
        return "NOT_WINDOWS"
    icacls = shutil.which("icacls")
    if icacls is None:
        return "SKIPPED_ICACLS_NOT_FOUND"
    username = os.environ.get("USERNAME")
    domain = os.environ.get("USERDOMAIN")
    if not username:
        return "SKIPPED_CURRENT_USER_UNKNOWN"
    account = f"{domain}\\{username}" if domain else username
    try:
        result = subprocess.run(
            [icacls, str(path), "/inheritance:r", "/grant:r", f"{account}:(OI)(CI)F"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"FAILED:{type(exc).__name__}"
    if result.returncode != 0:
        return f"FAILED:icacls_exit_{result.returncode}"
    return "APPLIED"


class NonceRegistry:
    """Persisted set of SHA-256 nonce fingerprints for wrapped-key operations.

    The registry stores fingerprints, never nonces or keys. It is only used for
    low-volume keystore operations; data-plane AEAD keeps using fresh 96-bit
    CSPRNG nonces bounded by the rotation interval.
    """

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._fingerprints: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            values = payload.get("nonce_sha256", [])
            if isinstance(values, list):
                self._fingerprints = {str(value) for value in values}
        except (OSError, ValueError):
            # A corrupt registry must not make keys unrecoverable; it is rebuilt
            # as new nonces are issued.
            self._fingerprints = set()

    def __len__(self) -> int:
        return len(self._fingerprints)

    def _persist(self) -> None:
        payload = {
            "algorithm": "sha256-fingerprint",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "nonce_sha256": sorted(self._fingerprints),
        }
        _atomic_write(self.path, json.dumps(payload, indent=2).encode("utf-8"), mode=0o600)

    def issue(self, length: int = NONCE_LENGTH_BYTES, attempts: int = 8) -> bytes:
        """Return a nonce whose fingerprint is new, or raise."""
        with self._lock:
            for _ in range(max(1, attempts)):
                nonce = os.urandom(length)
                digest = hashlib.sha256(nonce).hexdigest()
                if digest not in self._fingerprints:
                    self._fingerprints.add(digest)
                    self._persist()
                    return nonce
        raise KeyStorageError("nonce uniqueness registry exhausted its attempts")


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

    def __init__(
        self,
        keystore_dir: Optional[Path] = None,
        master_key: Optional[bytes] = None,
        allow_legacy_master_key: bool = False,
    ):
        self.keystore_dir = keystore_dir or Path("data/keys")
        self.keystore_dir.mkdir(parents=True, exist_ok=True)
        self.allow_legacy_master_key = allow_legacy_master_key
        self.load_errors: List[str] = []
        # In-memory key cache {key_id: raw_bytes}
        self._keys: Dict[str, bytes] = {}
        # Key metadata cache {key_id: KeyMetadata}
        self._metadata: Dict[str, KeyMetadata] = {}
        # Current active key id by domain
        self._active_key_ids: Dict[str, str] = {}
        self._acl_status = _harden_windows_acl(self.keystore_dir)
        self.nonce_registry = NonceRegistry(self.keystore_dir / NONCE_REGISTRY_FILENAME)
        self._master_key_protection = PROTECTION_DPAPI if dpapi_available() else PROTECTION_POSIX
        if master_key is not None:
            if len(master_key) != self.KEY_LENGTH_BYTES:
                raise KeyStorageError(f"master key must be exactly {self.KEY_LENGTH_BYTES} bytes")
            self._master_key = master_key
            self._master_key_protection = "IN_MEMORY_INJECTED"
        else:
            self._master_key = self._load_or_create_master_key()
        self._load_all_keys()

    def __repr__(self) -> str:  # never expose key material
        return (
            f"KeyManager(keystore_dir={str(self.keystore_dir)!r}, "
            f"keys={len(self._metadata)}, "
            f"master_key=<redacted>, "
            f"protection={self._master_key_protection!r})"
        )

    # ------------------------------------------------------------- master key
    def _master_key_path(self) -> Path:
        return self.keystore_dir / "master.key"

    def _load_or_create_master_key(self) -> bytes:
        """Load a protected master key or create one. Fails closed."""
        master_file = self._master_key_path()
        if master_file.exists():
            return self._read_master_key(master_file.read_bytes())

        new_key = os.urandom(self.KEY_LENGTH_BYTES)
        if dpapi_available():
            # No plaintext fallback: a DPAPI failure aborts key creation.
            try:
                encrypted_blob = _protect_dpapi(new_key, "NetFlow Sentinel Master Key")
            except KeyStorageError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                raise KeyStorageError(
                    f"Windows DPAPI protection failed: {type(exc).__name__}"
                ) from exc
            _atomic_write(master_file, DPAPI_PREFIX + encrypted_blob)
            self._master_key_protection = PROTECTION_DPAPI
        else:
            _atomic_write(master_file, POSIX_PREFIX + new_key)
            self._master_key_protection = PROTECTION_POSIX
        return new_key

    def _read_master_key(self, raw: bytes) -> bytes:
        """Decode master key bytes from a supported storage format."""
        if raw.startswith(DPAPI_PREFIX):
            if not dpapi_available():
                raise KeyStorageError(
                    "master.key is DPAPI-protected but this platform is not Windows"
                )
            try:
                material = _unprotect_dpapi(raw[len(DPAPI_PREFIX) :])
            except KeyStorageError as exc:
                raise KeyStorageError(
                    "Windows DPAPI could not unprotect master.key; the key belongs to "
                    "another Windows user or profile and must not be bypassed"
                ) from exc
            self._master_key_protection = PROTECTION_DPAPI
        elif raw.startswith(POSIX_PREFIX):
            if dpapi_available() and not self.allow_legacy_master_key:
                raise LegacyKeyMigrationRequired(
                    "master.key uses the legacy POSIX plaintext format on Windows. "
                    "Run 'python scripts/migrate_keystore.py' to protect it with "
                    "Windows DPAPI, or pass allow_legacy_master_key=True for a "
                    "controlled read-only migration."
                )
            material = raw[len(POSIX_PREFIX) :]
            self._master_key_protection = PROTECTION_POSIX
        elif len(raw) == self.KEY_LENGTH_BYTES:
            if not self.allow_legacy_master_key:
                raise LegacyKeyMigrationRequired(
                    "master.key is a legacy raw key without protection. Run "
                    "'python scripts/migrate_keystore.py' to migrate the keystore, "
                    "or pass allow_legacy_master_key=True for controlled migration."
                )
            material = raw
            self._master_key_protection = "LEGACY_PLAINTEXT"
        else:
            raise KeyStorageError(
                "master.key has an unrecognised format; refusing to guess key material"
            )

        if len(material) != self.KEY_LENGTH_BYTES:
            raise KeyStorageError(
                f"master key material must be {self.KEY_LENGTH_BYTES} bytes, "
                f"got {len(material)}"
            )
        return material

    # ------------------------------------------------------------------- DEKs
    @staticmethod
    def _dek_aad(key_id: str, domain: str, version: int) -> bytes:
        return f"{key_id}|{domain}|{version}".encode("utf-8")

    def _dek_file_path(self, key_id: str) -> Path:
        """Return validated DEK path strictly confined to ``self.keystore_dir``."""
        _validate_safe_identifier(key_id, "key_id")
        keystore_resolved = self.keystore_dir.resolve()
        candidate = (self.keystore_dir / f"{key_id}.key").resolve()
        if candidate.parent != keystore_resolved:
            raise ValueError(f"Invalid key_id {key_id!r}: path escapes keystore directory")
        return candidate

    def _save_dek_file(self, key_id: str, raw_key: bytes, domain: str, version: int) -> None:
        """Wrap and persist a DEK under the master KEK (AES-256-GCM, v2 AAD)."""
        _validate_safe_identifier(domain, "domain")
        kfile = self._dek_file_path(key_id)
        nonce = self.nonce_registry.issue()
        aesgcm = AESGCM(self._master_key)
        ciphertext = aesgcm.encrypt(nonce, raw_key, self._dek_aad(key_id, domain, version))
        _atomic_write(kfile, WRAPPED_DEK_PREFIX + nonce + ciphertext)

    def _load_dek_file(self, key_id: str) -> Optional[bytes]:
        """Load and unwrap a DEK, or return ``None`` when the file is absent."""
        kfile = self._dek_file_path(key_id)
        if not kfile.exists():
            return None
        raw = kfile.read_bytes()
        aesgcm = AESGCM(self._master_key)

        if raw.startswith(WRAPPED_DEK_PREFIX):
            metadata = self._metadata.get(key_id)
            if metadata is None:
                raise KeyStorageError(
                    f"wrapped key '{key_id}' has no metadata entry; cannot derive AAD"
                )
            payload = raw[len(WRAPPED_DEK_PREFIX) :]
            nonce, ciphertext = payload[:NONCE_LENGTH_BYTES], payload[NONCE_LENGTH_BYTES:]
            return aesgcm.decrypt(
                nonce,
                ciphertext,
                self._dek_aad(key_id, metadata.domain, metadata.version),
            )

        if raw.startswith(WRAPPED_DEK_PREFIX_V1):
            # Backward compatibility: v1 authenticated only the key id.
            payload = raw[len(WRAPPED_DEK_PREFIX_V1) :]
            nonce, ciphertext = payload[:NONCE_LENGTH_BYTES], payload[NONCE_LENGTH_BYTES:]
            return aesgcm.decrypt(nonce, ciphertext, key_id.encode("ascii"))

        if len(raw) == self.KEY_LENGTH_BYTES:
            if not self.allow_legacy_master_key:
                raise LegacyKeyMigrationRequired(
                    f"key file '{key_id}.key' is a legacy plaintext DEK. Run "
                    "'python scripts/migrate_keystore.py' to wrap it."
                )
            return raw

        raise KeyStorageError(f"key file '{key_id}.key' has an unrecognised format")

    def _load_all_keys(self) -> None:
        """Load keys and metadata from the keystore directory."""
        meta_file = self.keystore_dir / "keys_metadata.json"
        if not meta_file.exists():
            return
        try:
            data = json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise KeyStorageError(
                f"keys_metadata.json is unreadable: {type(exc).__name__}"
            ) from exc

        for item in data.get("keys", []):
            try:
                metadata = KeyMetadata.from_dict(item)
                _validate_safe_identifier(metadata.key_id, "key_id")
                _validate_safe_identifier(metadata.domain, "domain")
            except (KeyError, TypeError, ValueError) as exc:
                self.load_errors.append(
                    f"invalid metadata entry for key '{item.get('key_id', '?')}': "
                    f"{type(exc).__name__}"
                )
                continue
            self._metadata[metadata.key_id] = metadata

        for metadata in self._metadata.values():
            try:
                raw_key = self._load_dek_file(metadata.key_id)
            except Exception as exc:
                self.load_errors.append(
                    f"key '{metadata.key_id}' could not be unwrapped: "
                    f"{type(exc).__name__}: {exc}"
                )
                continue
            if raw_key is None:
                self.load_errors.append(
                    f"key '{metadata.key_id}' is listed in metadata but its key file is missing"
                )
                continue
            self._keys[metadata.key_id] = raw_key
            if metadata.status == KeyStatus.ACTIVE:
                self._active_key_ids[metadata.domain] = metadata.key_id

    def _save_metadata(self) -> None:
        """Persist the metadata ledger atomically."""
        meta_file = self.keystore_dir / "keys_metadata.json"
        data = {
            "keys": [km.to_dict() for km in self._metadata.values()],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write(meta_file, json.dumps(data, indent=2).encode("utf-8"), mode=0o600)

    # ----------------------------------------------------------------- public
    def storage_protection(self) -> Dict[str, Any]:
        """Report keystore protection without exposing any key material."""
        limitations = []
        if not dpapi_available():
            limitations.append(
                "POSIX has no DPAPI; the master key is protected by file permissions "
                "(0600) and the process/OS account boundary only."
            )
        if self._acl_status.startswith(("FAILED", "SKIPPED")):
            limitations.append(
                f"Windows ACL hardening did not complete ({self._acl_status}); the "
                "keystore directory may still inherit broader permissions."
            )
        return {
            "platform": sys.platform,
            "keystore_dir": str(self.keystore_dir),
            "master_key_protection": self._master_key_protection,
            "dpapi_required": dpapi_available(),
            "dpapi_available": dpapi_available(),
            "acl_hardening": self._acl_status,
            "dek_wrapping": {
                "algorithm": "AES-256-GCM",
                "format": "NETFLOW_WRAPPED_DEK_V2",
                "aad": "key_id|domain|version",
                "legacy_v1_supported": True,
            },
            "nonce_registry_entries": len(self.nonce_registry),
            "load_error_count": len(self.load_errors),
            "load_errors": list(self.load_errors),
            "limitations": limitations,
        }

    def derive_key(self, domain: str = "general", key_version: int = 1) -> bytes:
        """Derive domain-separated key using HKDF-SHA256 from master key."""
        _validate_safe_identifier(domain, "domain")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH_BYTES,
            salt=None,
            info=f"sentinel:{domain}:v{key_version}".encode("ascii"),
        )
        return hkdf.derive(self._master_key)

    def generate_key(self, domain: str = "general", version: Optional[int] = None) -> KeyMetadata:
        """Generate a new cryptographic key using CSPRNG and mark as ACTIVE."""
        _validate_safe_identifier(domain, "domain")
        now = datetime.now(timezone.utc)
        if version is None:
            existing_versions = [
                km.version for km in self._metadata.values() if km.domain == domain
            ]
            version = max(existing_versions, default=0) + 1
        key_id = f"k-{domain}-{now.strftime('%Y%m%d%H%M%S')}-{version}"
        _validate_safe_identifier(key_id, "key_id")
        raw_key = os.urandom(self.KEY_LENGTH_BYTES)

        prev_active_id = self._active_key_ids.get(domain)
        if prev_active_id and prev_active_id in self._metadata:
            self._metadata[prev_active_id].status = KeyStatus.RETIRED
            self._metadata[prev_active_id].retired_at = now.isoformat()

        metadata = KeyMetadata(
            key_id=key_id,
            version=version,
            algorithm="AES-256-GCM",
            status=KeyStatus.ACTIVE,
            created_at=now.isoformat(),
            domain=domain,
        )
        # Persist the wrapped DEK before publishing metadata, so a crash cannot
        # leave an ACTIVE key whose material is missing.
        self._save_dek_file(key_id, raw_key, domain=domain, version=version)
        self._metadata[key_id] = metadata
        self._keys[key_id] = raw_key
        self._active_key_ids[domain] = key_id
        self._save_metadata()
        return metadata

    def get_active_key(self, domain: str = "general") -> Tuple[str, bytes]:
        """Get (key_id, key_bytes) for the active key. Fails closed if broken."""
        _validate_safe_identifier(domain, "domain")
        active_id = self._active_key_ids.get(domain)
        if active_id:
            if active_id not in self._keys:
                raise KeyStorageError(
                    f"active key '{active_id}' for domain '{domain}' could not be "
                    "unwrapped; refusing to generate a replacement that would make "
                    "existing ciphertext unreadable"
                )
            return active_id, self._keys[active_id]

        claimed = [
            km
            for km in self._metadata.values()
            if km.domain == domain and km.status == KeyStatus.ACTIVE
        ]
        if claimed:
            raise KeyStorageError(
                f"metadata lists active key '{claimed[0].key_id}' for domain "
                f"'{domain}' but it is not loaded; run the keystore migration or "
                "repair the key file"
            )

        metadata = self.generate_key(domain=domain)
        return metadata.key_id, self._keys[metadata.key_id]

    def get_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve key bytes by key_id for historical decryption."""
        _validate_safe_identifier(key_id, "key_id")
        return self._keys.get(key_id)

    def get_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        _validate_safe_identifier(key_id, "key_id")
        return self._metadata.get(key_id)

    def list_keys(self) -> List[KeyMetadata]:
        return list(self._metadata.values())

    def record_usage(self, key_id: str, count: int = 1) -> None:
        """Increment count of records encrypted under this key."""
        _validate_safe_identifier(key_id, "key_id")
        if key_id in self._metadata:
            self._metadata[key_id].records_encrypted_count += count
            self._save_metadata()

    def revoke_key(self, key_id: str, active_references: int = 0) -> bool:
        """Revoke key if it has no active references. Guard against breaking data."""
        _validate_safe_identifier(key_id, "key_id")
        if active_references > 0:
            raise ValueError(
                f"Cannot revoke key '{key_id}': key still has {active_references} "
                "active encrypted references. Revocation denied."
            )
        if key_id in self._metadata:
            metadata = self._metadata[key_id]
            metadata.status = KeyStatus.REVOKED
            if self._active_key_ids.get(metadata.domain) == key_id:
                del self._active_key_ids[metadata.domain]
            self._save_metadata()
            return True
        return False

    # -------------------------------------------------------------- migration
    @classmethod
    def inspect_keystore(cls, keystore_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Report keystore formats without reading key bytes into the result."""
        keystore = Path(keystore_dir) if keystore_dir else Path("data/keys")
        master_file = keystore / "master.key"
        report: Dict[str, Any] = {
            "keystore_dir": str(keystore),
            "exists": keystore.exists(),
            "master_key_format": "MISSING",
            "dek_formats": {},
            "migration_required": False,
            "platform": sys.platform,
        }
        if not master_file.exists():
            return report
        raw = master_file.read_bytes()
        if raw.startswith(DPAPI_PREFIX):
            report["master_key_format"] = "DPAPI_PROTECTED"
        elif raw.startswith(POSIX_PREFIX):
            report["master_key_format"] = "POSIX_PREFIX_PLAINTEXT"
            report["migration_required"] = True
        elif len(raw) == cls.KEY_LENGTH_BYTES:
            report["master_key_format"] = "LEGACY_RAW_PLAINTEXT"
            report["migration_required"] = True
        else:
            report["master_key_format"] = "UNRECOGNISED"

        for key_file in sorted(keystore.glob("*.key")):
            if key_file.name == "master.key":
                continue
            raw = key_file.read_bytes()
            if raw.startswith(WRAPPED_DEK_PREFIX):
                fmt = "WRAPPED_V2"
            elif raw.startswith(WRAPPED_DEK_PREFIX_V1):
                fmt = "WRAPPED_V1"
            elif len(raw) == cls.KEY_LENGTH_BYTES:
                fmt = "LEGACY_PLAINTEXT"
                report["migration_required"] = True
            else:
                fmt = "UNRECOGNISED"
            report["dek_formats"][key_file.stem] = fmt
        return report

    @classmethod
    def migrate_legacy_keystore(
        cls, keystore_dir: Optional[Path] = None, dry_run: bool = False
    ) -> Dict[str, Any]:
        """Controlled migration of plaintext master key, plaintext DEKs and v1 wraps.

        Order matters: DEKs are re-wrapped first, then the master key is
        protected. A failure before the last step leaves the legacy master key
        in place, so the keystore remains usable. Key bytes are never included
        in the returned report.
        """
        keystore = Path(keystore_dir) if keystore_dir else Path("data/keys")
        inspection = cls.inspect_keystore(keystore)
        report: Dict[str, Any] = {
            "keystore_dir": str(keystore),
            "dry_run": dry_run,
            "platform": sys.platform,
            "source_master_key_format": inspection["master_key_format"],
            "dek_formats": inspection["dek_formats"],
            "dek_rewrapped_plaintext": [],
            "dek_rewrapped_v1": [],
            "master_key_migrated_to": None,
            "migrated": False,
        }
        if not inspection["exists"] or inspection["master_key_format"] == "MISSING":
            report["reason"] = "no master key present; nothing to migrate"
            return report
        if inspection["master_key_format"] == "UNRECOGNISED":
            raise KeyStorageError("master.key has an unrecognised format; refusing to migrate")
        if dry_run:
            report["migration_required"] = inspection["migration_required"]
            return report

        master_file = keystore / "master.key"
        raw_master = master_file.read_bytes()
        if raw_master.startswith(DPAPI_PREFIX):
            if not dpapi_available():
                raise KeyStorageError(
                    "keystore is DPAPI-protected and cannot be migrated on this platform"
                )
            master_key = _unprotect_dpapi(raw_master[len(DPAPI_PREFIX) :])
        elif raw_master.startswith(POSIX_PREFIX):
            master_key = raw_master[len(POSIX_PREFIX) :]
        else:
            master_key = raw_master
        if len(master_key) != cls.KEY_LENGTH_BYTES:
            raise KeyStorageError("legacy master key has an invalid length")

        # Metadata supplies domain/version for the v2 AAD.
        metadata: Dict[str, KeyMetadata] = {}
        meta_file = keystore / "keys_metadata.json"
        if meta_file.exists():
            try:
                payload = json.loads(meta_file.read_text(encoding="utf-8"))
                for item in payload.get("keys", []):
                    entry = KeyMetadata.from_dict(item)
                    metadata[entry.key_id] = entry
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise KeyStorageError(
                    f"cannot migrate without readable metadata: {type(exc).__name__}"
                ) from exc

        aesgcm = AESGCM(master_key)
        registry = NonceRegistry(keystore / NONCE_REGISTRY_FILENAME)
        replaced: List[Path] = []
        for key_file in sorted(keystore.glob("*.key")):
            if key_file.name == "master.key":
                continue
            key_id = key_file.stem
            raw = key_file.read_bytes()
            entry = metadata.get(key_id)
            if entry is None and (
                len(raw) == cls.KEY_LENGTH_BYTES or raw.startswith(WRAPPED_DEK_PREFIX_V1)
            ):
                raise KeyStorageError(f"cannot migrate key '{key_id}': metadata entry is missing")

            if raw.startswith(WRAPPED_DEK_PREFIX):
                continue
            if raw.startswith(WRAPPED_DEK_PREFIX_V1):
                payload = raw[len(WRAPPED_DEK_PREFIX_V1) :]
                nonce = payload[:NONCE_LENGTH_BYTES]
                ciphertext = payload[NONCE_LENGTH_BYTES:]
                dek = aesgcm.decrypt(nonce, ciphertext, key_id.encode("ascii"))
                bucket = report["dek_rewrapped_v1"]
            elif len(raw) == cls.KEY_LENGTH_BYTES:
                dek = raw
                bucket = report["dek_rewrapped_plaintext"]
            else:
                raise KeyStorageError(f"key file '{key_file.name}' has an unrecognised format")

            new_nonce = registry.issue()
            new_ciphertext = aesgcm.encrypt(
                new_nonce, dek, cls._dek_aad(key_id, entry.domain, entry.version)
            )
            _atomic_write(key_file, WRAPPED_DEK_PREFIX + new_nonce + new_ciphertext)
            bucket.append(key_id)
            replaced.append(key_file)

        # Only touch the master key once every DEK was successfully migrated.
        protected_form = None
        if dpapi_available():
            encrypted_blob = _protect_dpapi(master_key, "NetFlow Sentinel Master Key")
            _atomic_write(master_file, DPAPI_PREFIX + encrypted_blob)
            protected_form = PROTECTION_DPAPI
        else:
            _atomic_write(master_file, POSIX_PREFIX + master_key)
            protected_form = PROTECTION_POSIX

        report["master_key_migrated_to"] = protected_form
        report["migrated"] = True
        report["dek_files_touched"] = len(replaced)
        return report
