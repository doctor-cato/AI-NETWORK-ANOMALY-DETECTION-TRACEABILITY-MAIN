"""Keystore hardening tests: DPAPI fail-closed, legacy migration, AAD binding.

Issue #119 remediation evidence. These tests are platform-aware: DPAPI-specific
assertions run only on Windows, while legacy-format detection, migration,
AAD binding, atomic writes and nonce uniqueness run everywhere.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import network_anomaly.crypto.key_manager as key_manager_module
from network_anomaly.crypto.key_manager import (
    DPAPI_PREFIX,
    POSIX_PREFIX,
    WRAPPED_DEK_PREFIX,
    WRAPPED_DEK_PREFIX_V1,
    KeyManager,
    KeyStorageError,
    LegacyKeyMigrationRequired,
    NonceRegistry,
)

PLAINTEXT_MASTER = b"\x11" * 32
PLAINTEXT_DEK = b"\x22" * 32
LEGACY_KEY_ID = "k-behavioral-20260101000000-1"
V1_KEY_ID = "k-evidence-20260101000000-1"
V1_DEK = b"\x33" * 32


def _write_legacy_keystore(root: Path) -> Path:
    """Create a legacy keystore with a raw master key and one raw DEK."""
    keystore = root / "keys"
    keystore.mkdir(parents=True)
    (keystore / "master.key").write_bytes(PLAINTEXT_MASTER)
    (keystore / f"{LEGACY_KEY_ID}.key").write_bytes(PLAINTEXT_DEK)

    nonce = b"\x44" * 12
    v1_ciphertext = AESGCM(PLAINTEXT_MASTER).encrypt(nonce, V1_DEK, V1_KEY_ID.encode("ascii"))
    (keystore / f"{V1_KEY_ID}.key").write_bytes(WRAPPED_DEK_PREFIX_V1 + nonce + v1_ciphertext)

    metadata = {
        "keys": [
            {
                "key_id": LEGACY_KEY_ID,
                "version": 1,
                "algorithm": "AES-256-GCM",
                "status": "ACTIVE",
                "created_at": "2026-01-01T00:00:00+00:00",
                "retired_at": None,
                "records_encrypted_count": 2,
                "domain": "behavioral",
            },
            {
                "key_id": V1_KEY_ID,
                "version": 2,
                "algorithm": "AES-256-GCM",
                "status": "ACTIVE",
                "created_at": "2026-01-01T00:10:00+00:00",
                "retired_at": None,
                "records_encrypted_count": 0,
                "domain": "evidence",
            },
        ],
        "updated_at": "2026-01-01T00:10:00+00:00",
    }
    (keystore / "keys_metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    return keystore


def _protected_prefix() -> bytes:
    return DPAPI_PREFIX if sys.platform == "win32" else POSIX_PREFIX


class TestMasterKeyProtection:
    def test_new_keystore_never_writes_plaintext_master_key(self, tmp_path):
        keystore = tmp_path / "keys"
        km = KeyManager(keystore_dir=keystore)
        disk = (keystore / "master.key").read_bytes()

        assert disk.startswith(_protected_prefix())
        if sys.platform == "win32":
            assert disk[len(DPAPI_PREFIX) :] != km._master_key
            assert km._master_key not in disk
        report = km.storage_protection()
        assert report["master_key_protection"] in {
            "WINDOWS_DPAPI",
            "POSIX_FILE_PERMISSIONS",
        }
        assert report["dek_wrapping"]["aad"] == "key_id|domain|version"
        assert report["load_error_count"] == 0

    @pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
    def test_dpapi_failure_is_fail_closed(self, tmp_path, monkeypatch):
        keystore = tmp_path / "keys"

        def _fail(*args, **kwargs):
            raise KeyStorageError("simulated DPAPI failure")

        monkeypatch.setattr(key_manager_module, "_protect_dpapi", _fail)
        with pytest.raises(KeyStorageError, match="simulated DPAPI failure"):
            KeyManager(keystore_dir=keystore)

        assert not (keystore / "master.key").exists()
        assert list(keystore.glob("*.key")) == []

    def test_legacy_raw_master_key_requires_migration(self, tmp_path):
        keystore = _write_legacy_keystore(tmp_path)

        with pytest.raises(LegacyKeyMigrationRequired, match="migrate_keystore"):
            KeyManager(keystore_dir=keystore)

        # Explicit opt-in supports a controlled read-only migration.
        km = KeyManager(keystore_dir=keystore, allow_legacy_master_key=True)
        assert km.get_key(LEGACY_KEY_ID) == PLAINTEXT_DEK
        assert km.get_key(V1_KEY_ID) == V1_DEK
        assert km.storage_protection()["master_key_protection"] == "LEGACY_PLAINTEXT"

    def test_migration_protects_master_and_wraps_every_dek(self, tmp_path):
        keystore = _write_legacy_keystore(tmp_path)
        report = KeyManager.migrate_legacy_keystore(keystore)

        assert report["migrated"] is True
        assert report["source_master_key_format"] == "LEGACY_RAW_PLAINTEXT"
        assert report["dek_rewrapped_plaintext"] == [LEGACY_KEY_ID]
        assert report["dek_rewrapped_v1"] == [V1_KEY_ID]
        assert report["master_key_migrated_to"] in {
            "WINDOWS_DPAPI",
            "POSIX_FILE_PERMISSIONS",
        }
        master_bytes = (keystore / "master.key").read_bytes()
        assert master_bytes.startswith(_protected_prefix())
        if sys.platform == "win32":
            assert PLAINTEXT_MASTER not in master_bytes
        else:
            assert (keystore / "master.key").stat().st_mode & 0o777 == 0o600
        for key_file in keystore.glob("*.key"):
            if key_file.name == "master.key":
                continue
            assert key_file.read_bytes().startswith(WRAPPED_DEK_PREFIX)

        # The default fail-closed constructor now succeeds and preserves material.
        km = KeyManager(keystore_dir=keystore)
        assert km.get_key(LEGACY_KEY_ID) == PLAINTEXT_DEK
        assert km.get_key(V1_KEY_ID) == V1_DEK
        assert km.storage_protection()["load_error_count"] == 0

    def test_verify_only_detects_required_migration(self, tmp_path):
        keystore = _write_legacy_keystore(tmp_path)
        inspection = KeyManager.inspect_keystore(keystore)
        assert inspection["migration_required"] is True
        assert inspection["dek_formats"][LEGACY_KEY_ID] == "LEGACY_PLAINTEXT"

    def test_plaintext_dek_with_protected_master_is_not_loaded_silently(self, tmp_path):
        keystore = tmp_path / "keys"
        km = KeyManager(keystore_dir=keystore)
        metadata = km.generate_key(domain="behavioral")
        key_id, raw_key = metadata.key_id, km.get_key(metadata.key_id)

        # Simulate an old plaintext DEK left by a previous version.
        (keystore / f"{key_id}.key").write_bytes(raw_key)

        reloaded = KeyManager(keystore_dir=keystore)
        assert reloaded.get_key(key_id) is None
        assert any(key_id in error for error in reloaded.load_errors)
        with pytest.raises(KeyStorageError, match="not loaded"):
            reloaded.get_active_key(domain="behavioral")


class TestDekWrapping:
    def test_aad_binds_key_id_domain_and_version(self, tmp_path):
        keystore = tmp_path / "keys"
        km = KeyManager(keystore_dir=keystore)
        metadata = km.generate_key(domain="behavioral")
        key_id = metadata.key_id
        raw_key = km.get_key(key_id)

        tampered = KeyManager(keystore_dir=keystore)
        tampered.get_metadata(key_id).version += 1
        tampered._save_metadata()

        reloaded = KeyManager(keystore_dir=keystore)
        assert reloaded.get_key(key_id) is None
        assert any(key_id in error for error in reloaded.load_errors)
        assert reloaded.get_key(key_id) != raw_key

    def test_v1_wrapped_dek_remains_readable(self, tmp_path):
        keystore = tmp_path / "keys"
        km = KeyManager(keystore_dir=keystore)
        metadata = km.generate_key(domain="evidence")
        key_id = metadata.key_id
        raw_key = km.get_key(key_id)

        nonce = b"\x55" * 12
        ciphertext = AESGCM(km._master_key).encrypt(nonce, raw_key, key_id.encode("ascii"))
        (keystore / f"{key_id}.key").write_bytes(WRAPPED_DEK_PREFIX_V1 + nonce + ciphertext)

        reloaded = KeyManager(keystore_dir=keystore)
        assert reloaded.get_key(key_id) == raw_key
        assert reloaded.storage_protection()["dek_wrapping"]["legacy_v1_supported"] is True

    def test_key_files_and_temp_files_leave_no_key_bytes(self, tmp_path):
        keystore = tmp_path / "keys"
        km = KeyManager(keystore_dir=keystore)
        metadata = km.generate_key(domain="behavioral")
        raw_key = km.get_key(metadata.key_id)

        disk = (keystore / f"{metadata.key_id}.key").read_bytes()
        assert disk.startswith(WRAPPED_DEK_PREFIX)
        assert raw_key not in disk
        assert list(keystore.glob(".*.tmp-*")) == []

    def test_storage_report_and_repr_never_expose_key_material(self, tmp_path):
        km = KeyManager(keystore_dir=tmp_path / "keys")
        _, raw_key = km.get_active_key(domain="evidence")
        payload = json.dumps(km.storage_protection()) + repr(km)
        payload += json.dumps([meta.to_dict() for meta in km.list_keys()])

        assert raw_key.hex() not in payload
        assert "<redacted>" in repr(km)
        assert "load_errors" in km.storage_protection()


class TestNonceRegistry:
    def test_registry_persists_fingerprints_only(self, tmp_path):
        registry_path = tmp_path / "nonce_registry.json"
        first = NonceRegistry(registry_path).issue()
        assert len(first) == 12

        on_disk = registry_path.read_text(encoding="utf-8")
        assert first.hex() not in on_disk  # fingerprints, not nonces
        assert "sha256" in json.loads(on_disk)["algorithm"]

        reloaded = NonceRegistry(registry_path)
        assert len(reloaded) == 1

    def test_duplicate_nonce_is_refused(self, tmp_path, monkeypatch):
        registry = NonceRegistry(tmp_path / "nonce_registry.json")
        first = registry.issue()
        real_urandom = os.urandom
        monkeypatch.setattr(
            key_manager_module.os,
            "urandom",
            lambda size: first if size == 12 else real_urandom(size),
        )
        with pytest.raises(KeyStorageError, match="nonce uniqueness"):
            registry.issue()

    def test_generate_key_stops_when_registry_cannot_issue(self, tmp_path, monkeypatch):
        km = KeyManager(keystore_dir=tmp_path / "keys")

        def _exhausted(*args, **kwargs):
            raise KeyStorageError("nonce uniqueness registry exhausted its attempts")

        monkeypatch.setattr(km.nonce_registry, "issue", _exhausted)
        with pytest.raises(KeyStorageError, match="nonce uniqueness"):
            km.generate_key(domain="behavioral")
        # No metadata entry was published for the failed key.
        assert [meta for meta in km.list_keys() if meta.domain == "behavioral"] == []


class TestKeystoreBackupRestore:
    def test_backup_corruption_fails_closed_and_restore_recovers_ciphertext(self, tmp_path):
        import shutil

        from network_anomaly.crypto.aead import AESGCMCipher

        keystore = tmp_path / "keys"
        backup_dir = tmp_path / "keys_backup"
        km = KeyManager(keystore_dir=keystore)
        key_id, raw_key = km.get_active_key(domain="behavioral")
        cipher = AESGCMCipher(key=raw_key, key_id=key_id)
        env = cipher.encrypt_json({"entity": "host:10.0.0.1", "score": 0.42})

        shutil.copytree(keystore, backup_dir)

        # Corrupt DEK file -> key must not load and load_error_count must increment
        dek_file = keystore / f"{key_id}.key"
        dek_file.write_bytes(b"CORRUPTED_DEK")
        km_broken = KeyManager(keystore_dir=keystore)
        assert km_broken.get_key(key_id) is None
        assert km_broken.storage_protection()["load_error_count"] >= 1

        # Corrupt master.key -> must fail-closed with KeyStorageError
        (keystore / "master.key").write_bytes(b"CORRUPTED_MASTER")
        with pytest.raises(KeyStorageError):
            KeyManager(keystore_dir=keystore)

        # Restore from backup -> historical ciphertext decrypts identically
        shutil.rmtree(keystore)
        shutil.copytree(backup_dir, keystore)
        km_restored = KeyManager(keystore_dir=keystore)
        restored_key = km_restored.get_key(key_id)
        assert restored_key == raw_key
        restored_cipher = AESGCMCipher(key=restored_key, key_id=key_id)
        assert restored_cipher.decrypt_json(env) == {"entity": "host:10.0.0.1", "score": 0.42}
