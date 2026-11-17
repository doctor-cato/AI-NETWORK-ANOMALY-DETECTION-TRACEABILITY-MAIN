"""Comprehensive cryptographic integrity tests (Issue #124).

Covers:
- Nonce uniqueness under repeated encryption
- Key isolation across domains
- Key rotation (fixed, adaptive, cooldown, rate-limit)
- Historical key decryption across multiple rotations
- Zero plaintext at-rest verification
- Protection against unauthorized key revocation
"""

from pathlib import Path
import pytest
from network_anomaly.crypto.aead import AESGCMCipher, AuthenticationError
from network_anomaly.crypto.encrypted_storage import EncryptedStorageVault
from network_anomaly.crypto.key_manager import KeyManager, KeyStatus
from network_anomaly.crypto.rotation import (
    KeyRotationPolicy,
    RotationDecision,
    RotationTrigger,
)


def test_nonce_uniqueness():
    """Verify that 1,000 encryptions produce 1,000 distinct nonces."""
    key = b"\x01" * 32
    cipher = AESGCMCipher(key, key_id="k-nonce")
    nonces = set()
    for _ in range(1000):
        env = cipher.encrypt(b"Same payload")
        assert env.nonce_b64 not in nonces
        nonces.add(env.nonce_b64)
    assert len(nonces) == 1000


def test_key_isolation_across_domains(tmp_path: Path):
    """Keys derived or generated for domain A cannot decrypt domain B."""
    km = KeyManager(keystore_dir=tmp_path / "keys")
    k_beh_id, k_beh_raw = km.get_active_key(domain="behavioral")
    k_evi_id, k_evi_raw = km.get_active_key(domain="evidence")

    assert k_beh_id != k_evi_id
    assert k_beh_raw != k_evi_raw

    cipher_beh = AESGCMCipher(k_beh_raw, key_id=k_beh_id)
    cipher_evi = AESGCMCipher(k_evi_raw, key_id=k_evi_id)

    env_beh = cipher_beh.encrypt(b"Behavioral vector bytes")

    # Attempting to decrypt with evidence key must fail
    with pytest.raises(AuthenticationError):
        cipher_evi.decrypt(env_beh)


def test_encrypted_storage_zero_plaintext_at_rest(tmp_path: Path):
    """Verify that when encrypted=True, NO plaintext vector or string appears in SQLite."""
    km = KeyManager(keystore_dir=tmp_path / "keys")
    db_path = tmp_path / "vault_test.db"
    vault = EncryptedStorageVault(km, db_path)

    secret_vector = [0.12345, 0.6789, 0.9999, 0.5555]
    vec_id = vault.store_behavioral_vector(
        entity_id="host-sensitive-101",
        window_start="2026-11-17T12:00:00Z",
        window_end="2026-11-17T12:15:00Z",
        vector=secret_vector,
        encrypt=True,
    )

    # 1. Read directly from DB file bytes and SQLite columns
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute(
        "SELECT is_encrypted, vector_json, ciphertext, nonce, tag FROM behavioral_vectors WHERE vector_id = ?;",
        (vec_id,),
    )
    row = cursor.fetchone()
    conn.close()

    assert row[0] == 1
    assert row[1] is None  # vector_json is strictly NULL!
    assert row[2] is not None  # ciphertext is binary
    assert row[3] is not None  # nonce is binary
    assert row[4] is not None  # tag is binary

    # Raw DB file should not contain the exact float string
    db_raw = db_path.read_bytes()
    assert b"0.12345" not in db_raw

    # 2. Decrypt via vault should reproduce exact vector
    loaded = vault.load_behavioral_vector(vec_id)
    assert loaded is not None
    assert len(loaded) == 4
    for a, b in zip(secret_vector, loaded):
        assert pytest.approx(a, 1e-5) == b


def test_key_rotation_cooldown_and_rate_limit(tmp_path: Path):
    """Verify rotation guardrails: cooldown and rate limiting."""
    km = KeyManager(keystore_dir=tmp_path / "keys")
    db_path = tmp_path / "rot_test.db"
    policy = KeyRotationPolicy(
        km,
        db_path=db_path,
        cooldown_seconds=10,  # 10s cooldown
        max_rotations_per_hour=3,  # Max 3
    )

    # First rotation: EXECUTED
    dec1, key1 = policy.execute_rotation(trigger=RotationTrigger.MANUAL_ADMIN)
    assert dec1 == RotationDecision.EXECUTED
    assert key1 is not None

    # Immediate second rotation: REJECTED by cooldown
    dec2, msg2 = policy.execute_rotation(trigger=RotationTrigger.MANUAL_ADMIN)
    assert dec2 == RotationDecision.REJECTED_COOLDOWN
    assert "cooldown active" in msg2.lower()

    # Fast forward cooldown
    policy._last_rotation_time["general"] -= 15.0

    # Third rotation: EXECUTED
    dec3, key3 = policy.execute_rotation(trigger=RotationTrigger.MANUAL_ADMIN)
    assert dec3 == RotationDecision.EXECUTED
    assert key3 != key1

    # Fast forward cooldown
    policy._last_rotation_time["general"] -= 15.0

    # Fourth rotation: EXECUTED (hits 3 in hour)
    dec4, key4 = policy.execute_rotation(trigger=RotationTrigger.MANUAL_ADMIN)
    assert dec4 == RotationDecision.EXECUTED

    # Fast forward cooldown
    policy._last_rotation_time["general"] -= 15.0

    # Fifth rotation: REJECTED by rate limit
    dec5, msg5 = policy.execute_rotation(trigger=RotationTrigger.MANUAL_ADMIN)
    assert dec5 == RotationDecision.REJECTED_RATE_LIMIT
    assert "rate limit reached" in msg5.lower()


def test_adaptive_rotation_triggered_by_risk(tmp_path: Path):
    km = KeyManager(keystore_dir=tmp_path / "keys")
    policy = KeyRotationPolicy(km, cooldown_seconds=0, adaptive_risk_threshold=85.0)

    # Risk 70: skipped
    dec_low, _ = policy.evaluate_adaptive_rotation(risk_score=70.0)
    assert dec_low == RotationDecision.SKIPPED_BELOW_THRESHOLD

    # Risk 92: executed
    dec_high, key_id = policy.evaluate_adaptive_rotation(risk_score=92.0, context={"event_id": "evt-attack-01"})
    assert dec_high == RotationDecision.EXECUTED
    assert key_id is not None


def test_historical_decryption_across_ten_rotations(tmp_path: Path):
    """Verify that records encrypted across 10 rotation cycles remain completely decryptable."""
    km = KeyManager(keystore_dir=tmp_path / "keys")
    db_path = tmp_path / "hist_test.db"
    vault = EncryptedStorageVault(km, db_path)
    policy = KeyRotationPolicy(km, cooldown_seconds=0)

    records = []
    for i in range(10):
        # Rotate key
        policy.execute_rotation(trigger=RotationTrigger.FIXED_SCHEDULE)
        vec = [float(i), float(i * 2), float(i * 3)]
        vid = vault.store_behavioral_vector(
            entity_id=f"host-{i}",
            window_start=f"2026-11-17T{i:02d}:00:00Z",
            window_end=f"2026-11-17T{i:02d}:15:00Z",
            vector=vec,
            encrypt=True,
        )
        records.append((vid, vec))

    # Decrypt all historical vectors
    for vid, expected_vec in records:
        decrypted = vault.load_behavioral_vector(vid)
        assert decrypted is not None
        for a, b in zip(expected_vec, decrypted):
            assert pytest.approx(a) == b


def test_unauthorized_key_revocation_denied(tmp_path: Path):
    """Revoking a key with active references must be rejected."""
    km = KeyManager(keystore_dir=tmp_path / "keys")
    key_id, _ = km.get_active_key(domain="general")

    with pytest.raises(ValueError, match="Cannot revoke key.*active encrypted references"):
        km.revoke_key(key_id, active_references=5)

    # Revoking key with 0 references succeeds
    res = km.revoke_key(key_id, active_references=0)
    assert res is True
    meta = km.get_metadata(key_id)
    assert meta.status == KeyStatus.REVOKED
