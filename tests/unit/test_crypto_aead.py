"""Unit tests for AES-256-GCM cipher and envelope codec (Issue #117)."""

import base64
import os

import pytest

from network_anomaly.crypto.aead import (
    AESGCMCipher,
    AuthenticationError,
)


def test_aead_round_trip_bytes():
    key = os.urandom(32)
    cipher = AESGCMCipher(key, key_id="key-001")
    plaintext = b"Secret network anomaly payload 123456789"
    aad = b"context:flow-101"

    envelope = cipher.encrypt(plaintext, aad=aad)
    assert envelope.key_id == "key-001"
    assert envelope.version == "aes-256-gcm-v1"
    assert envelope.ciphertext_b64 is not None

    decrypted = cipher.decrypt(envelope, expected_aad=aad)
    assert decrypted == plaintext


def test_aead_round_trip_json():
    key = os.urandom(32)
    cipher = AESGCMCipher(key, key_id="key-002")
    payload = {"entity": "host-1", "vector": [0.1, 0.2, 0.3], "alert": True}

    envelope = cipher.encrypt_json(payload)
    decrypted = cipher.decrypt_json(envelope)
    assert decrypted == payload


def test_tamper_detection_ciphertext():
    """Modifying 1 bit of ciphertext must raise AuthenticationError fail-closed."""
    key = os.urandom(32)
    cipher = AESGCMCipher(key, key_id="key-003")
    envelope = cipher.encrypt(b"Immutable network payload")

    # Flip 1 bit in ciphertext
    raw_ct = bytearray(base64.b64decode(envelope.ciphertext_b64))
    raw_ct[0] ^= 0x01
    envelope.ciphertext_b64 = base64.b64encode(raw_ct).decode("ascii")

    with pytest.raises(AuthenticationError):
        cipher.decrypt(envelope)


def test_tamper_detection_tag():
    """Modifying 1 bit of tag must raise AuthenticationError."""
    key = os.urandom(32)
    cipher = AESGCMCipher(key, key_id="key-004")
    envelope = cipher.encrypt(b"Payload with tag")

    # Flip 1 bit in tag
    raw_tag = bytearray(base64.b64decode(envelope.tag_b64))
    raw_tag[0] ^= 0x01
    envelope.tag_b64 = base64.b64encode(raw_tag).decode("ascii")

    with pytest.raises(AuthenticationError):
        cipher.decrypt(envelope)


def test_aad_mismatch():
    """AAD mismatch must fail authentication."""
    key = os.urandom(32)
    cipher = AESGCMCipher(key, key_id="key-005")
    envelope = cipher.encrypt(b"Payload", aad=b"correct-aad")

    with pytest.raises(AuthenticationError):
        cipher.decrypt(envelope, expected_aad=b"wrong-aad")


def test_invalid_key_length():
    with pytest.raises(ValueError, match="must be exactly 32 bytes"):
        AESGCMCipher(os.urandom(16), key_id="bad-key")
