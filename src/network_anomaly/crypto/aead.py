"""AES-256-GCM authenticated encryption and envelope codec.

Implements Issue #117 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoError(Exception):
    """Base exception for cryptographic operations."""

    pass


class AuthenticationError(CryptoError):
    """Raised when authentication tag or ciphertext integrity check fails (tamper detected)."""

    pass


@dataclass
class CiphertextEnvelope:
    version: str
    key_id: str
    nonce_b64: str
    ciphertext_b64: str
    tag_b64: str
    aad_b64: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "key_id": self.key_id,
            "nonce_b64": self.nonce_b64,
            "ciphertext_b64": self.ciphertext_b64,
            "tag_b64": self.tag_b64,
            "aad_b64": self.aad_b64,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CiphertextEnvelope:
        return cls(
            version=data["version"],
            key_id=data["key_id"],
            nonce_b64=data["nonce_b64"],
            ciphertext_b64=data["ciphertext_b64"],
            tag_b64=data["tag_b64"],
            aad_b64=data.get("aad_b64"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> CiphertextEnvelope:
        return cls.from_dict(json.loads(json_str))


class AESGCMCipher:
    """AES-256-GCM authenticated cipher with 96-bit nonces and 128-bit auth tags."""

    ENVELOPE_VERSION = "aes-256-gcm-v1"
    KEY_LENGTH_BYTES = 32  # 256 bits
    NONCE_LENGTH_BYTES = 12  # 96 bits

    def __init__(self, key: bytes, key_id: str):
        if len(key) != self.KEY_LENGTH_BYTES:
            raise ValueError(
                f"AES-256-GCM key must be exactly {self.KEY_LENGTH_BYTES} bytes, got {len(key)}"
            )
        self._key = key
        self.key_id = key_id
        self._aesgcm = AESGCM(self._key)

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> CiphertextEnvelope:
        """Encrypt plaintext bytes and return a verified CiphertextEnvelope."""
        nonce = os.urandom(self.NONCE_LENGTH_BYTES)

        # AESGCM.encrypt appends 16-byte tag to the ciphertext
        raw_ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)

        ciphertext = raw_ciphertext[:-16]
        tag = raw_ciphertext[-16:]

        return CiphertextEnvelope(
            version=self.ENVELOPE_VERSION,
            key_id=self.key_id,
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            tag_b64=base64.b64encode(tag).decode("ascii"),
            aad_b64=base64.b64encode(aad).decode("ascii") if aad is not None else None,
        )

    def encrypt_json(self, data: Any, aad: Optional[bytes] = None) -> CiphertextEnvelope:
        """Serialize data to JSON and encrypt."""
        payload_bytes = json.dumps(data, ensure_ascii=False).encode("utf-8")
        return self.encrypt(payload_bytes, aad=aad)

    def decrypt(self, envelope: CiphertextEnvelope, expected_aad: Optional[bytes] = None) -> bytes:
        """Decrypt a CiphertextEnvelope and verify its authentication tag.

        Raises:
            AuthenticationError: If ciphertext, tag, or AAD has been tampered with or is invalid.
        """
        if envelope.version != self.ENVELOPE_VERSION:
            raise CryptoError(
                f"Unsupported envelope version '{envelope.version}', expected '{self.ENVELOPE_VERSION}'"
            )

        try:
            nonce = base64.b64decode(envelope.nonce_b64)
            ciphertext = base64.b64decode(envelope.ciphertext_b64)
            tag = base64.b64decode(envelope.tag_b64)
            combined_ciphertext = ciphertext + tag

            # Resolve AAD
            aad = expected_aad
            if aad is None and envelope.aad_b64 is not None:
                aad = base64.b64decode(envelope.aad_b64)

            plaintext = self._aesgcm.decrypt(nonce, combined_ciphertext, aad)
            return plaintext
        except InvalidTag as e:
            raise AuthenticationError(
                f"Decryption failed: integrity check or authentication tag invalid for key '{envelope.key_id}'"
            ) from e
        except Exception as e:
            if isinstance(e, AuthenticationError):
                raise
            raise CryptoError(f"Decryption failed: malformed envelope payload: {e}") from e

    def decrypt_json(
        self, envelope: CiphertextEnvelope, expected_aad: Optional[bytes] = None
    ) -> Any:
        """Decrypt and deserialize JSON payload."""
        plaintext_bytes = self.decrypt(envelope, expected_aad=expected_aad)
        return json.loads(plaintext_bytes.decode("utf-8"))
