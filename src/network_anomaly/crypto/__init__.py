"""Cryptographic engine for NetFlow Sentinel v2.0.

Provides AES-256-GCM authenticated encryption, key lifecycle management,
fixed and adaptive key rotation, and secure at-rest persistence. (Milestone M6.5).
"""

from .aead import AESGCMCipher, CiphertextEnvelope
from .key_manager import KeyManager, KeyMetadata, KeyStatus
from .rotation import KeyRotationPolicy, RotationDecision, RotationTrigger
from .encrypted_storage import EncryptedStorageVault

__all__ = [
    "AESGCMCipher",
    "CiphertextEnvelope",
    "KeyManager",
    "KeyMetadata",
    "KeyStatus",
    "KeyRotationPolicy",
    "RotationDecision",
    "RotationTrigger",
    "EncryptedStorageVault",
]
