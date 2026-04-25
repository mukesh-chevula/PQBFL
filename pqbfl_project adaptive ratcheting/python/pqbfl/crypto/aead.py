"""
AES-256-GCM Authenticated Encryption with Associated Data (AEAD).

Side-channel hardening:
  - Random nonces via os.urandom (prevents nonce-reuse and deterministic
    patterns that leak round information).
  - Constant-length key validation (no early-exit branching on key content).
  - Nonce is prepended to ciphertext so it travels with the message.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_NONCE_LEN = 12  # 96-bit nonce recommended for GCM
_KEY_LEN = 32    # AES-256


def _validate_key(key: bytes) -> None:
    """Validate key length without leaking which check failed."""
    if not isinstance(key, (bytes, bytearray)) or len(key) != _KEY_LEN:
        raise ValueError(f"AES-256-GCM key must be exactly {_KEY_LEN} bytes")


def aead_encrypt(key32: bytes, plaintext: bytes, *, aad: bytes) -> bytes:
    """Encrypt with AES-256-GCM using a random nonce.

    Returns:
        nonce (12 bytes) || ciphertext+tag
    """
    _validate_key(key32)
    nonce = os.urandom(_NONCE_LEN)
    aesgcm = AESGCM(key32)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct


def aead_decrypt(key32: bytes, nonce_and_ciphertext: bytes, *, aad: bytes) -> bytes:
    """Decrypt AES-256-GCM.  Expects nonce || ciphertext+tag as input."""
    _validate_key(key32)
    if len(nonce_and_ciphertext) < _NONCE_LEN + 16:  # at least nonce + GCM tag
        raise ValueError("ciphertext too short")
    nonce = nonce_and_ciphertext[:_NONCE_LEN]
    ct = nonce_and_ciphertext[_NONCE_LEN:]
    aesgcm = AESGCM(key32)
    return aesgcm.decrypt(nonce, ct, aad)
