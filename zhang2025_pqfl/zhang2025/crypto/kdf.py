"""
crypto/kdf.py
Key Derivation Functions used by Zhang et al. (2025).

Implements the two-stage HKDF-SHA-256 construction described in the paper:
  • extract(salt, IKM) → PRK      via HMAC-SHA256
  • expand(PRK, label, length)    via HKDF-Expand

Label strings are domain-separated per key type to prevent cross-protocol
confusion, following RFC 5869 best practice.
"""
from __future__ import annotations

import hashlib
import hmac
import struct


_HASH = "sha256"
_HASH_LEN = 32  # bytes


# ---------------------------------------------------------------------------
# Low-level HKDF primitives
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)."""
    if not salt:
        salt = b"\x00" * _HASH_LEN
    return hmac.new(salt, ikm, _HASH).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: OKM = T(1) || T(2) || ... truncated to `length` bytes."""
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + struct.pack("B", counter), _HASH).digest()
        okm += t
        counter += 1
    return okm[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """Full HKDF-SHA-256 (extract + expand)."""
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, info, length)


# ---------------------------------------------------------------------------
# Protocol-level key derivation (Zhang et al. §III)
# ---------------------------------------------------------------------------

def derive_root_key(shared_secret_kem: bytes, session_salt: bytes | None = None) -> bytes:
    """
    Derive the session root key RK_j from the KEM shared secret.

    Zhang et al. use a single KEM (no ECDH hybrid), so:
        PRK = HKDF-Extract(session_salt, SS_kem)
        RK_j = HKDF-Expand(PRK, "zhang2025:RK", 32)

    The static nature of RK_j per session is the key distinction from
    adaptive PQBFL — it never changes until a full KEM round restarts.
    """
    salt = session_salt if session_salt else b"\x00" * 32
    return hkdf(salt, shared_secret_kem, b"zhang2025:RK", 32)


def derive_chain_key(root_key: bytes, round_index: int) -> bytes:
    """
    Derive symmetric chain key CK_{i,j} for training round i.

    CK_{i,j} = HKDF-Expand(RK_j, "zhang2025:CK" || i, 32)

    This is the *static* ratchet step: no asymmetric refresh within
    the session window of L_j rounds.
    """
    info = b"zhang2025:CK" + round_index.to_bytes(4, "big")
    return hkdf(root_key, root_key, info, 32)


def derive_message_key(chain_key: bytes, round_index: int) -> bytes:
    """
    Derive per-round AES-256-GCM encryption key MK_{i,j}.

    MK_{i,j} = HKDF-Expand(CK_{i,j}, "zhang2025:MK" || i, 32)
    """
    info = b"zhang2025:MK" + round_index.to_bytes(4, "big")
    return hkdf(chain_key, chain_key, info, 32)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Convenience: bare HMAC-SHA256."""
    return hmac.new(key, data, _HASH).digest()
