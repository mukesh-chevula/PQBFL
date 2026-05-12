"""
crypto/kdf.py  — Key derivation for Kappala et al. (2026).
HKDF-SHA-256 for deriving symmetric keys from KEM shared secrets.
"""
from __future__ import annotations
import hashlib, hmac, struct


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    # Extract
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, "sha256").digest()
    # Expand
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + struct.pack("B", i), "sha256").digest()
        okm += t; i += 1
    return okm[:length]


def derive_session_key(shared_secret: bytes, sensor_id: int, packet_id: int) -> bytes:
    """Derive a per-packet AES-256 key from a KEM shared secret."""
    info = b"kappala2026:pkt" + struct.pack(">II", sensor_id, packet_id)
    return hkdf(shared_secret, b"", info, 32)


def derive_psk_key(pre_shared_key: bytes, sensor_id: int, packet_id: int) -> bytes:
    """Derive a per-packet key from the pre-shared symmetric key (AES_ONLY tier)."""
    info = b"kappala2026:psk" + struct.pack(">II", sensor_id, packet_id)
    return hkdf(pre_shared_key, b"", info, 32)
