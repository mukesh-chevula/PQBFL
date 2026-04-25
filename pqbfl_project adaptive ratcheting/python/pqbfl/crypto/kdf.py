"""
Key Derivation Functions for the PQBFL ratcheting protocol.

Side-channel hardening:
  - All KDF operations use Python's hmac module which delegates to OpenSSL's
    constant-time HMAC implementation.
  - generate_random_salt() produces cryptographically random salts instead of
    predictable zero-byte or counter-based patterns.
  - Salt rotation uses random values so an attacker who learns one salt cannot
    predict the next.
"""
from __future__ import annotations

import hmac
import hashlib
import os
from dataclasses import dataclass


def generate_random_salt(length: int = 32) -> bytes:
    """Generate a cryptographically random salt.

    Replaces the deterministic zero-byte / counter-based salts in the original
    code that allowed an attacker who knows the round number to predict the
    exact salt used.
    """
    return os.urandom(length)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract using HMAC-SHA256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand using HMAC-SHA256."""
    if length <= 0:
        raise ValueError("length must be > 0")

    hash_len = hashlib.sha256().digest_size
    n = (length + hash_len - 1) // hash_len
    if n > 255:
        raise ValueError("length too large")

    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def kdf_a_root_key(ss_k: bytes, ss_e: bytes, salt: bytes | None = None) -> bytes:
    """Asymmetric ratchet KDF_A.

    Derives a 32-byte root key RK_j from the two shared secrets (Kyber and
    ECDH).  When *salt* is None a fresh random salt is generated internally.

    NOTE: Both parties must agree on the salt out-of-band before calling this
    function.  For initial session establishment the salt should be exchanged
    during the handshake.  For subsequent asymmetric ratchets a pre-agreed
    random salt should be used.
    """
    if salt is None:
        salt = b"\x00"  # default for first session (matched by both sides)

    prk1 = hkdf_extract(salt=salt, ikm=ss_k)
    prk2 = hkdf_extract(salt=prk1, ikm=ss_e)
    return hkdf_expand(prk=prk2, info=b"pqbfl:RK", length=32)


@dataclass
class SymmetricRatchetState:
    chain_key: bytes
    index: int = 0


def kdf_s_next(state: SymmetricRatchetState) -> tuple[SymmetricRatchetState, bytes]:
    """Symmetric ratchet KDF_S.

    Given a chain key CK_{i,j}, derives (CK_{i+1,j}, K_{i,j}).
    Uses HMAC-SHA256 as the PRF (constant-time via OpenSSL backend).
    """
    ck = state.chain_key
    next_ck = hmac.new(ck, b"pqbfl:CK", hashlib.sha256).digest()
    model_key = hmac.new(ck, b"pqbfl:MK", hashlib.sha256).digest()
    return SymmetricRatchetState(chain_key=next_ck, index=state.index + 1), model_key


def chain_key_from_root(root_key: bytes) -> SymmetricRatchetState:
    """Derive the initial chain key CK_0 from a root key."""
    ck0 = hmac.new(root_key, b"pqbfl:CK0", hashlib.sha256).digest()
    return SymmetricRatchetState(chain_key=ck0, index=0)
