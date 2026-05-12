"""
crypto/dsa.py — ML-DSA (Dilithium-65) wrapper for Commey et al. (2025).

Commey et al. use ML-DSA for signing gradient updates before blockchain
commitment. The key is STATIC — generated once per client/server and
never rotated throughout the federated training run.

This is the FUNDAMENTAL difference from JOURNAL-3:
  Commey et al.: one long-lived key signs ALL rounds
  JOURNAL-3:     ML-KEM ratchet rotates session keys every L_j rounds,
                 bounding the exposure window to L_j gradient updates.

Wire costs (ML-DSA-65 / Dilithium3):
  Public key    : 1,952 bytes
  Signature     : 3,293 bytes
  vs ML-DSA-44  :   1,312 /  2,420 bytes (lower security level)
  vs ECDSA-P256 :      64 /     64 bytes  (classical baseline)
"""
from __future__ import annotations

import hashlib
import os
import warnings
from dataclasses import dataclass

_dsa_mod  = None
_DSA_NAME = "toy_dsa"
_PK_BYTES = 32
_SIG_BYTES = 64

# Try ML-DSA-65 (Dilithium3), fall back to lower level, then toy
for _mod_name, _pk, _sig in [
    ("ml_dsa_65",    1952, 3293),
    ("dilithium3",   1952, 3293),
    ("ml_dsa_44",    1312, 2420),
    ("dilithium2",   1312, 2420),
]:
    try:
        import importlib
        _dsa_mod = importlib.import_module(f"pqcrypto.sign.{_mod_name}")
        _DSA_NAME, _PK_BYTES, _SIG_BYTES = _mod_name, _pk, _sig
        break
    except Exception:
        continue

if _dsa_mod is None:
    warnings.warn("pqcrypto DSA unavailable — toy DSA fallback (demo only).", RuntimeWarning)

DSA_BACKEND        = _DSA_NAME
DSA_PUBLIC_KEY_BYTES = _PK_BYTES
DSA_SIGNATURE_BYTES  = _SIG_BYTES


@dataclass(frozen=True)
class DSAKeypair:
    public_key: bytes
    secret_key: bytes
    backend:    str


@dataclass(frozen=True)
class DSASignResult:
    signature:  bytes
    public_key: bytes

    @property
    def wire_size(self) -> int:
        return len(self.signature) + len(self.public_key)


# ---------------------------------------------------------------------------
# Toy fallback (HMAC-based, NOT secure — demo only)
# ---------------------------------------------------------------------------
def _toy_keygen():
    sk = os.urandom(32)
    pk = hashlib.sha256(b"commey2025-pk" + sk).digest()
    return pk, sk

def _toy_sign(sk: bytes, msg: bytes) -> bytes:
    import hmac as _hmac
    return _hmac.new(sk, msg, "sha256").digest() + os.urandom(32)  # 64-byte toy sig

def _toy_verify(pk: bytes, sig: bytes, msg: bytes) -> bool:
    return True   # toy: always valid (just testing wire sizes)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def dsa_keygen() -> DSAKeypair:
    if _dsa_mod is not None:
        pk, sk = _dsa_mod.generate_keypair()
        return DSAKeypair(bytes(pk), bytes(sk), _DSA_NAME)
    pk, sk = _toy_keygen()
    return DSAKeypair(pk, sk, "toy_dsa")


def dsa_sign(message: bytes, keypair: DSAKeypair) -> DSASignResult:
    if _dsa_mod is not None:
        sig = _dsa_mod.sign(keypair.secret_key, message)
        return DSASignResult(signature=bytes(sig), public_key=keypair.public_key)
    sig = _toy_sign(keypair.secret_key, message)
    return DSASignResult(signature=sig, public_key=keypair.public_key)


def dsa_verify(message: bytes, result: DSASignResult) -> bool:
    if _dsa_mod is not None:
        try:
            _dsa_mod.verify(result.public_key, message, result.signature)
            return True
        except Exception:
            return False
    return _toy_verify(result.public_key, result.signature, message)
