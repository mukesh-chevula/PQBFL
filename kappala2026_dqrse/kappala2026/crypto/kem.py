"""
crypto/kem.py  — ML-KEM (Kyber) wrapper for Kappala et al. (2026).

Kappala et al. use Kyber for key encapsulation on critical-tier packets only.
The variant used in the paper is Kyber-512 (targeting NIST Level 1 security),
appropriate for resource-constrained agricultural sensor hardware.

Wire costs:
  Kyber-512 public key  :  800 bytes
  Kyber-512 ciphertext  :  768 bytes
  Compared to Kyber-768 : 1184 / 1088 bytes (Zhang et al.)
  The smaller variant is a deliberate hardware-resource trade-off.
"""
from __future__ import annotations

import hashlib
import os
import warnings
from dataclasses import dataclass

_kem_mod = None
_KEM_BACKEND = "toy_kem"
_KEM_PK_BYTES = 32
_KEM_CT_BYTES = 32
_KEM_SS_BYTES = 32

try:
    from pqcrypto.kem import ml_kem_512 as _kem_mod  # type: ignore
    _KEM_BACKEND, _KEM_PK_BYTES, _KEM_CT_BYTES = "ml_kem_512", 800, 768
except Exception:
    try:
        from pqcrypto.kem import kyber512 as _kem_mod  # type: ignore
        _KEM_BACKEND, _KEM_PK_BYTES, _KEM_CT_BYTES = "kyber512", 800, 768
    except Exception:
        try:
            from pqcrypto.kem import ml_kem_768 as _kem_mod  # type: ignore
            _KEM_BACKEND, _KEM_PK_BYTES, _KEM_CT_BYTES = "ml_kem_768", 1184, 1088
        except Exception:
            warnings.warn(
                "pqcrypto unavailable — using toy KEM fallback (demo only).",
                RuntimeWarning, stacklevel=2
            )

KEM_BACKEND           = _KEM_BACKEND
KEM_PUBLIC_KEY_BYTES  = _KEM_PK_BYTES
KEM_CIPHERTEXT_BYTES  = _KEM_CT_BYTES
KEM_SHARED_SECRET_BYTES = 32


@dataclass(frozen=True)
class KEMKeypair:
    public_key: bytes
    secret_key: bytes


@dataclass(frozen=True)
class KEMEncapResult:
    ciphertext:    bytes
    shared_secret: bytes

    @property
    def wire_size(self) -> int:
        return len(self.ciphertext)


def kem_keygen() -> KEMKeypair:
    if _kem_mod is not None:
        pk, sk = _kem_mod.generate_keypair()
        return KEMKeypair(public_key=bytes(pk), secret_key=bytes(sk))
    sk = os.urandom(32)
    return KEMKeypair(public_key=_toy_pk(sk), secret_key=sk)


def kem_encap(public_key: bytes) -> KEMEncapResult:
    if _kem_mod is not None:
        ct, ss = _kem_mod.encrypt(public_key)
        return KEMEncapResult(ciphertext=bytes(ct), shared_secret=bytes(ss))
    ct = os.urandom(32)
    return KEMEncapResult(ciphertext=ct, shared_secret=_toy_ss(ct, public_key))


def kem_decap(ciphertext: bytes, secret_key: bytes) -> bytes:
    if _kem_mod is not None:
        return bytes(_kem_mod.decrypt(secret_key, ciphertext))
    return _toy_ss(ciphertext, _toy_pk(secret_key))


def _toy_pk(sk: bytes) -> bytes:
    return hashlib.sha256(b"kappala2026-pk" + sk).digest()

def _toy_ss(ct: bytes, pk: bytes) -> bytes:
    return hashlib.sha256(b"kappala2026-ss" + ct + pk).digest()
