"""
crypto/kem.py  — ML-KEM wrapper for Commey et al. (2025).
Used for client→server session key establishment (static, non-ratcheted).
"""
from __future__ import annotations
import hashlib, os, warnings
from dataclasses import dataclass

_kem_mod = None; _KEM_NAME = "toy_kem"; _PK_B = 32; _CT_B = 32
for _n, _p, _c in [("ml_kem_768",1184,1088),("kyber768",1184,1088),
                    ("ml_kem_512",800,768),("kyber512",800,768)]:
    try:
        import importlib; _kem_mod = importlib.import_module(f"pqcrypto.kem.{_n}")
        _KEM_NAME, _PK_B, _CT_B = _n, _p, _c; break
    except Exception: continue
if _kem_mod is None:
    warnings.warn("pqcrypto KEM unavailable — toy fallback.", RuntimeWarning)

KEM_BACKEND = _KEM_NAME; KEM_PUBLIC_KEY_BYTES = _PK_B; KEM_CIPHERTEXT_BYTES = _CT_B

@dataclass(frozen=True)
class KEMKeypair:
    public_key: bytes; secret_key: bytes

@dataclass(frozen=True)
class KEMEncapResult:
    ciphertext: bytes; shared_secret: bytes

def kem_keygen() -> KEMKeypair:
    if _kem_mod:
        pk, sk = _kem_mod.generate_keypair(); return KEMKeypair(bytes(pk), bytes(sk))
    sk = os.urandom(32)
    return KEMKeypair(hashlib.sha256(b"pk"+sk).digest(), sk)

def kem_encap(pk: bytes) -> KEMEncapResult:
    if _kem_mod:
        ct, ss = _kem_mod.encrypt(pk); return KEMEncapResult(bytes(ct), bytes(ss))
    ct = os.urandom(32)
    return KEMEncapResult(ct, hashlib.sha256(b"ss"+ct+pk).digest())

def kem_decap(ct: bytes, sk: bytes) -> bytes:
    if _kem_mod: return bytes(_kem_mod.decrypt(sk, ct))
    pk = hashlib.sha256(b"pk"+sk).digest()
    return hashlib.sha256(b"ss"+ct+pk).digest()
