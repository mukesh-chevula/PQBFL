"""
crypto/kem.py
ML-KEM (CRYSTALS-Kyber) wrapper for Zhang et al. (2025).

Key design from the paper:
  • Uses Kyber-768 (ML-KEM-768) for 192-bit classical / quantum security.
  • Each FL session establishes a fresh KEM keypair on the server side.
  • Clients encapsulate to the server's public key → shared secret.
  • The shared secret feeds a static ratchet chain (see ratchet.py).
  • Static threshold L_j = const — no threat-adaptive modulation.

Overhead note (reproduced from Zhang et al.):
  • Kyber-768 public key  : 1,184 bytes
  • Kyber-768 ciphertext  : 1,088 bytes
  • Compared to ECDH-256  :    64 bytes public key, 32 bytes shared secret
  • This 17–34× size increase translates to ~40-50% communication overhead
    in gradient rounds when keys are re-established every Lj rounds.
"""
from __future__ import annotations

import hashlib
import os
import warnings
from dataclasses import dataclass

# --- Attempt to load real pqcrypto Kyber / ML-KEM backend ---
_kem_mod = None
_KEM_BACKEND: str = "toy_kem"
_KEM_PK_BYTES: int = 32   # toy fallback sizes
_KEM_CT_BYTES: int = 32
_KEM_SS_BYTES: int = 32

try:
    from pqcrypto.kem import ml_kem_768 as _kem_mod  # type: ignore
    _KEM_BACKEND  = "ml_kem_768"
    _KEM_PK_BYTES = 1184
    _KEM_CT_BYTES = 1088
    _KEM_SS_BYTES = 32
except Exception:
    try:
        from pqcrypto.kem import kyber768 as _kem_mod  # type: ignore
        _KEM_BACKEND  = "kyber768"
        _KEM_PK_BYTES = 1184
        _KEM_CT_BYTES = 1088
        _KEM_SS_BYTES = 32
    except Exception:
        try:
            from pqcrypto.kem import ml_kem_512 as _kem_mod  # type: ignore
            _KEM_BACKEND  = "ml_kem_512"
            _KEM_PK_BYTES = 800
            _KEM_CT_BYTES = 768
            _KEM_SS_BYTES = 32
        except Exception:
            try:
                from pqcrypto.kem import kyber512 as _kem_mod  # type: ignore
                _KEM_BACKEND  = "kyber512"
                _KEM_PK_BYTES = 800
                _KEM_CT_BYTES = 768
                _KEM_SS_BYTES = 32
            except Exception:
                _kem_mod = None
                warnings.warn(
                    "pqcrypto Kyber/ML-KEM backend unavailable. "
                    "Falling back to toy KEM (NOT post-quantum secure). "
                    "Install pqcrypto on Python 3.10–3.12 for real security.",
                    RuntimeWarning,
                    stacklevel=2,
                )

KEM_BACKEND           = _KEM_BACKEND
KEM_PUBLIC_KEY_BYTES  = _KEM_PK_BYTES
KEM_CIPHERTEXT_BYTES  = _KEM_CT_BYTES
KEM_SHARED_SECRET_BYTES = _KEM_SS_BYTES


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KyberKeypair:
    """Server-side KEM keypair (public + secret)."""
    public_key: bytes
    secret_key: bytes

    @property
    def pk_size(self) -> int:
        return len(self.public_key)


@dataclass(frozen=True)
class KyberEncapResult:
    """Client-side encapsulation result: ciphertext + derived shared secret."""
    ciphertext: bytes
    shared_secret: bytes

    @property
    def wire_size(self) -> int:
        """Bytes transmitted over the network (ciphertext only)."""
        return len(self.ciphertext)


def kyber_keygen() -> KyberKeypair:
    """Generate a fresh ML-KEM keypair (server side)."""
    if _kem_mod is not None:
        pk, sk = _kem_mod.generate_keypair()
        return KyberKeypair(public_key=bytes(pk), secret_key=bytes(sk))

    # Toy fallback -----------------------------------------------------------
    sk = os.urandom(32)
    pk = _toy_pk(sk)
    return KyberKeypair(public_key=pk, secret_key=sk)


def kyber_encap(public_key: bytes) -> KyberEncapResult:
    """Client encapsulates to server public key → (ciphertext, shared_secret)."""
    if _kem_mod is not None:
        ct, ss = _kem_mod.encrypt(public_key)
        return KyberEncapResult(ciphertext=bytes(ct), shared_secret=bytes(ss))

    # Toy fallback -----------------------------------------------------------
    ct = os.urandom(32)
    ss = _toy_ss(ct, public_key)
    return KyberEncapResult(ciphertext=ct, shared_secret=ss)


def kyber_decap(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Server decapsulates client ciphertext → shared_secret."""
    if _kem_mod is not None:
        ss = _kem_mod.decrypt(secret_key, ciphertext)
        return bytes(ss)

    # Toy fallback -----------------------------------------------------------
    pk = _toy_pk(secret_key)
    return _toy_ss(ciphertext, pk)


# ---------------------------------------------------------------------------
# Toy fallback helpers (NOT secure — demo only)
# ---------------------------------------------------------------------------

def _toy_pk(sk: bytes) -> bytes:
    return hashlib.sha256(b"zhang2025-toy-pk" + sk).digest()


def _toy_ss(ct: bytes, pk: bytes) -> bytes:
    return hashlib.sha256(b"zhang2025-toy-ss" + ct + pk).digest()
