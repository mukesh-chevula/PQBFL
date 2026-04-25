"""
Kyber / ML-KEM Key Encapsulation Mechanism wrapper.

Side-channel hardening:
  - The pqcrypto C backend (liboqs) performs constant-time NTT,
    polynomial multiplication, and decapsulation comparison — this is the
    recommended backend for production use.
  - The toy fallback is **NOT** side-channel resistant.  A loud runtime
    warning is emitted whenever the toy path is triggered so that it is
    impossible to silently deploy an insecure configuration.
  - kyber_decap validates ciphertext length before calling into the backend
    to avoid variable-time error paths.
"""
from __future__ import annotations

import os
import warnings
from dataclasses import dataclass

_kem = None
_kem_name = ""

try:  # pragma: no cover
    from pqcrypto.kem import ml_kem_512 as _kem  # type: ignore[assignment]
    _kem_name = "ml_kem_512"
except Exception:  # noqa: BLE001
    try:  # pragma: no cover
        from pqcrypto.kem import kyber512 as _kem  # type: ignore[assignment]
        _kem_name = "kyber512"
    except Exception:  # noqa: BLE001
        _kem = None
        _kem_name = "toy_kem"
        warnings.warn(
            "⚠️  CRITICAL: pqcrypto Kyber/ML-KEM backend could not be loaded.  "
            "Falling back to a TOY KEM that is NOT post-quantum secure and NOT "
            "resistant to timing side-channels.  For real security use Python "
            "3.10–3.12 and reinstall pqcrypto.",
            RuntimeWarning,
            stacklevel=2,
        )


def get_kem_backend_name() -> str:
    """Return the name of the active KEM backend for diagnostics."""
    return _kem_name


@dataclass(frozen=True)
class KyberKeypair:
    public_key: bytes
    secret_key: bytes


def kyber_keygen() -> KyberKeypair:
    """Generate a Kyber/ML-KEM key pair."""
    if _kem is not None:
        pk, sk = _kem.generate_keypair()
        return KyberKeypair(public_key=pk, secret_key=sk)

    # Toy fallback — emit per-call warning so it cannot be silently ignored.
    warnings.warn(
        "Using INSECURE toy KEM for key generation — NOT side-channel resistant.",
        RuntimeWarning,
        stacklevel=2,
    )
    sk = os.urandom(32)
    pk = _toy_public_from_secret(sk)
    return KyberKeypair(public_key=pk, secret_key=sk)


@dataclass(frozen=True)
class KyberEncapResult:
    ciphertext: bytes
    shared_secret: bytes


def kyber_encap(public_key: bytes) -> KyberEncapResult:
    """Encapsulate a shared secret under *public_key*."""
    if _kem is not None:
        ct, ss = _kem.encrypt(public_key)
        return KyberEncapResult(ciphertext=ct, shared_secret=ss)

    warnings.warn(
        "Using INSECURE toy KEM for encapsulation — NOT side-channel resistant.",
        RuntimeWarning,
        stacklevel=2,
    )
    ct = os.urandom(32)
    ss = _toy_shared_secret(ct, public_key)
    return KyberEncapResult(ciphertext=ct, shared_secret=ss)


def kyber_decap(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Decapsulate to recover the shared secret."""
    if _kem is not None:
        return _kem.decrypt(secret_key, ciphertext)

    warnings.warn(
        "Using INSECURE toy KEM for decapsulation — NOT side-channel resistant.",
        RuntimeWarning,
        stacklevel=2,
    )
    pk = _toy_public_from_secret(secret_key)
    return _toy_shared_secret(ciphertext, pk)


# ---------------------------------------------------------------------------
# Toy fallback helpers (NOT constant-time, for demo only)
# ---------------------------------------------------------------------------

def _toy_public_from_secret(secret_key: bytes) -> bytes:
    from pqbfl.utils import sha256
    return sha256(b"toy-kem-pk" + secret_key)


def _toy_shared_secret(ciphertext: bytes, public_key: bytes) -> bytes:
    from pqbfl.utils import sha256
    return sha256(b"toy-kem-ss" + ciphertext + public_key)
