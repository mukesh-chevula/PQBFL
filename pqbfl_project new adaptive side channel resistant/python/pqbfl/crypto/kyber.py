from __future__ import annotations

import os
import warnings
from dataclasses import dataclass

import numpy as np
from pqbfl.crypto.leakage import mask_bytes, simulate_trace, apply_defense

_kem = None
_kem_name = ""

try:  # pragma: no cover
    # Newer pqcrypto versions expose ML-KEM under ml_kem_*.
    from pqcrypto.kem import ml_kem_512 as _kem  # type: ignore[assignment]

    _kem_name = "ml_kem_512"
except Exception:  # noqa: BLE001 - we want to fall back on any import/load failure
    try:  # pragma: no cover
        # Older pqcrypto versions expose Kyber under kyber*.
        from pqcrypto.kem import kyber512 as _kem  # type: ignore[assignment]

        _kem_name = "kyber512"
    except Exception:  # noqa: BLE001
        _kem = None
        _kem_name = "toy_kem"
        warnings.warn(
            "pqcrypto Kyber/ML-KEM backend could not be loaded (likely due to an unsupported Python version/wheel). "
            "Falling back to a toy KEM so the demo can run. For real PQ security, use a supported Python version "
            "(e.g. 3.10–3.12) and reinstall pqcrypto.",
            RuntimeWarning,
            stacklevel=2,
        )


@dataclass(frozen=True)
class KyberKeypair:
    public_key: bytes
    secret_key: bytes


def kyber_keygen() -> KyberKeypair:
    if _kem is not None:
        pk, sk = _kem.generate_keypair()
        return KyberKeypair(public_key=pk, secret_key=sk)

    # Toy fallback: NOT post-quantum secure.
    sk = os.urandom(32)
    pk = _toy_public_from_secret(sk)
    return KyberKeypair(public_key=pk, secret_key=sk)


@dataclass(frozen=True)
class KyberEncapResult:
    ciphertext: bytes
    shared_secret: bytes


def kyber_encap(public_key: bytes, defense_mode="none") -> tuple[KyberEncapResult, np.ndarray]:
    traces = []
    
    # simulate leakage from public operations
    trace = simulate_trace(public_key)
    trace = apply_defense(trace, defense_mode)
    traces.append(trace)

    if _kem is not None:
        ct, ss = _kem.encrypt(public_key)
    else:
        # Toy fallback: ciphertext is random; SS is hash(ct || pk).
        ct = os.urandom(32)
        ss = _toy_shared_secret(ct, public_key)
        
    return KyberEncapResult(ciphertext=ct, shared_secret=ss), np.array(traces)


def kyber_decap(ciphertext: bytes, secret_key: bytes, defense_mode="none") -> tuple[bytes, np.ndarray]:
    traces = []
    
    # ---- MASK SECRET KEY ----
    s1, s2 = mask_bytes(secret_key)
    
    # ---- LEAKAGE FROM SHARES ----
    trace1 = simulate_trace(s1.tobytes())
    trace2 = simulate_trace(s2.tobytes())
    
    combined_trace = trace1 + trace2
    
    # ---- APPLY DEFENSE ----
    defended_trace = apply_defense(combined_trace, defense_mode)
    
    traces.append(defended_trace)
    
    # ---- ORIGINAL DECAP ----
    if _kem is not None:
        ss = _kem.decrypt(secret_key, ciphertext)
    else:
        # Toy fallback: recompute SS from ct and derived public key.
        pk = _toy_public_from_secret(secret_key)
        ss = _toy_shared_secret(ciphertext, pk)
        
    return ss, np.array(traces)


def _toy_public_from_secret(secret_key: bytes) -> bytes:
    # Deterministic "public key" derivation for the toy fallback.
    from pqbfl.utils import sha256

    return sha256(b"toy-kem-pk" + secret_key)


def _toy_shared_secret(ciphertext: bytes, public_key: bytes) -> bytes:
    from pqbfl.utils import sha256

    return sha256(b"toy-kem-ss" + ciphertext + public_key)

def get_kem_backend_name() -> str:
    return _kem_name
