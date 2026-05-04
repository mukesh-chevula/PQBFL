from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

import numpy as np
from pqbfl.crypto.leakage import mask_bytes, simulate_trace, apply_defense


@dataclass(frozen=True)
class Ed25519Keypair:
    private_key: ed25519.Ed25519PrivateKey
    public_key_bytes: bytes


def ed25519_keygen() -> Ed25519Keypair:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return Ed25519Keypair(private_key=private_key, public_key_bytes=public_key_bytes)


def ed25519_sign(private_key: ed25519.Ed25519PrivateKey, message: bytes, defense_mode="none") -> tuple[bytes, np.ndarray]:
    traces = []
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    s1, s2 = mask_bytes(priv_bytes)
    trace1 = simulate_trace(s1.tobytes())
    trace2 = simulate_trace(s2.tobytes())
    combined_trace = trace1 + trace2
    defended_trace = apply_defense(combined_trace, defense_mode)
    traces.append(defended_trace)

    sig = private_key.sign(message)
    return sig, np.array(traces)


def ed25519_verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(signature, message)
        return True
    except (ValueError, InvalidSignature):
        return False
