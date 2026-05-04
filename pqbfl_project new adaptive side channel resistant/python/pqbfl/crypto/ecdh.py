from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

import numpy as np
from pqbfl.crypto.leakage import mask_bytes, simulate_trace, apply_defense


@dataclass(frozen=True)
class ECDHKeypair:
    private_key: ec.EllipticCurvePrivateKey
    public_key_bytes: bytes


@dataclass(frozen=True)
class X25519Keypair:
    private_key: x25519.X25519PrivateKey
    public_key_bytes: bytes


def ecdh_keygen_secp256k1() -> ECDHKeypair:
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    return ECDHKeypair(private_key=private_key, public_key_bytes=public_key_bytes)


def ecdh_shared_secret_secp256k1(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key_bytes: bytes,
    defense_mode="none"
) -> tuple[bytes, np.ndarray]:
    traces = []
    priv_bytes = private_key.private_numbers().private_value.to_bytes(32, "big")
    s1, s2 = mask_bytes(priv_bytes)
    trace1 = simulate_trace(s1.tobytes())
    trace2 = simulate_trace(s2.tobytes())
    combined_trace = trace1 + trace2
    defended_trace = apply_defense(combined_trace, defense_mode)
    traces.append(defended_trace)

    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), peer_public_key_bytes)
    ss = private_key.exchange(ec.ECDH(), peer_public_key)
    return ss, np.array(traces)


def ecdh_keygen_x25519() -> X25519Keypair:
    private_key = x25519.X25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return X25519Keypair(private_key=private_key, public_key_bytes=public_key_bytes)


def ecdh_shared_secret_x25519(
    private_key: x25519.X25519PrivateKey, 
    peer_public_key_bytes: bytes,
    defense_mode="none"
) -> tuple[bytes, np.ndarray]:
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

    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    ss = private_key.exchange(peer_public_key)
    return ss, np.array(traces)
