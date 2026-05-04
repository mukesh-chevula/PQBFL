from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import numpy as np
from pqbfl.crypto.leakage import mask_bytes, simulate_trace, apply_defense
from pqbfl.utils import hash32


def nonce_for_round(round_num: int, label: str) -> bytes:
    if round_num < 0:
        raise ValueError("round_num must be >= 0")
    seed = f"pqbfl:{label}:{round_num}".encode("utf-8")
    return hash32(seed)[:12]


def aead_encrypt(key32: bytes, plaintext: bytes, *, aad: bytes, nonce: bytes, defense_mode="none") -> tuple[bytes, np.ndarray]:
    traces = []
    s1, s2 = mask_bytes(key32)
    trace1 = simulate_trace(s1.tobytes())
    trace2 = simulate_trace(s2.tobytes())
    combined_trace = trace1 + trace2
    defended_trace = apply_defense(combined_trace, defense_mode)
    traces.append(defended_trace)

    if len(key32) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
    aead = ChaCha20Poly1305(key32)
    ct = aead.encrypt(nonce, plaintext, aad)
    return ct, np.array(traces)


def aead_decrypt(key32: bytes, ciphertext: bytes, *, aad: bytes, nonce: bytes, defense_mode="none") -> tuple[bytes, np.ndarray]:
    traces = []
    s1, s2 = mask_bytes(key32)
    trace1 = simulate_trace(s1.tobytes())
    trace2 = simulate_trace(s2.tobytes())
    combined_trace = trace1 + trace2
    defended_trace = apply_defense(combined_trace, defense_mode)
    traces.append(defended_trace)

    if len(key32) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
    aead = ChaCha20Poly1305(key32)
    pt = aead.decrypt(nonce, ciphertext, aad)
    return pt, np.array(traces)
