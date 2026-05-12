"""
crypto/aead.py  — AES-256-GCM AEAD for Kappala et al. (2026).

Used for both KYBER_AES tier (key derived via KEM) and AES_ONLY tier
(key is a pre-shared symmetric key loaded at initialisation).

Wire format:  nonce(12) || ciphertext+tag(len(pt)+16)
Energy model: ~0.12 μJ per byte encrypted on typical ARM Cortex-M4
              (used to compute simulated energy cost per packet).
"""
from __future__ import annotations
import os
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ENERGY_PER_BYTE_UJ: float = 0.12   # μJ per byte — typical Cortex-M4 AES-HW


@dataclass
class AEADResult:
    nonce:      bytes
    ciphertext: bytes          # plaintext + 16-byte GCM tag

    @property
    def wire_size(self) -> int:
        return 12 + len(self.ciphertext)

    @property
    def energy_uj(self) -> float:
        """Simulated energy cost in micro-joules."""
        return self.wire_size * ENERGY_PER_BYTE_UJ


def aead_encrypt(key: bytes, plaintext: bytes, ad: bytes = b"") -> AEADResult:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, ad)
    return AEADResult(nonce=nonce, ciphertext=ct)


def aead_decrypt(key: bytes, result: AEADResult, ad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(result.nonce, result.ciphertext, ad)
