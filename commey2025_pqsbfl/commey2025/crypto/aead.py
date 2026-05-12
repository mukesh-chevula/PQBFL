"""
crypto/aead.py  — AES-256-GCM for Commey et al. (2025).
"""
from __future__ import annotations
import os
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

@dataclass
class AEADPacket:
    nonce: bytes; ciphertext: bytes
    @property
    def wire_size(self) -> int: return 12 + len(self.ciphertext)

def aead_encrypt(key: bytes, pt: bytes, ad: bytes = b"") -> AEADPacket:
    n = os.urandom(12); return AEADPacket(n, AESGCM(key).encrypt(n, pt, ad))

def aead_decrypt(key: bytes, pkt: AEADPacket, ad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(pkt.nonce, pkt.ciphertext, ad)

"""
crypto/__init__.py
"""
