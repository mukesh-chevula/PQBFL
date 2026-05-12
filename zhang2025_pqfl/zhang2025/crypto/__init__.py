"""
crypto/__init__.py
Exposes the entire cryptographic stack used by Zhang et al.:
  • ML-KEM (Kyber) KEM  — post-quantum key encapsulation
  • Static symmetric ratchet — fixed-Lj HMAC chain
  • AES-256-GCM AEAD      — gradient encryption
  • HKDF-SHA-256          — key derivation
"""
from zhang2025.crypto.kem import (
    KyberKeypair,
    KyberEncapResult,
    kyber_keygen,
    kyber_encap,
    kyber_decap,
    KEM_BACKEND,
    KEM_PUBLIC_KEY_BYTES,
    KEM_CIPHERTEXT_BYTES,
    KEM_SHARED_SECRET_BYTES,
)
from zhang2025.crypto.ratchet import StaticRatchet, RatchetState
from zhang2025.crypto.aead import aead_encrypt, aead_decrypt, AEADCiphertext
from zhang2025.crypto.kdf import derive_root_key, derive_chain_key, derive_message_key

__all__ = [
    "KyberKeypair", "KyberEncapResult",
    "kyber_keygen", "kyber_encap", "kyber_decap",
    "KEM_BACKEND", "KEM_PUBLIC_KEY_BYTES", "KEM_CIPHERTEXT_BYTES", "KEM_SHARED_SECRET_BYTES",
    "StaticRatchet", "RatchetState",
    "aead_encrypt", "aead_decrypt", "AEADCiphertext",
    "derive_root_key", "derive_chain_key", "derive_message_key",
]
