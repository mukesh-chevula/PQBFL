"""
crypto/aead.py
AES-256-GCM Authenticated Encryption with Associated Data (AEAD).

Used by Zhang et al. to encrypt serialised gradient payloads:
    C_{i,r} = Enc(MK_{i,j}, Δ_{i,r})

Key properties mirroring the paper:
  • 96-bit random nonce per encryption (GCM standard)
  • 128-bit authentication tag
  • Associated data = round_index (4 bytes big-endian) to bind ciphertext
    to a specific FL round and prevent replay/reorder attacks
  • No side-channel hardening (plain branch-based comparisons) — this is
    the *static baseline* the paper benchmarks against adaptive PQBFL.

Wire format:  [ nonce(12) | tag(16) | ciphertext ]
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class AEADCiphertext:
    """Wire-serialisable AEAD output."""
    nonce: bytes          # 12 bytes
    tag: bytes            # 16 bytes (embedded in ciphertext by cryptography lib)
    ciphertext: bytes     # len(plaintext) + 16 (GCM tag appended)

    @property
    def wire_bytes(self) -> bytes:
        """Full on-wire representation: nonce || ciphertext+tag."""
        return self.nonce + self.ciphertext

    @property
    def wire_size(self) -> int:
        return len(self.wire_bytes)

    @property
    def payload_size(self) -> int:
        """Plaintext size (ciphertext minus the 16-byte GCM tag)."""
        return len(self.ciphertext) - 16


def aead_encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes = b"",
) -> AEADCiphertext:
    """
    Encrypt `plaintext` under AES-256-GCM key `key`.

    Args:
        key:             32-byte AES-256 key (derived via derive_message_key).
        plaintext:       Serialised gradient payload (numpy bytes).
        associated_data: Typically the round index in big-endian.

    Returns:
        AEADCiphertext with nonce, tag embedded in ciphertext, and wire_size.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256-GCM requires a 32-byte key, got {len(key)}")

    nonce = os.urandom(12)  # 96-bit random nonce — standard GCM requirement
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)  # ct includes 16-byte tag
    tag = ct[-16:]

    return AEADCiphertext(nonce=nonce, tag=tag, ciphertext=ct)


def aead_decrypt(
    key: bytes,
    enc: AEADCiphertext,
    associated_data: bytes = b"",
) -> bytes:
    """
    Decrypt an AEADCiphertext.

    Raises cryptography.exceptions.InvalidTag if authentication fails.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256-GCM requires a 32-byte key, got {len(key)}")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(enc.nonce, enc.ciphertext, associated_data)
