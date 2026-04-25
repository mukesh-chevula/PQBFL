"""
Ethereum ECDSA signature utilities.

Side-channel hardening:
  - recover_signer always returns a normalised (checksummed) address.
  - verify_signer performs constant-time address comparison via
    hmac.compare_digest to prevent timing oracles on address contents.
  - Signing delegates to eth_account which uses the OpenSSL / libsecp256k1
    backend (constant-time scalar multiplication).
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass

from eth_account import Account
from eth_account.messages import encode_defunct


@dataclass(frozen=True)
class EthIdentity:
    address: str
    private_key_hex: str


def sign_bytes(private_key_hex: str, message: bytes) -> bytes:
    """Sign an arbitrary byte message using Ethereum's personal_sign scheme."""
    signed = Account.sign_message(encode_defunct(message), private_key=private_key_hex)
    return signed.signature


def recover_signer(message: bytes, signature: bytes) -> str:
    """Recover the signer address from a signed message."""
    return Account.recover_message(encode_defunct(message), signature=signature)


def verify_signer(message: bytes, signature: bytes, expected_address: str) -> bool:
    """Verify that *message* was signed by *expected_address*.

    Uses hmac.compare_digest for constant-time comparison of the recovered
    address against the expected one, preventing timing side-channels that
    could leak address bytes.
    """
    recovered = recover_signer(message, signature).lower().encode("ascii")
    expected = expected_address.lower().encode("ascii")
    return hmac.compare_digest(recovered, expected)
