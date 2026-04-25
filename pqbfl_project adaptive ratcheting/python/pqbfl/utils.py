"""
Utility functions for PQBFL.

Side-channel hardening:
  - secure_compare() uses hmac.compare_digest for constant-time comparison
    of bytes or strings, preventing timing oracles.
  - secure_hash_compare() combines SHA-256 hashing with constant-time
    comparison for hash integrity checks.
  - All hash comparison helpers are thin wrappers so call-sites read clearly.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, is_dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Constant-time comparison helpers
# ---------------------------------------------------------------------------

def secure_compare(a: bytes | str, b: bytes | str) -> bool:
    """Constant-time comparison of two byte strings or unicode strings.

    Prevents timing side-channels that allow an attacker to progressively
    brute-force values byte-by-byte by measuring response times.  Uses
    hmac.compare_digest which is implemented in C and runs in time
    proportional only to the length of the inputs, not their content.
    """
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)


def secure_hash_compare(data: bytes, expected_hex: str) -> bool:
    """Hash *data* with SHA-256 and compare to *expected_hex* in constant time."""
    actual = sha256_hex(data)
    return hmac.compare_digest(actual.encode("ascii"), expected_hex.encode("ascii"))


def secure_bytes_compare(a: bytes, b: bytes) -> bool:
    """Constant-time bytes comparison.  Preferred over ``a == b``."""
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()


def sha256_bytes32(data: bytes) -> bytes:
    return sha256(data)[:32]


def to_bytes32_hex(data: bytes) -> str:
    return "0x" + sha256_bytes32(data).hex()


# ---------------------------------------------------------------------------
# JSON serialization (safe alternative to pickle)
# ---------------------------------------------------------------------------

def json_dumps_canonical(obj: Any) -> str:
    """Deterministic JSON serialization with bytes support."""
    def default(o: Any):
        if is_dataclass(o):
            return asdict(o)
        if isinstance(o, (bytes, bytearray)):
            return {"__bytes__": True, "hex": bytes(o).hex()}
        raise TypeError(f"Unsupported type: {type(o)!r}")

    return json.dumps(obj, default=default, separators=(",", ":"), sort_keys=True)


def json_loads_bytes(obj: Any) -> Any:
    """Recursively restore bytes objects from JSON-serialised form."""
    if isinstance(obj, dict) and obj.get("__bytes__") is True:
        return bytes.fromhex(obj["hex"])
    if isinstance(obj, dict):
        return {k: json_loads_bytes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_loads_bytes(v) for v in obj]
    return obj
