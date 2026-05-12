"""
blockchain/block.py
Block structure for the PQS-BFL chain — Commey et al. (2025).

Each block records one FL round's gradient commitments:
  • SHA-3-256 hash of the aggregated gradient
  • ML-DSA signature from each participating client
  • Previous block hash (chain linkage)
  • Round index and timestamp

Commey et al. use a permissioned PoA (Proof-of-Authority) chain where
the aggregation server is the block proposer and clients are validators.
"""
from __future__ import annotations
import hashlib, json, time
from dataclasses import dataclass, field
from typing import List


@dataclass
class GradientCommitment:
    """One client's signed gradient record embedded in a block."""
    client_id:      int
    gradient_hash:  str    # SHA-3-256 hex of serialised gradient delta
    signature_hex:  str    # ML-DSA signature hex
    pubkey_hex:     str    # client's ML-DSA public key hex
    wire_bytes:     int    # total encrypted gradient bytes on wire
    sig_bytes:      int    # ML-DSA signature size

    @classmethod
    def from_bytes(cls, client_id: int, gradient_bytes: bytes,
                   sig_bytes: bytes, pk_bytes: bytes, wire_size: int) -> "GradientCommitment":
        g_hash = hashlib.sha3_256(gradient_bytes).hexdigest()
        return cls(
            client_id     = client_id,
            gradient_hash = g_hash,
            signature_hex = sig_bytes.hex(),
            pubkey_hex    = pk_bytes.hex(),
            wire_bytes    = wire_size,
            sig_bytes     = len(sig_bytes),
        )

    def to_dict(self) -> dict:
        return {
            "client_id":     self.client_id,
            "gradient_hash": self.gradient_hash,
            "sig_bytes":     self.sig_bytes,
            "wire_bytes":    self.wire_bytes,
        }


@dataclass
class Block:
    index:          int
    round_idx:      int
    timestamp:      float
    commitments:    List[GradientCommitment]
    agg_hash:       str     # SHA-3-256 of aggregated gradient
    prev_hash:      str
    proposer:       str     # server identity
    _hash:          str = field(default="", init=False, repr=False)

    def __post_init__(self):
        self._hash = self._compute_hash()

    def _compute_hash(self) -> str:
        payload = json.dumps({
            "index":      self.index,
            "round_idx":  self.round_idx,
            "timestamp":  self.timestamp,
            "agg_hash":   self.agg_hash,
            "prev_hash":  self.prev_hash,
            "proposer":   self.proposer,
            "commitments": [c.to_dict() for c in self.commitments],
        }, sort_keys=True).encode()
        return hashlib.sha3_256(payload).hexdigest()

    @property
    def hash(self) -> str:
        return self._hash

    @property
    def n_clients(self) -> int:
        return len(self.commitments)

    @property
    def total_sig_bytes(self) -> int:
        return sum(c.sig_bytes for c in self.commitments)

    @property
    def total_wire_bytes(self) -> int:
        return sum(c.wire_bytes for c in self.commitments)

    def to_dict(self) -> dict:
        return {
            "index":           self.index,
            "round_idx":       self.round_idx,
            "hash":            self._hash,
            "prev_hash":       self.prev_hash,
            "agg_hash":        self.agg_hash,
            "n_clients":       self.n_clients,
            "total_sig_bytes": self.total_sig_bytes,
            "total_wire_bytes":self.total_wire_bytes,
        }


def genesis_block() -> Block:
    return Block(
        index       = 0,
        round_idx   = -1,
        timestamp   = time.time(),
        commitments = [],
        agg_hash    = "0" * 64,
        prev_hash   = "0" * 64,
        proposer    = "genesis",
    )
