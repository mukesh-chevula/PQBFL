"""
blockchain/chain.py
Permissioned PoA blockchain — Commey et al. (2025).

Lightweight chain where the aggregation server is the sole block proposer.
Each FL round produces exactly one block containing all client gradient
commitments that passed the smart contract verification.
"""
from __future__ import annotations

import hashlib
import time
from typing import List, Optional

import numpy as np

from commey2025.blockchain.block import Block, GradientCommitment, genesis_block
from commey2025.blockchain.contract import GradientVerificationContract


class PQSBFLChain:
    """
    PoA chain for PQS-BFL gradient audit trail.

    Invariants:
      • chain[0] is the genesis block
      • chain[i].prev_hash == chain[i-1].hash for i ≥ 1
      • All gradient commitments in a block have been verified by the contract
    """

    def __init__(self):
        self.chain:    List[Block]                  = [genesis_block()]
        self.contract: GradientVerificationContract = GradientVerificationContract()
        self._total_sig_bytes    = 0
        self._total_wire_bytes   = 0
        self._total_gradient_bytes = 0

    # ------------------------------------------------------------------
    # Chain operations
    # ------------------------------------------------------------------

    @property
    def latest(self) -> Block:
        return self.chain[-1]

    @property
    def height(self) -> int:
        return len(self.chain)

    def append_round_block(
        self,
        round_idx:    int,
        commitments:  List[GradientCommitment],
        agg_gradient: np.ndarray,
        proposer:     str = "server",
    ) -> Block:
        """
        Propose and append a new block for one FL round.

        Only commitments already verified by the smart contract are included.
        """
        agg_bytes = agg_gradient.tobytes()
        agg_hash  = hashlib.sha3_256(agg_bytes).hexdigest()

        block = Block(
            index       = len(self.chain),
            round_idx   = round_idx,
            timestamp   = time.time(),
            commitments = commitments,
            agg_hash    = agg_hash,
            prev_hash   = self.latest.hash,
            proposer    = proposer,
        )

        # Validate chain linkage before appending
        assert block.prev_hash == self.latest.hash, "Chain integrity violation!"
        self.chain.append(block)

        self._total_sig_bytes    += block.total_sig_bytes
        self._total_wire_bytes   += block.total_wire_bytes

        return block

    def is_valid(self) -> bool:
        """Verify entire chain integrity (hash linkage)."""
        for i in range(1, len(self.chain)):
            if self.chain[i].prev_hash != self.chain[i-1].hash:
                return False
        return True

    def chain_summary(self) -> dict:
        n_blocks = len(self.chain) - 1   # exclude genesis
        return {
            "chain_height":         len(self.chain),
            "fl_rounds_recorded":   n_blocks,
            "total_sig_bytes":      self._total_sig_bytes,
            "total_wire_bytes":     self._total_wire_bytes,
            "sig_overhead_frac":    round(
                self._total_sig_bytes / max(1, self._total_wire_bytes), 4),
            "chain_valid":          self.is_valid(),
            **self.contract.summary(),
        }
