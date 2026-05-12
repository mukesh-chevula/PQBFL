"""
blockchain/contract.py
Smart Contract simulation — Commey et al. (2025).

The on-chain verifier that enforces the PQS-BFL security policy:
  1. Every gradient submission MUST include a valid ML-DSA signature.
  2. The signing public key MUST be pre-registered (whitelist).
  3. A client whose signature fails verification is BLACKLISTED for
     the remainder of the training run.

This is the TRUST ANCHOR that replaces the classical PKI in Commey et al.

Gap vs JOURNAL-3:
  The contract here only checks SIGNATURE validity (authentication).
  JOURNAL-3's contract additionally:
    — Emits a threat score θ when anomalies are detected on-chain
    — Drives adaptive L_j ratchet modulation
    — Records ratchet epoch transitions for auditability
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from commey2025.crypto.dsa import dsa_verify, DSASignResult


@dataclass
class ContractEvent:
    event_type: str    # "REGISTER", "ACCEPT", "REJECT", "BLACKLIST"
    client_id:  int
    round_idx:  int
    timestamp:  float
    detail:     str = ""


class GradientVerificationContract:
    """
    Simulated smart contract for on-chain gradient authentication.

    Clients must register their ML-DSA public key before participating.
    Each round, the contract verifies signatures before FedAvg.
    Failed verifications accumulate — 3 failures → permanent blacklist.
    """

    MAX_FAILURES = 3

    def __init__(self):
        self._registry:   Dict[int, bytes] = {}          # client_id → public_key
        self._blacklist:  Set[int]         = set()
        self._failures:   Dict[int, int]   = {}
        self.events:      List[ContractEvent] = []

        # Overhead tracking
        self.total_accepts:  int = 0
        self.total_rejects:  int = 0
        self.total_sig_verifications: int = 0

    # ------------------------------------------------------------------
    # Client registration
    # ------------------------------------------------------------------

    def register(self, client_id: int, public_key: bytes) -> bool:
        """Register a client's ML-DSA public key on-chain."""
        if client_id in self._blacklist:
            return False
        self._registry[client_id] = public_key
        self.events.append(ContractEvent(
            "REGISTER", client_id, -1, time.time(),
            f"pk_len={len(public_key)}B"
        ))
        return True

    def is_registered(self, client_id: int) -> bool:
        return client_id in self._registry and client_id not in self._blacklist

    # ------------------------------------------------------------------
    # Per-round gradient verification
    # ------------------------------------------------------------------

    def verify_gradient(
        self,
        client_id:      int,
        round_idx:      int,
        gradient_bytes: bytes,
        sign_result:    DSASignResult,
    ) -> bool:
        """
        Verify a client's ML-DSA gradient signature.

        Returns True if accepted; False if rejected (and may blacklist).
        """
        self.total_sig_verifications += 1

        # Blacklist check
        if client_id in self._blacklist:
            self._emit("REJECT", client_id, round_idx,
                       "client is blacklisted")
            self.total_rejects += 1
            return False

        # Registration check
        if client_id not in self._registry:
            self._emit("REJECT", client_id, round_idx,
                       "client not registered")
            self.total_rejects += 1
            return False

        # Signature verification
        valid = dsa_verify(gradient_bytes, sign_result)

        if valid:
            self.total_accepts += 1
            self._emit("ACCEPT", client_id, round_idx, "sig valid")
            # Reset failure counter on success
            self._failures[client_id] = 0
        else:
            fails = self._failures.get(client_id, 0) + 1
            self._failures[client_id] = fails
            self.total_rejects += 1

            if fails >= self.MAX_FAILURES:
                self._blacklist.add(client_id)
                self._emit("BLACKLIST", client_id, round_idx,
                           f"exceeded {self.MAX_FAILURES} failures")
            else:
                self._emit("REJECT", client_id, round_idx,
                           f"sig invalid (failure {fails}/{self.MAX_FAILURES})")

        return valid

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _emit(self, etype: str, cid: int, rnd: int, detail: str):
        self.events.append(
            ContractEvent(etype, cid, rnd, time.time(), detail)
        )

    def summary(self) -> dict:
        return {
            "registered_clients":     len(self._registry),
            "blacklisted_clients":    len(self._blacklist),
            "total_sig_verifications":self.total_sig_verifications,
            "total_accepts":          self.total_accepts,
            "total_rejects":          self.total_rejects,
            "accept_rate":            round(self.total_accepts /
                                            max(1, self.total_sig_verifications), 4),
            "events_logged":          len(self.events),
        }
