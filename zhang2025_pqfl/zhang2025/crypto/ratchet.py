"""
crypto/ratchet.py
Static symmetric ratchet — the Zhang et al. (2025) baseline design.

Core design (§III of the paper):
  • Session window L_j is a FIXED constant (default 10 rounds).
  • Every L_j rounds, a full KEM re-establishment is triggered.
  • Within the window, only lightweight HMAC chain-key advances occur.
  • There is NO threat signal, NO adaptive modulation of L_j.

This is the fundamental design choice that causes the 40-50% overhead:
  With L_j = 10 and Kyber-768 (1,184-byte pk + 1,088-byte ct = 2,272 bytes),
  amortised overhead per round = 2272 / 10 = 227 bytes in KEM cost alone.
  By contrast, adaptive PQBFL (Gharavi/JOURNAL-3) only triggers KEM when
  the threat signal exceeds a threshold, reducing amortised cost by ~76%.

State machine:
    IDLE ──[begin_session]──► ACTIVE
    ACTIVE ──[advance_round]──► ACTIVE  (symmetric only, within window)
    ACTIVE ──[L_j exhausted]──► NEEDS_REKEY
    NEEDS_REKEY ──[begin_session]──► ACTIVE  (new KEM round)
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from zhang2025.crypto.kdf import derive_chain_key, derive_message_key


class RatchetStatus(Enum):
    IDLE         = auto()
    ACTIVE       = auto()
    NEEDS_REKEY  = auto()


@dataclass
class RatchetState:
    """
    Complete, inspectable snapshot of ratchet state for one client-server pair.
    """
    session_epoch: int         = 0          # j — increments each KEM exchange
    round_in_epoch: int        = 0          # i — resets to 0 each new epoch
    lj: int                    = 10         # FIXED threshold (static design)
    root_key: bytes            = b""        # RK_j (32 bytes)
    chain_key: bytes           = b""        # CK_{i,j} (32 bytes)
    status: RatchetStatus      = RatchetStatus.IDLE

    # Overhead accounting
    kem_exchanges: int         = 0
    symmetric_advances: int    = 0
    total_kem_bytes: int       = 0          # cumulative KEM wire bytes
    total_symmetric_bytes: int = 0          # cumulative HMAC/KDF bytes


class StaticRatchet:
    """
    Implements the static-Lj symmetric ratchet from Zhang et al.

    Usage (server side mirrored by client):
        ratchet = StaticRatchet(lj=10, kem_bytes=1088+1184)
        ratchet.begin_session(root_key)
        mk = ratchet.advance()   # returns per-round encryption key
        ...
        if ratchet.needs_rekey:  # True every Lj rounds
            new_rk = do_kem_exchange()
            ratchet.begin_session(new_rk)
    """

    def __init__(
        self,
        lj: int = 10,
        kem_wire_bytes: int = 2272,     # pk(1184) + ct(1088) for Kyber-768
        hmac_overhead_bytes: int = 64,  # per-round HMAC chain cost (2 × 32)
    ):
        self._lj = lj
        self._kem_wire = kem_wire_bytes
        self._hmac_overhead = hmac_overhead_bytes
        self.state = RatchetState(lj=lj)

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def begin_session(self, root_key: bytes) -> None:
        """
        Start or restart a session epoch with a freshly-derived root key.
        Called after every KEM exchange (every L_j rounds).
        """
        s = self.state
        s.root_key       = root_key
        s.chain_key      = derive_chain_key(root_key, 0)
        s.round_in_epoch = 0
        s.session_epoch += 1
        s.status         = RatchetStatus.ACTIVE

        # Account for KEM wire cost
        s.kem_exchanges     += 1
        s.total_kem_bytes   += self._kem_wire

    # ------------------------------------------------------------------
    # Per-round ratchet advance
    # ------------------------------------------------------------------

    def advance(self) -> bytes:
        """
        Advance the ratchet by one round and return the per-round message key.

        Returns:
            32-byte AES-256 key MK_{i,j} for this round.

        Raises:
            RuntimeError if the session has not been initialised.
        """
        s = self.state
        if s.status != RatchetStatus.ACTIVE:
            raise RuntimeError(
                f"Ratchet is not ACTIVE (status={s.status.name}). "
                "Call begin_session() first."
            )

        mk = derive_message_key(s.chain_key, s.round_in_epoch)

        # Symmetric advance: CK_{i+1,j} = HMAC(CK_{i,j}, 0x02 || i)
        s.chain_key      = derive_chain_key(s.root_key, s.round_in_epoch + 1)
        s.round_in_epoch += 1
        s.symmetric_advances += 1
        s.total_symmetric_bytes += self._hmac_overhead

        # Check if window is exhausted → force next KEM exchange
        if s.round_in_epoch >= self._lj:
            s.status = RatchetStatus.NEEDS_REKEY

        return mk

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def needs_rekey(self) -> bool:
        return self.state.status == RatchetStatus.NEEDS_REKEY

    @property
    def lj(self) -> int:
        return self._lj

    @property
    def rounds_until_rekey(self) -> int:
        s = self.state
        remaining = self._lj - s.round_in_epoch
        return max(0, remaining)

    @property
    def amortised_kem_bytes_per_round(self) -> float:
        """
        Average KEM overhead per training round.
        For Kyber-768 with L_j = 10: 2272 / 10 = 227.2 bytes/round.
        """
        total_rounds = self.state.symmetric_advances
        if total_rounds == 0:
            return float(self._kem_wire) / self._lj
        return self.state.total_kem_bytes / total_rounds

    def overhead_summary(self) -> dict:
        s = self.state
        total_rounds = s.symmetric_advances
        total_bytes  = s.total_kem_bytes + s.total_symmetric_bytes
        kem_fraction = s.total_kem_bytes / total_bytes if total_bytes else 0.0
        return {
            "lj_fixed":                self._lj,
            "session_epochs":          s.session_epoch,
            "kem_exchanges":           s.kem_exchanges,
            "symmetric_advances":      s.symmetric_advances,
            "total_kem_bytes":         s.total_kem_bytes,
            "total_symmetric_bytes":   s.total_symmetric_bytes,
            "total_wire_bytes":        total_bytes,
            "kem_fraction":            round(kem_fraction, 4),
            "amortised_kem_bytes_per_round": round(self.amortised_kem_bytes_per_round, 2),
        }
