"""
Adaptive Ratchet Policy for PQBFL.

Maps the current threat level (0.0–1.0) from the ThreatMonitor to a
concrete symmetric ratcheting threshold ``L_j``.  The policy ensures
that:

  - High threat → small L_j → asymmetric ratchet triggers more often
    (more frequent key rotation for stronger forward secrecy / PCS).
  - Low threat  → large L_j → fewer asymmetric ratchets
    (reduced PQ key generation overhead, better performance).

Every L_j adjustment is recorded in an audit log that can be committed
on-chain or displayed in the UI for transparency.

This is the first implementation of threat-adaptive ratcheting in any
post-quantum federated learning system.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class RatchetAdjustment:
    """Record of a single L_j adjustment."""

    timestamp: float
    round_num: int
    old_L_j: int
    new_L_j: int
    threat_level: float
    reason: str


@dataclass
class AdaptiveRatchetPolicy:
    """Policy that maps threat level → symmetric ratcheting window L_j.

    Parameters
    ----------
    L_min : int
        Minimum L_j (used at maximum threat).  Must be ≥ 1.
    L_max : int
        Maximum L_j (used at zero threat).
    L_default : int
        Starting value for L_j before any adaptation.
    cooldown_rounds : int
        Minimum number of rounds between consecutive L_j changes to
        prevent oscillation.  Default 1.
    alpha : float
        Security risk weight coefficient in the joint optimization. Default 1.0.
    beta : float
        Communication cost weight coefficient. Default 1.0.
    gamma : float
        Energy cost weight coefficient. Default 1.0.
    N : int
        Number of federated learning rounds. Default 50.
    C_kem : float
        Measured communication cost per KEM re-keying operation. Default 0.1386.
    E_kem : float
        Measured energy cost per KEM re-keying operation. Default 0.1386.
    sensitivity : float
        Exponent kept for backward compatibility. Default 2.0.
    """

    L_min: int = 2
    L_max: int = 20
    L_default: int = 10
    cooldown_rounds: int = 1
    alpha: float = 1.0
    beta: float = 1.0
    gamma: float = 1.0
    N: int = 50
    C_kem: float = 0.1386
    E_kem: float = 0.1386
    sensitivity: float = 2.0

    _current_L_j: int = field(init=False, repr=False)
    _last_change_round: int = field(default=-100, init=False, repr=False)
    _adjustments: list[RatchetAdjustment] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self.L_min = max(1, self.L_min)
        self.L_max = max(self.L_min, self.L_max)
        self.L_default = max(self.L_min, min(self.L_max, self.L_default))
        self._current_L_j = self.L_default

    # ── core policy ──────────────────────────────────────────────

    def compute_L_j(self, threat_level: float) -> int:
        """Compute the ideal L_j for a given threat level.

        Uses the joint optimization-based threshold selection model:
            L_j* = sqrt( N * (beta * C_kem + gamma * E_kem) / (alpha * Theta_epsilon(t)) )
            where Theta_epsilon(t) = max(threat_level, 1e-6) to avoid singularity.
            The result is bounded within [L_min, L_max].
        """
        t = max(0.0, min(1.0, threat_level))
        t_eps = max(t, 1e-6)
        
        # Calculate optimal L_j^* using closed-form derivation
        numerator = self.N * (self.beta * self.C_kem + self.gamma * self.E_kem)
        denominator = self.alpha * t_eps
        L_j_star = math.sqrt(numerator / denominator)
        
        # Bound within [L_min, L_max]
        return max(self.L_min, min(self.L_max, round(L_j_star)))

    def evaluate(
        self,
        threat_level: float,
        *,
        round_num: int = -1,
        reason: str = "",
    ) -> int:
        """Evaluate and possibly update L_j based on current threat level.

        Respects the cooldown period to prevent oscillation.

        Returns
        -------
        int
            The current (possibly updated) L_j value.
        """
        ideal = self.compute_L_j(threat_level)

        # Cooldown check
        if abs(round_num - self._last_change_round) < self.cooldown_rounds:
            return self._current_L_j

        if ideal != self._current_L_j:
            old = self._current_L_j
            self._current_L_j = ideal
            self._last_change_round = round_num

            adj = RatchetAdjustment(
                timestamp=time.time(),
                round_num=round_num,
                old_L_j=old,
                new_L_j=ideal,
                threat_level=round(threat_level, 4),
                reason=reason or f"Threat level {threat_level:.3f} → L_j {old} → {ideal}",
            )
            self._adjustments.append(adj)

        return self._current_L_j

    # ── ratchet decision ─────────────────────────────────────────

    def should_ratchet(
        self,
        current_i: int,
        current_L_j: int,
        threat_level: float,
    ) -> bool:
        """Determine whether an asymmetric ratchet should trigger now.

        An asymmetric ratchet triggers when the symmetric ratchet counter
        ``current_i`` reaches the (possibly adaptive) threshold.  Under
        high threat, the threshold may have been lowered dynamically.

        Parameters
        ----------
        current_i : int
            Current symmetric ratchet step index within this epoch.
        current_L_j : int
            The currently active L_j for this session.
        threat_level : float
            The current composite threat level.

        Returns
        -------
        bool
            True if an asymmetric ratchet should be triggered.
        """
        adaptive_L_j = self.compute_L_j(threat_level)
        # Use the more conservative (smaller) of the two thresholds
        effective = min(current_L_j, adaptive_L_j)
        return current_i >= effective

    # ── accessors ────────────────────────────────────────────────

    @property
    def current_L_j(self) -> int:
        """The most recently evaluated L_j value."""
        return self._current_L_j

    def get_adjustment_log(self) -> list[dict]:
        """Return all L_j adjustments as serialisable dicts."""
        return [
            {
                "timestamp": adj.timestamp,
                "round": adj.round_num,
                "old_L_j": adj.old_L_j,
                "new_L_j": adj.new_L_j,
                "threat_level": adj.threat_level,
                "reason": adj.reason,
            }
            for adj in self._adjustments
        ]

    def get_adjustment_count(self) -> int:
        """Total number of L_j adjustments made."""
        return len(self._adjustments)

    def reset(self) -> None:
        """Reset the policy to its initial state."""
        self._current_L_j = self.L_default
        self._last_change_round = -100
        self._adjustments.clear()
