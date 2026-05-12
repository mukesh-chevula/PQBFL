"""
adaptive/policy.py
Selective Encryption Policy — Kappala et al. (2026) §IV.

Maps (DataTier, θ) → EncryptionMode using dual thresholds θ_lo and θ_hi.
This is the "dynamic threshold modulation" that makes the paper adaptive.

Data Tiers (agricultural sensor context):
  CRITICAL — actuator commands, pesticide dosing, irrigation valve controls
  SENSITIVE — soil pH, temperature, GPS coordinates, harvest schedules
  NORMAL   — ambient light, wind speed, non-sensitive environmental readings

Encryption Modes:
  KYBER_AES  — ML-KEM session key + AES-256-GCM  (post-quantum full stack)
  AES_ONLY   — AES-256-GCM with pre-shared key    (classical, fast)
  PLAINTEXT  — no encryption                       (benign diagnostics only)

Policy table (Kappala et al. Table III):
  ┌──────────┬───────────────────┬───────────────────┬────────────────────┐
  │ Tier     │ θ < θ_lo (benign) │ θ_lo ≤ θ < θ_hi   │ θ ≥ θ_hi (attack)  │
  ├──────────┼───────────────────┼───────────────────┼────────────────────┤
  │ CRITICAL │ AES_ONLY          │ KYBER_AES         │ KYBER_AES          │
  │ SENSITIVE│ PLAINTEXT         │ AES_ONLY          │ KYBER_AES          │
  │ NORMAL   │ PLAINTEXT         │ PLAINTEXT         │ AES_ONLY           │
  └──────────┴───────────────────┴───────────────────┴────────────────────┘

This directly parallels JOURNAL-3's L_j policy:
  • Low threat  → relax encryption (save energy)  ↔  high L_j (save KEM cost)
  • High threat → tighten encryption (max security) ↔  low L_j (frequent KEM)
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class DataTier(Enum):
    CRITICAL  = 3   # actuator commands, dosing instructions
    SENSITIVE = 2   # soil/GPS/harvest data
    NORMAL    = 1   # ambient environmental readings


class EncryptionMode(Enum):
    KYBER_AES  = "kyber_aes"    # ML-KEM + AES-256-GCM
    AES_ONLY   = "aes_only"     # AES-256-GCM (pre-shared key)
    PLAINTEXT  = "plaintext"    # no encryption

    @property
    def energy_cost_relative(self) -> float:
        """Relative energy cost (PLAINTEXT = 1.0)."""
        return {
            EncryptionMode.PLAINTEXT: 1.0,
            EncryptionMode.AES_ONLY:  3.2,
            EncryptionMode.KYBER_AES: 18.5,   # KEM is expensive on MCU
        }[self]

    @property
    def latency_ms_estimate(self) -> float:
        """Estimated processing latency on ARM Cortex-M4 @ 168 MHz."""
        return {
            EncryptionMode.PLAINTEXT: 0.05,
            EncryptionMode.AES_ONLY:  0.38,
            EncryptionMode.KYBER_AES: 4.20,   # Kyber encap on embedded HW
        }[self]


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------

@dataclass
class SelectiveEncryptionPolicy:
    """
    Maps (DataTier, θ) → EncryptionMode.

    Parameters
    ----------
    theta_lo : float  Lower threshold — below this, relax encryption.
    theta_hi : float  Upper threshold — above this, apply maximum encryption.
    """
    theta_lo: float = 0.25
    theta_hi: float = 0.65

    def __post_init__(self):
        if not 0 < self.theta_lo < self.theta_hi < 1:
            raise ValueError(
                f"Require 0 < θ_lo={self.theta_lo} < θ_hi={self.theta_hi} < 1"
            )

    def decide(self, tier: DataTier, theta: float) -> EncryptionMode:
        """
        Apply the Kappala et al. (2026) policy table.

        Args:
            tier:  Data sensitivity tier of the outgoing packet.
            theta: Current threat score θ ∈ [0, 1].

        Returns:
            EncryptionMode to apply to this packet.
        """
        theta = max(0.0, min(1.0, theta))   # clamp

        if theta < self.theta_lo:
            # Benign zone — conserve energy
            return {
                DataTier.CRITICAL:  EncryptionMode.AES_ONLY,
                DataTier.SENSITIVE: EncryptionMode.PLAINTEXT,
                DataTier.NORMAL:    EncryptionMode.PLAINTEXT,
            }[tier]

        elif theta < self.theta_hi:
            # Elevated zone — selective hardening
            return {
                DataTier.CRITICAL:  EncryptionMode.KYBER_AES,
                DataTier.SENSITIVE: EncryptionMode.AES_ONLY,
                DataTier.NORMAL:    EncryptionMode.PLAINTEXT,
            }[tier]

        else:
            # Attack zone — maximum encryption
            return {
                DataTier.CRITICAL:  EncryptionMode.KYBER_AES,
                DataTier.SENSITIVE: EncryptionMode.KYBER_AES,
                DataTier.NORMAL:    EncryptionMode.AES_ONLY,
            }[tier]

    def policy_table(self) -> list[dict]:
        """Return full policy table as a list of dicts (for display/logging)."""
        rows = []
        for tier in DataTier:
            for zone, theta in [("benign", 0.0), ("elevated", 0.45), ("attack", 0.85)]:
                mode = self.decide(tier, theta)
                rows.append({
                    "tier":   tier.name,
                    "zone":   zone,
                    "theta":  theta,
                    "mode":   mode.value,
                    "energy": mode.energy_cost_relative,
                    "lat_ms": mode.latency_ms_estimate,
                })
        return rows
