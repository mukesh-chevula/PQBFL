"""
privacy/dp.py
Differential Privacy utilities for Zhang et al. (2025).

Zhang et al. combine PQC gradient encryption with a Gaussian DP mechanism
on the aggregated gradients, providing both:
  • Cryptographic privacy: gradients encrypted in transit via ML-KEM + AES-GCM
  • Statistical privacy: gradient aggregates satisfy (ε, δ)-DP

This module implements:
  1. GaussianDP     — calibrates and applies Gaussian noise per the Gaussian Mechanism
  2. clip_gradient  — L2-norm gradient clipping (sensitivity bounding)
  3. compute_rdp_epsilon — Rényi DP budget accounting across T rounds
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

import numpy as np


# ---------------------------------------------------------------------------
# L2 gradient clipping
# ---------------------------------------------------------------------------

def clip_gradient(gradient: np.ndarray, max_norm: float) -> np.ndarray:
    """
    Clip gradient to L2 norm ≤ max_norm (sensitivity bound C).

    This bounds the sensitivity of the gradient function so that the
    Gaussian Mechanism can be calibrated correctly.
    """
    norm = float(np.linalg.norm(gradient))
    if norm > max_norm:
        return gradient * (max_norm / norm)
    return gradient


# ---------------------------------------------------------------------------
# Gaussian DP Mechanism
# ---------------------------------------------------------------------------

@dataclass
class GaussianDP:
    """
    Gaussian Mechanism for (ε, δ)-differential privacy.

    The noise scale σ is calibrated to:
        σ = C * sqrt(2 * ln(1.25 / δ)) / ε

    where C is the L2 sensitivity (max_norm after clipping).

    Attributes:
        epsilon:  Privacy budget ε  (smaller = more private = more noise)
        delta:    Privacy failure probability δ (typically 1e-5)
        max_norm: L2 sensitivity / clipping bound C
    """
    epsilon:  float = 1.0
    delta:    float = 1e-5
    max_norm: float = 1.0

    def __post_init__(self):
        if self.epsilon <= 0:
            raise ValueError("epsilon must be positive")
        if not (0 < self.delta < 1):
            raise ValueError("delta must be in (0, 1)")
        if self.max_norm <= 0:
            raise ValueError("max_norm must be positive")

    @property
    def sigma(self) -> float:
        """Gaussian noise standard deviation σ."""
        return self.max_norm * math.sqrt(2 * math.log(1.25 / self.delta)) / self.epsilon

    def add_noise(
        self,
        gradient: np.ndarray,
        clip: bool = True,
        rng: Optional[np.random.Generator] = None,
    ) -> np.ndarray:
        """
        Clip gradient (optional) then add calibrated Gaussian noise.

        Args:
            gradient: Aggregated gradient array.
            clip:     Whether to apply L2 clipping first.
            rng:      NumPy random generator (None = global default).

        Returns:
            Noisy gradient satisfying (ε, δ)-DP.
        """
        g = clip_gradient(gradient, self.max_norm) if clip else gradient.copy()
        noise_rng = rng if rng is not None else np.random.default_rng()
        noise = noise_rng.normal(0.0, self.sigma, g.shape).astype(g.dtype)
        return g + noise

    def __repr__(self) -> str:
        return (
            f"GaussianDP(ε={self.epsilon}, δ={self.delta:.0e}, "
            f"C={self.max_norm}, σ={self.sigma:.4f})"
        )


# ---------------------------------------------------------------------------
# Rényi DP budget accounting
# ---------------------------------------------------------------------------

def compute_rdp_epsilon(
    sigma: float,
    q: float,        # sampling rate = batch_size / dataset_size
    n_rounds: int,
    delta: float = 1e-5,
    orders: Optional[list] = None,
) -> float:
    """
    Compute the (ε, δ)-DP guarantee of T rounds of subsampled Gaussian mechanism
    using Rényi DP composition.

    Uses the simplified closed-form bound (Mironov 2017 / Abadi 2016):
        RDP(α) ≈ α * q^2 / (2 * σ^2)  (for small q)
    Composition over T rounds multiplies by T.
    Conversion: ε(δ) = min_α [ RDP(α) + log(1/δ) / (α - 1) ]

    Args:
        sigma:    Noise multiplier.
        q:        Subsampling rate (= n_clients / total_clients or batch/dataset).
        n_rounds: Number of training rounds.
        delta:    DP failure probability.
        orders:   List of Rényi orders α to optimise over.

    Returns:
        Estimated ε for the given δ.
    """
    if orders is None:
        orders = list(range(2, 128))

    best_eps = float("inf")
    for alpha in orders:
        # Simplified RDP bound for subsampled Gaussian
        rdp = alpha * (q ** 2) / (2 * sigma ** 2) * n_rounds
        # Convert RDP → (ε, δ)-DP
        eps = rdp + math.log(1.0 / delta) / (alpha - 1)
        best_eps = min(best_eps, eps)

    return best_eps
