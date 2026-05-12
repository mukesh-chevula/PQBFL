"""
attacks/timing_leakage.py
Side-channel timing leakage model — Saeed & Alqahtani (2024) §III.

This module implements the CORE FINDING of the paper: that naive
cryptographic implementations on IoT devices (ARM Cortex-M / ESP32 / STM32)
leak key-dependent timing information exploitable by a passive adversary.

Leakage Sources Modelled (Saeed & Alqahtani Table II):
  1. Data-dependent branching   — early-exit comparisons (strcmp, memcmp)
  2. Non-constant-time multiply — variable-time modular exponentiation
  3. Cache timing               — AES S-box lookup cache misses
  4. Hamming-weight leakage     — power draw proportional to bit popcount
  5. Nonce reuse                — deterministic ciphertext enables correlation

Attack Model:
  An adversary collects N timing observations T = {t₁, t₂, ..., tₙ}
  during authentication/encryption operations and fits a linear model:
      t = α·HW(k_guess) + β·HD(k_guess, prev) + ε
  where HW = Hamming weight, HD = Hamming distance, ε ~ N(0, σ²).
  If σ is small enough (low noise), key bits are recoverable.

Saeed & Alqahtani (2024) report that 35-40% of gradient directions in
the world can be inferred via average observation vectors — this is the
specific claim cited in JOURNAL-3's Introduction.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import struct
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Tuple

import numpy as np


# ---------------------------------------------------------------------------
# Leakage source constants (from Saeed & Alqahtani Table II)
# ---------------------------------------------------------------------------

BASE_LATENCY_US   = 100.0   # baseline op time (μs)
BRANCH_COEFF      = 8.0     # μs per bit in data-dependent branch
HW_COEFF          = 2.5     # μs per Hamming weight unit
CACHE_MISS_US     = 45.0    # μs per cache miss
NOISE_STD_US      = 3.0     # measurement noise σ


class LeakageMode(Enum):
    """Implementation variant being simulated."""
    VULNERABLE      = auto()   # naive stdlib implementation
    HARDENED        = auto()   # constant-time + CSPRNG hardened


@dataclass
class TimingObservation:
    """A single timing measurement from one cryptographic operation."""
    device_id:       int
    operation:       str      # e.g. "hmac", "kem_decap", "aes_gcm"
    secret_hw:       int      # Hamming weight of the secret (ground truth)
    measured_us:     float    # observed timing in microseconds
    mode:            LeakageMode
    is_attack:       bool     # True if an adversary injected a probe packet

    @property
    def leakage_snr(self) -> float:
        """Signal-to-noise ratio of the leakage signal."""
        signal = abs(self.secret_hw * HW_COEFF)
        noise  = NOISE_STD_US
        return signal / noise if noise > 0 else float("inf")


# ---------------------------------------------------------------------------
# Vulnerable implementation simulator
# ---------------------------------------------------------------------------

def _hamming_weight(x: bytes) -> int:
    return sum(bin(b).count("1") for b in x)


def _hamming_distance(a: bytes, b: bytes) -> int:
    assert len(a) == len(b)
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def vulnerable_hmac_compare(key: bytes, msg: bytes, expected_tag: bytes,
                             rng: np.random.Generator) -> Tuple[bool, float]:
    """
    Simulate a VULNERABLE early-exit HMAC comparison (data-dependent branch).

    Timing leaks: comparison stops at first mismatched byte.
    An adversary can determine the correct prefix byte-by-byte.

    Returns (is_valid, timing_us).
    """
    computed = hmac.new(key, msg, "sha256").digest()
    # Simulate early-exit timing: time proportional to matching prefix length
    match_len = 0
    for a, b in zip(computed, expected_tag):
        if a == b:
            match_len += 1
        else:
            break
    # Leaky timing: more matching bytes = longer time
    hw = _hamming_weight(computed[:4])
    timing = (
        BASE_LATENCY_US
        + match_len * BRANCH_COEFF        # early-exit leakage
        + hw * HW_COEFF                   # Hamming-weight leakage
        + rng.normal(0, NOISE_STD_US)     # measurement noise
    )
    return computed == expected_tag, max(0, timing)


def hardened_hmac_compare(key: bytes, msg: bytes, expected_tag: bytes,
                           rng: np.random.Generator) -> Tuple[bool, float]:
    """
    Simulate a HARDENED constant-time HMAC comparison (Python hmac.compare_digest).

    Timing is independent of the content — always runs full length.
    Remaining jitter comes only from noise and is uncorrelated with the secret.
    """
    computed = hmac.new(key, msg, "sha256").digest()
    result   = hmac.compare_digest(computed, expected_tag)
    # Constant-time: timing is key-independent, only noise remains
    timing = BASE_LATENCY_US + rng.normal(0, NOISE_STD_US)
    return result, max(0, timing)


def vulnerable_aes_gcm(key: bytes, nonce: bytes | None, plaintext: bytes,
                        rng: np.random.Generator) -> Tuple[bytes, float]:
    """
    Simulate VULNERABLE AES-GCM with a FIXED / reused nonce.

    Nonce reuse allows an adversary to XOR two ciphertexts and recover
    plaintext XOR plaintext — completely breaking confidentiality.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    # Use deterministic nonce (reuse vulnerability)
    fixed_nonce = nonce if nonce else b"\x00" * 12
    ct      = AESGCM(key).encrypt(fixed_nonce, plaintext, b"")
    hw      = _hamming_weight(plaintext[:4])
    timing  = BASE_LATENCY_US + hw * HW_COEFF + rng.normal(0, NOISE_STD_US)
    return ct, max(0, timing)


def hardened_aes_gcm(key: bytes, plaintext: bytes,
                     rng: np.random.Generator) -> Tuple[bytes, float]:
    """
    Simulate HARDENED AES-GCM with a CSPRNG random nonce per operation.
    Nonce is always fresh → nonce-reuse attacks impossible.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    fresh_nonce = os.urandom(12)   # CSPRNG — unpredictable
    ct      = AESGCM(key).encrypt(fresh_nonce, plaintext, b"")
    # Constant-time: timing independent of plaintext content
    timing  = BASE_LATENCY_US + rng.normal(0, NOISE_STD_US)
    return ct, max(0, timing)


# ---------------------------------------------------------------------------
# Trace generator — creates datasets of timing observations
# ---------------------------------------------------------------------------

def generate_timing_traces(
    n_samples:   int   = 500,
    mode:        LeakageMode = LeakageMode.VULNERABLE,
    attack_frac: float = 0.25,   # fraction of samples where attacker probes
    seed:        int   = 42,
    device_id:   int   = 0,
) -> List[TimingObservation]:
    """
    Generate a dataset of timing observations for one IoT device.

    Benign operations: normal HMAC verification with random keys and messages.
    Attack probes: adversary sends carefully crafted messages to maximise
                   timing signal (known-plaintext attack).

    Returns list of TimingObservation with ground-truth labels.
    """
    rng = np.random.default_rng(seed)
    observations = []

    for i in range(n_samples):
        key      = os.urandom(32)
        msg      = bytes(rng.integers(0, 256, 32, dtype=np.uint8))
        tag      = hmac.new(key, msg, "sha256").digest()
        is_attack = rng.random() < attack_frac

        if is_attack:
            # Attack probe: adversary modifies one byte to probe timing
            probe_tag = bytearray(tag)
            probe_tag[rng.integers(0, 32)] ^= 0xFF
            probe_tag = bytes(probe_tag)
        else:
            probe_tag = tag

        hw = _hamming_weight(key[:4])

        if mode == LeakageMode.VULNERABLE:
            _, timing = vulnerable_hmac_compare(key, msg, probe_tag, rng)
        else:
            _, timing = hardened_hmac_compare(key, msg, probe_tag, rng)

        observations.append(TimingObservation(
            device_id   = device_id,
            operation   = "hmac_verify",
            secret_hw   = hw,
            measured_us = timing,
            mode        = mode,
            is_attack   = is_attack,
        ))

    return observations
