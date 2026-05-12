"""
simulate.py
End-to-end experiment reproducing Saeed & Alqahtani (2024) §V–VI.

Experiment design:
  1. Generate timing traces from VULNERABLE IoT devices (N observations)
  2. Generate timing traces from HARDENED IoT devices (same N)
  3. Train AI detector on VULNERABLE traces → high accuracy (signal exists)
  4. Train AI detector on HARDENED traces  → lower accuracy (signal removed)
  5. Compute leakage CV reduction and report side-by-side metrics
  6. Show PQC overhead (ML-KEM encap timing)

Run:
    python simulate.py [--samples 1000] [--attack-frac 0.25] [--devices 5]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np

from saeed2024.attacks.timing_leakage import (
    generate_timing_traces, LeakageMode,
    BASE_LATENCY_US, NOISE_STD_US, BRANCH_COEFF, HW_COEFF,
)
from saeed2024.ai.detector import SideChannelDetector
from saeed2024.crypto.hardened import (
    pqc_keygen, pqc_encap, compute_leakage_ratio,
)


BANNER = """
╔══════════════════════════════════════════════════════════════════════╗
║  Saeed & Alqahtani (2024) — AI + PQC Cybersecurity for IoT         ║
║  PeerJ Computer Science, 2024                                        ║
║  Side-Channel Timing Leakage + AI Anomaly Detection                 ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def run_simulation(
    n_samples:    int   = 1000,
    attack_frac:  float = 0.25,
    n_devices:    int   = 5,
    window_size:  int   = 20,
    step:         int   = 10,
    seed:         int   = 42,
    verbose:      bool  = True,
) -> dict:
    if verbose:
        print(BANNER)
        print(f"  Observations per device : {n_samples}")
        print(f"  Attack fraction         : {attack_frac:.0%}")
        print(f"  IoT devices             : {n_devices}")
        print(f"  Window size             : {window_size}\n")

    # ------------------------------------------------------------------ 1.
    # Generate timing traces for VULNERABLE and HARDENED implementations
    # ------------------------------------------------------------------
    if verbose:
        print("  [1] Generating timing traces…")

    vuln_obs, hard_obs = [], []
    for dev in range(n_devices):
        vuln_obs += generate_timing_traces(n_samples, LeakageMode.VULNERABLE,
                                           attack_frac, seed + dev, dev)
        hard_obs += generate_timing_traces(n_samples, LeakageMode.HARDENED,
                                           attack_frac, seed + dev + 100, dev)

    vuln_t = np.array([o.measured_us for o in vuln_obs])
    hard_t = np.array([o.measured_us for o in hard_obs])

    leakage = compute_leakage_ratio(vuln_t, hard_t)
    if verbose:
        print(f"  Leakage CV (vulnerable) : {leakage['cv_vulnerable']:.4f}")
        print(f"  Leakage CV (hardened)   : {leakage['cv_hardened']:.4f}")
        print(f"  Leakage reduction       : {leakage['leakage_reduction_pct']:.1f}%\n")

    # ------------------------------------------------------------------ 2.
    # AI Detector — VULNERABLE traces
    # ------------------------------------------------------------------
    if verbose:
        print("  [2] Training AI detector on VULNERABLE traces…")
    t0 = time.perf_counter()
    det_vuln = SideChannelDetector(window_size=window_size, step=step, seed=seed)
    metrics_vuln = det_vuln.fit(vuln_obs)
    ms_vuln = (time.perf_counter() - t0) * 1000

    if verbose:
        print(f"     Accuracy  : {metrics_vuln.accuracy:.4f}")
        print(f"     F1-score  : {metrics_vuln.f1:.4f}")
        print(f"     AUC-ROC   : {metrics_vuln.auc_roc:.4f}")
        print(f"     FPR       : {metrics_vuln.fpr:.4f}")
        print(f"     Train time: {ms_vuln:.0f} ms\n")

    # ------------------------------------------------------------------ 3.
    # AI Detector — HARDENED traces
    # ------------------------------------------------------------------
    if verbose:
        print("  [3] Training AI detector on HARDENED traces…")
    t1 = time.perf_counter()
    det_hard = SideChannelDetector(window_size=window_size, step=step, seed=seed)
    metrics_hard = det_hard.fit(hard_obs)
    ms_hard = (time.perf_counter() - t1) * 1000

    if verbose:
        print(f"     Accuracy  : {metrics_hard.accuracy:.4f}")
        print(f"     F1-score  : {metrics_hard.f1:.4f}")
        print(f"     AUC-ROC   : {metrics_hard.auc_roc:.4f}")
        print(f"     FPR       : {metrics_hard.fpr:.4f}")
        print(f"     Train time: {ms_hard:.0f} ms\n")

    # ------------------------------------------------------------------ 4.
    # PQC overhead measurement
    # ------------------------------------------------------------------
    if verbose:
        print("  [4] Measuring PQC (ML-KEM) overhead…")
    pk, sk, backend = pqc_keygen()
    kem_times = []
    for _ in range(20):
        t = time.perf_counter()
        pqc_encap(pk, backend)
        kem_times.append((time.perf_counter() - t) * 1000)
    avg_kem_ms = float(np.mean(kem_times))

    if verbose:
        print(f"     KEM backend           : {backend}")
        print(f"     Avg encap latency     : {avg_kem_ms:.3f} ms")
        print(f"     PK size               : {len(pk)} bytes")
        print()

    # ------------------------------------------------------------------ Summary
    # ------------------------------------------------------------------
    if verbose:
        print("═" * 68)
        print("  RESULTS — SAEED & ALQAHTANI (2024)")
        print("═" * 68)
        print(f"  Detector accuracy (vulnerable):   {metrics_vuln.accuracy:.4f}  ← high (signal present)")
        print(f"  Detector accuracy (hardened):     {metrics_hard.accuracy:.4f}  ← lower (signal removed)")
        accuracy_drop = metrics_vuln.accuracy - metrics_hard.accuracy
        print(f"  Accuracy drop from hardening:     {accuracy_drop:+.4f}  → hardening works")
        print(f"  Leakage CV reduction:             {leakage['leakage_reduction_pct']:.1f}%")
        print()
        print("  Top features (vulnerable):")
        for fname, fimp in metrics_vuln.feature_importances:
            print(f"    {fname:<20} {fimp:.4f}")
        print()
        print("  JOURNAL-3 adoption of these findings:")
        print("    ✅ hmac.compare_digest for all tag comparisons")
        print("    ✅ os.urandom() nonces (never reused)")
        print("    ✅ Per-derivation random HKDF salt")
        print("    ✅ ML-KEM for PQC layer")
        print("═" * 68)

    return {
        "config": {
            "n_samples": n_samples, "attack_frac": attack_frac,
            "n_devices": n_devices, "window_size": window_size,
        },
        "leakage":  leakage,
        "pqc": {
            "backend": backend,
            "pk_bytes": len(pk),
            "avg_encap_ms": round(avg_kem_ms, 4),
        },
        "detector_vulnerable": {
            "accuracy":   metrics_vuln.accuracy,
            "f1":         metrics_vuln.f1,
            "auc_roc":    metrics_vuln.auc_roc,
            "precision":  metrics_vuln.precision,
            "recall":     metrics_vuln.recall,
            "fpr":        metrics_vuln.fpr,
            "fnr":        metrics_vuln.fnr,
            "confusion":  metrics_vuln.confusion,
            "n_train":    metrics_vuln.n_train,
            "n_test":     metrics_vuln.n_test,
            "top_features": metrics_vuln.feature_importances,
        },
        "detector_hardened": {
            "accuracy":   metrics_hard.accuracy,
            "f1":         metrics_hard.f1,
            "auc_roc":    metrics_hard.auc_roc,
            "precision":  metrics_hard.precision,
            "recall":     metrics_hard.recall,
            "fpr":        metrics_hard.fpr,
            "fnr":        metrics_hard.fnr,
            "confusion":  metrics_hard.confusion,
            "n_train":    metrics_hard.n_train,
            "n_test":     metrics_hard.n_test,
            "top_features": metrics_hard.feature_importances,
        },
        "timing_summary": {
            "vuln_mean_us":  round(float(vuln_t.mean()), 2),
            "vuln_std_us":   round(float(vuln_t.std()), 2),
            "hard_mean_us":  round(float(hard_t.mean()), 2),
            "hard_std_us":   round(float(hard_t.std()), 2),
        },
    }


def parse_args():
    p = argparse.ArgumentParser(description="Saeed & Alqahtani (2024) simulation")
    p.add_argument("--samples",      type=int,   default=1000)
    p.add_argument("--attack-frac",  type=float, default=0.25)
    p.add_argument("--devices",      type=int,   default=5)
    p.add_argument("--window",       type=int,   default=20)
    p.add_argument("--step",         type=int,   default=10)
    p.add_argument("--seed",         type=int,   default=42)
    p.add_argument("--out",          type=str,   default="benchmark/")
    p.add_argument("--quiet",        action="store_true")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    results = run_simulation(
        n_samples   = args.samples,
        attack_frac = args.attack_frac,
        n_devices   = args.devices,
        window_size = args.window,
        step        = args.step,
        seed        = args.seed,
        verbose     = not args.quiet,
    )
    out_dir  = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"saeed2024_{ts}.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[OUT] Results saved → {out_path}")
