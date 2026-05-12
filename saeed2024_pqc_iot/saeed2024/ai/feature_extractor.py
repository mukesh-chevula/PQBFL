"""
ai/feature_extractor.py
Timing-trace feature extraction for the AI anomaly detector.

Saeed & Alqahtani (2024) §IV extract statistical features from windows of
timing observations and feed them to a machine-learning classifier.

Features per window (n observations):
  1.  mean_us          — average timing
  2.  std_us           — standard deviation (spread of leakage signal)
  3.  min_us           — minimum timing (indicates fast-path branches)
  4.  max_us           — maximum timing
  5.  range_us         — max - min (total leakage range)
  6.  skewness         — asymmetry of timing distribution
  7.  kurtosis         — tail heaviness (spikes → attack probes)
  8.  entropy_bits     — Shannon entropy of binned timing histogram
  9.  autocorr_lag1    — lag-1 autocorrelation (pattern repetition)
  10. cv               — coefficient of variation (relative spread)
  11. p10, p25, p75, p90 — percentiles (distribution shape)
  12. n_outliers       — count of observations > mean + 3σ (spike detection)
"""
from __future__ import annotations

from typing import List
import numpy as np
from scipy import stats as sp_stats


FEATURE_NAMES = [
    "mean_us", "std_us", "min_us", "max_us", "range_us",
    "skewness", "kurtosis", "entropy_bits", "autocorr_lag1", "cv",
    "p10", "p25", "p75", "p90", "n_outliers",
]


def extract_features(timings: np.ndarray) -> np.ndarray:
    """
    Extract 15 statistical features from a window of timing measurements.

    Args:
        timings: 1-D array of timing values in microseconds.

    Returns:
        Feature vector of shape (15,).
    """
    if len(timings) < 2:
        return np.zeros(len(FEATURE_NAMES), dtype=np.float32)

    mu  = float(np.mean(timings))
    sig = float(np.std(timings)) + 1e-9
    mn  = float(np.min(timings))
    mx  = float(np.max(timings))

    # Shannon entropy on 20-bin histogram
    counts, _ = np.histogram(timings, bins=20)
    probs = counts / (counts.sum() + 1e-9)
    entropy = float(-sum(p * np.log2(p + 1e-9) for p in probs if p > 0))

    # Lag-1 autocorrelation
    if len(timings) > 2:
        autocorr = float(np.corrcoef(timings[:-1], timings[1:])[0, 1])
    else:
        autocorr = 0.0

    # Outliers: > mean + 3σ
    n_outliers = int(np.sum(timings > mu + 3 * sig))

    feats = np.array([
        mu,
        sig,
        mn,
        mx,
        mx - mn,
        float(sp_stats.skew(timings)),
        float(sp_stats.kurtosis(timings)),
        entropy,
        autocorr if np.isfinite(autocorr) else 0.0,
        sig / mu,
        float(np.percentile(timings, 10)),
        float(np.percentile(timings, 25)),
        float(np.percentile(timings, 75)),
        float(np.percentile(timings, 90)),
        float(n_outliers),
    ], dtype=np.float32)

    return feats


def build_feature_matrix(
    all_timings:  List[float],
    all_labels:   List[int],     # 1 = attack, 0 = benign
    window_size:  int = 20,
    step:         int = 10,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Sliding-window feature extraction over a timing trace.

    Args:
        all_timings:  Full timing sequence.
        all_labels:   Per-observation attack label.
        window_size:  Observations per window.
        step:         Stride between windows.

    Returns:
        X: (n_windows, n_features)  feature matrix
        y: (n_windows,)             window label (1 if >50% samples are attacks)
    """
    arr = np.array(all_timings, dtype=np.float32)
    lbl = np.array(all_labels,  dtype=np.int32)

    X_rows, y_rows = [], []
    for start in range(0, len(arr) - window_size + 1, step):
        window_t = arr[start : start + window_size]
        window_l = lbl[start : start + window_size]
        X_rows.append(extract_features(window_t))
        # Label the window as 'attack' if ≥30% of samples are attack probes
        y_rows.append(int(window_l.mean() >= 0.30))

    return np.array(X_rows, dtype=np.float32), np.array(y_rows, dtype=np.int32)
