from __future__ import annotations

import numpy as np

from pqbfl.fl.model import LogisticModel


def fedavg(models: list[tuple[LogisticModel, int]]) -> LogisticModel:
    if not models:
        raise ValueError("no models")

    total = sum(n for _, n in models)
    if total <= 0:
        raise ValueError("total weight must be > 0")

    print(f"    [Aggregator] Starting FedAvg for {len(models)} models (Total samples: {total})...")

    base_model = models[0][0]
    new_w = np.zeros_like(base_model.w)
    new_b = 0.0

    for m, n in models:
        coef = n / total
        new_w += coef * m.w
        new_b += coef * m.b

    new_m = base_model.copy()
    new_m.w = new_w
    new_m.b = float(new_b)
    return new_m


def coord_median(models: list[tuple[LogisticModel, int]]) -> LogisticModel:
    """Coordinate-wise median aggregator (unweighted).

    Useful as a simple robust alternative to FedAvg.
    """

    if not models:
        raise ValueError("no models")

    print(f"    [Aggregator] Starting Coordinate Median for {len(models)} models...")

    w_stack = np.stack([m.w for m, _ in models], axis=0)  # shape: (n_models, d)
    b_stack = np.array([m.b for m, _ in models])          # shape: (n_models,)

    new_w = np.median(w_stack, axis=0)
    new_b = np.median(b_stack)

    base_model = models[0][0]
    new_m = base_model.copy()
    new_m.w = new_w
    new_m.b = float(new_b)
    return new_m


def trimmed_mean(models: list[tuple[LogisticModel, int]], *, trim_ratio: float = 0.1) -> LogisticModel:
    """Coordinate-wise trimmed mean aggregator (unweighted).

    trim_ratio=0.1 trims 10% lowest and 10% highest values per coordinate.
    """

    if not models:
        raise ValueError("no models")
    if not (0.0 <= trim_ratio < 0.5):
        raise ValueError("trim_ratio must be in [0, 0.5)")

    print(f"    [Aggregator] Starting Trimmed Mean for {len(models)} models (Trim ratio: {trim_ratio})...")

    n = len(models)
    k = int(np.floor(trim_ratio * n))

    w_stack = np.stack([m.w for m, _ in models], axis=0)
    b_stack = np.array([m.b for m, _ in models])

    if k == 0:
        new_w = np.mean(w_stack, axis=0)
        new_b = np.mean(b_stack)
    elif 2 * k >= n:
        raise ValueError("trim_ratio too large for number of models")
    else:
        # Sort along the model axis
        w_sorted = np.sort(w_stack, axis=0)
        b_sorted = np.sort(b_stack)

        # Trim k from top and bottom
        w_trim = w_sorted[k : n - k]
        b_trim = b_sorted[k : n - k]

        new_w = np.mean(w_trim, axis=0)
        new_b = np.mean(b_trim)

    base_model = models[0][0]
    new_m = base_model.copy()
    new_m.w = new_w
    new_m.b = float(new_b)
    return new_m
