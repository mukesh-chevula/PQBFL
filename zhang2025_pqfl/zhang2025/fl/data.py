"""
fl/data.py
Synthetic and real-data loaders for Zhang et al. (2025) FL simulation.

Synthetic data simulates a healthcare binary classification task
(e.g., patient readmission risk) with configurable non-IID distribution
across clients (Dirichlet-α partitioning).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
import numpy as np


@dataclass(frozen=True)
class ClientDataset:
    client_id: int
    X: np.ndarray    # (n_samples, n_features)  float32
    y: np.ndarray    # (n_samples,)              int


@dataclass(frozen=True)
class FederatedDataset:
    clients: List[ClientDataset]
    X_test:  np.ndarray
    y_test:  np.ndarray
    n_features: int
    name: str = "synthetic"

    @property
    def n_clients(self) -> int:
        return len(self.clients)

    @property
    def total_train_samples(self) -> int:
        return sum(len(c.X) for c in self.clients)


def make_synthetic_dataset(
    n_clients: int = 5,
    n_samples: int = 4_000,
    n_features: int = 46,
    test_frac: float = 0.20,
    iid: bool = True,
    alpha: float = 0.5,        # Dirichlet α for non-IID split
    class_imbalance: float = 0.35,  # fraction of positive class
    seed: int = 42,
) -> FederatedDataset:
    """
    Generate synthetic binary-classification data partitioned across clients.

    Args:
        n_clients:       Number of FL clients.
        n_samples:       Total samples (train + test).
        n_features:      Feature dimensionality (default 46 matches IoTID20).
        test_frac:       Fraction held out as global test set.
        iid:             If True, random IID split; else Dirichlet-α non-IID.
        alpha:           Dirichlet concentration (lower → more non-IID).
        class_imbalance: Positive-class prevalence.
        seed:            RNG seed for reproducibility.

    Returns:
        FederatedDataset with per-client train splits and a global test split.
    """
    rng = np.random.default_rng(seed)

    # ------------------------------------------------------------------
    # 1. Generate raw synthetic features and labels
    # ------------------------------------------------------------------
    n_test  = int(n_samples * test_frac)
    n_train = n_samples - n_test

    # Two-cluster Gaussian per class
    n_pos = int(n_train * class_imbalance)
    n_neg = n_train - n_pos

    centre_pos = rng.normal(0.5, 1.0, n_features)
    centre_neg = rng.normal(-0.5, 1.0, n_features)

    X_pos = rng.normal(centre_pos, 0.8, (n_pos, n_features)).astype(np.float32)
    X_neg = rng.normal(centre_neg, 0.8, (n_neg, n_features)).astype(np.float32)
    X_train_raw = np.vstack([X_pos, X_neg])
    y_train_raw = np.array([1] * n_pos + [0] * n_neg, dtype=np.int32)

    # Shuffle
    perm = rng.permutation(n_train)
    X_train_raw, y_train_raw = X_train_raw[perm], y_train_raw[perm]

    # Standardise
    mu, sigma = X_train_raw.mean(0), X_train_raw.std(0) + 1e-8
    X_train = (X_train_raw - mu) / sigma

    # Test set
    n_pos_t = int(n_test * class_imbalance)
    n_neg_t = n_test - n_pos_t
    X_test_raw = np.vstack([
        rng.normal(centre_pos, 0.8, (n_pos_t, n_features)).astype(np.float32),
        rng.normal(centre_neg, 0.8, (n_neg_t, n_features)).astype(np.float32),
    ])
    y_test = np.array([1] * n_pos_t + [0] * n_neg_t, dtype=np.int32)
    perm_t = rng.permutation(n_test)
    X_test  = ((X_test_raw - mu) / sigma)[perm_t]
    y_test  = y_test[perm_t]

    # ------------------------------------------------------------------
    # 2. Partition among clients
    # ------------------------------------------------------------------
    if iid:
        splits = _iid_split(X_train, y_train_raw, n_clients, rng)
    else:
        splits = _dirichlet_split(X_train, y_train_raw, n_clients, alpha, rng)

    clients = [
        ClientDataset(client_id=i, X=sx, y=sy)
        for i, (sx, sy) in enumerate(splits)
    ]

    return FederatedDataset(
        clients=clients,
        X_test=X_test,
        y_test=y_test,
        n_features=n_features,
        name="synthetic_healthcare",
    )


# ---------------------------------------------------------------------------
# Partition helpers
# ---------------------------------------------------------------------------

def _iid_split(
    X: np.ndarray,
    y: np.ndarray,
    n_clients: int,
    rng: np.random.Generator,
) -> List[tuple]:
    n = len(X)
    idx = rng.permutation(n)
    splits = np.array_split(idx, n_clients)
    return [(X[s], y[s]) for s in splits]


def _dirichlet_split(
    X: np.ndarray,
    y: np.ndarray,
    n_clients: int,
    alpha: float,
    rng: np.random.Generator,
) -> List[tuple]:
    """Dirichlet label distribution split (standard FL non-IID benchmark)."""
    classes = np.unique(y)
    client_indices: List[List[int]] = [[] for _ in range(n_clients)]

    for cls in classes:
        cls_idx = np.where(y == cls)[0].tolist()
        rng.shuffle(cls_idx)
        proportions = rng.dirichlet([alpha] * n_clients)
        proportions = (proportions / proportions.sum() * len(cls_idx)).astype(int)
        # Fix rounding
        proportions[-1] = len(cls_idx) - proportions[:-1].sum()
        start = 0
        for c, p in enumerate(proportions):
            client_indices[c].extend(cls_idx[start : start + p])
            start += p

    result = []
    for idx_list in client_indices:
        arr = np.array(idx_list)
        result.append((X[arr], y[arr]))
    return result
