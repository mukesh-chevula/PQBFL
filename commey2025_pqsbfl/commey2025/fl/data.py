"""
fl/data.py — Healthcare dataset for Commey et al. (2025).
Commey et al. evaluate on healthcare analytics (same domain as PQBFL).
We reuse the synthetic binary-classification generator from Zhang et al.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List
import numpy as np


@dataclass(frozen=True)
class ClientDataset:
    client_id: int
    X: np.ndarray
    y: np.ndarray

@dataclass(frozen=True)
class FederatedDataset:
    clients: List[ClientDataset]
    X_test:  np.ndarray
    y_test:  np.ndarray
    n_features: int
    name: str = "healthcare_synthetic"

    @property
    def n_clients(self) -> int: return len(self.clients)
    @property
    def total_train_samples(self) -> int: return sum(len(c.X) for c in self.clients)


def make_healthcare_dataset(
    n_clients:  int   = 5,
    n_samples:  int   = 4000,
    n_features: int   = 46,
    test_frac:  float = 0.20,
    seed:       int   = 42,
) -> FederatedDataset:
    rng = np.random.default_rng(seed)
    n_test  = int(n_samples * test_frac)
    n_train = n_samples - n_test
    n_pos   = int(n_train * 0.35)
    n_neg   = n_train - n_pos

    cp = rng.normal(0.5, 1.0, n_features)
    cn = rng.normal(-0.5, 1.0, n_features)
    Xp = rng.normal(cp, 0.8, (n_pos, n_features)).astype(np.float32)
    Xn = rng.normal(cn, 0.8, (n_neg, n_features)).astype(np.float32)
    X  = np.vstack([Xp, Xn]); y = np.array([1]*n_pos+[0]*n_neg, dtype=np.int32)
    mu, sig = X.mean(0), X.std(0)+1e-8
    perm = rng.permutation(n_train); X, y = (X-mu)/sig, y
    X, y = X[perm], y[perm]

    splits = np.array_split(rng.permutation(n_train), n_clients)
    clients = [ClientDataset(i, X[s], y[s]) for i, s in enumerate(splits)]

    n_tp = int(n_test * 0.35)
    Xt = ((np.vstack([rng.normal(cp,.8,(n_tp,n_features)),
                      rng.normal(cn,.8,(n_test-n_tp,n_features))]).astype(np.float32)-mu)/sig)
    yt = np.array([1]*n_tp+[0]*(n_test-n_tp), dtype=np.int32)
    pt = rng.permutation(n_test)

    return FederatedDataset(clients=clients, X_test=Xt[pt], y_test=yt[pt], n_features=n_features)
