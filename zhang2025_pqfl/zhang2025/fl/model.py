"""
fl/model.py
Simple logistic-regression model used in the FL simulation.

Zhang et al. evaluate on healthcare / sensitive datasets.
We implement a numpy-only logistic regression with:
  • Sigmoid activation
  • Binary cross-entropy loss
  • SGD weight update

The model parameters (weights + bias) are the gradient payload transmitted
between clients and the server in every FL round.
"""
from __future__ import annotations

import numpy as np


def _sigmoid(z: np.ndarray) -> np.ndarray:
    """Numerically stable sigmoid."""
    return np.where(z >= 0, 1 / (1 + np.exp(-z)), np.exp(z) / (1 + np.exp(z)))


class LogisticModel:
    """
    Binary logistic regression for federated learning.

    Parameters are stored as a flat weight vector W (n_features,) and a
    scalar bias b.  The combined parameter vector is W (n_features+1,) =
    [W | b] for serialisation convenience.
    """

    def __init__(self, n_features: int, seed: int = 0):
        rng = np.random.default_rng(seed)
        self.W: np.ndarray = rng.normal(0, 0.01, n_features).astype(np.float32)
        self.b: float = 0.0
        self.n_features = n_features

    # ------------------------------------------------------------------
    # Serialisation helpers (for gradient payload accounting)
    # ------------------------------------------------------------------

    def get_params(self) -> np.ndarray:
        """Return flat [W | b] parameter array (float32)."""
        return np.append(self.W, self.b).astype(np.float32)

    def set_params(self, params: np.ndarray) -> None:
        """Load flat [W | b] parameter array."""
        self.W = params[:-1].astype(np.float32)
        self.b = float(params[-1])

    @property
    def param_bytes(self) -> int:
        """Wire size of serialised parameters in bytes (float32 = 4 bytes each)."""
        return (self.n_features + 1) * 4

    # ------------------------------------------------------------------
    # Forward / loss
    # ------------------------------------------------------------------

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return _sigmoid(X @ self.W + self.b)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X) >= 0.5).astype(int)

    def loss(self, X: np.ndarray, y: np.ndarray, eps: float = 1e-8) -> float:
        p = np.clip(self.predict_proba(X), eps, 1 - eps)
        return float(-np.mean(y * np.log(p) + (1 - y) * np.log(1 - p)))

    def accuracy(self, X: np.ndarray, y: np.ndarray) -> float:
        return float(np.mean(self.predict(X) == y))

    # ------------------------------------------------------------------
    # SGD local training step
    # ------------------------------------------------------------------

    def local_train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        lr: float = 0.01,
        epochs: int = 5,
        batch_size: int = 64,
        l2_lambda: float = 1e-4,
    ) -> np.ndarray:
        """
        Run local SGD and return the gradient delta (param_new − param_old).

        This delta is what gets encrypted and transmitted to the server.
        """
        old_params = self.get_params().copy()
        n = len(X)
        rng = np.random.default_rng()

        for _ in range(epochs):
            idx = rng.permutation(n)
            for start in range(0, n, batch_size):
                batch_idx = idx[start : start + batch_size]
                Xb, yb = X[batch_idx], y[batch_idx]

                p = self.predict_proba(Xb)
                error = p - yb.astype(np.float32)

                grad_W = (Xb.T @ error) / len(Xb) + l2_lambda * self.W
                grad_b = float(np.mean(error))

                self.W -= lr * grad_W
                self.b -= lr * grad_b

        return self.get_params() - old_params  # gradient delta Δ_{i,r}

    # ------------------------------------------------------------------
    # Cloning (for server-side fresh initialisation)
    # ------------------------------------------------------------------

    def clone(self) -> "LogisticModel":
        m = LogisticModel(self.n_features)
        m.set_params(self.get_params().copy())
        return m
