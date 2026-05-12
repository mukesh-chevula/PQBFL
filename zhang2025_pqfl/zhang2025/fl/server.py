"""
fl/server.py
FL Aggregation Server — Zhang et al. (2025) full-stack PQ-FL implementation.

Responsibilities:
  • Generate and publish ML-KEM session keypair per epoch.
  • Decapsulate client KEM ciphertexts → per-client shared secrets.
  • Derive per-client root keys and manage static ratchets (server-mirror).
  • Decrypt per-round encrypted gradients from all clients.
  • FedAvg aggregation → updated global model.
  • Track per-round overhead and convergence metrics.

Static Lj design constraint (Zhang et al.):
  Every L_j rounds ALL clients must do a fresh KEM exchange.
  This is the overhead that the paper quantifies as ~40-50% over classical ECDH-based FL.
"""
from __future__ import annotations

import io
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

from zhang2025.crypto.kem    import kyber_keygen, kyber_decap, KyberKeypair
from zhang2025.crypto.kdf    import derive_root_key, derive_chain_key, derive_message_key
from zhang2025.crypto.ratchet import StaticRatchet
from zhang2025.crypto.aead   import aead_decrypt
from zhang2025.fl.model      import LogisticModel
from zhang2025.fl.client     import FLClient, RoundResult


@dataclass
class RoundMetrics:
    round_idx: int
    accuracy: float
    loss: float
    n_clients_active: int
    kem_exchanges_this_round: int
    total_wire_bytes_this_round: int     # gradient bytes + KEM bytes
    gradient_bytes_this_round: int
    kem_bytes_this_round: int
    aggregate_ms: float
    overhead_fraction: float             # KEM / total


class FLServer:
    """
    Central aggregation server.

    Parameters
    ----------
    n_features : int
    lj         : int   Fixed ratchet window (same for all clients).
    dp_epsilon : float Differential privacy noise (0 = disabled).
    dp_delta   : float DP delta parameter.
    """

    def __init__(
        self,
        n_features: int,
        lj: int = 10,
        dp_epsilon: float = 0.0,
        dp_delta: float = 1e-5,
    ):
        self.n_features  = n_features
        self.lj          = lj
        self.dp_epsilon  = dp_epsilon
        self.dp_delta    = dp_delta

        self.global_model = LogisticModel(n_features, seed=0)
        self.round_metrics: List[RoundMetrics] = []

        # Per-session KEM state
        self._keypair: Optional[KyberKeypair] = None
        # Per-client server-side ratchets (mirrors client ratchets)
        self._server_ratchets: Dict[int, StaticRatchet] = {}

        # Cumulative overhead
        self._total_wire_bytes = 0
        self._total_kem_bytes  = 0
        self._total_gradient_bytes = 0
        self._total_kem_exchanges  = 0

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def new_session(self) -> bytes:
        """
        Generate a fresh ML-KEM keypair and return the public key.
        Called at the start of the experiment and every L_j rounds.
        """
        self._keypair = kyber_keygen()
        return self._keypair.public_key

    def register_client_kem(
        self,
        client_id: int,
        kem_ciphertext: bytes,
    ) -> None:
        """
        Decapsulate a client's KEM ciphertext, derive root key, init ratchet.
        """
        ss = kyber_decap(kem_ciphertext, self._keypair.secret_key)
        root_key = derive_root_key(ss)

        ratchet = StaticRatchet(lj=self.lj, kem_wire_bytes=len(kem_ciphertext))
        ratchet.begin_session(root_key)
        self._server_ratchets[client_id] = ratchet
        self._total_kem_exchanges += 1

    # ------------------------------------------------------------------
    # Per-round processing
    # ------------------------------------------------------------------

    def aggregate_round(
        self,
        round_idx: int,
        round_results: List[RoundResult],
        dataset_test,   # FederatedDataset
    ) -> RoundMetrics:
        """
        Decrypt all client gradients, run FedAvg, update global model.
        """
        t0 = time.perf_counter()

        decrypted_deltas: List[np.ndarray] = []
        grad_bytes = 0
        kem_bytes  = 0

        for result in round_results:
            # Advance server-side ratchet for this client
            srv_ratchet = self._server_ratchets[result.client_id]
            msg_key = srv_ratchet.advance()

            # Decrypt gradient
            ad = struct.pack(">II", result.client_id, round_idx)
            raw = aead_decrypt(msg_key, result.encrypted_gradient, ad)

            buf = io.BytesIO(raw)
            delta = np.load(buf)
            decrypted_deltas.append(delta)

            grad_bytes += result.wire_gradient_bytes
            kem_bytes  += result.wire_kem_bytes

        # ------------------------------------------------------------------
        # FedAvg: simple mean of gradient deltas
        # ------------------------------------------------------------------
        avg_delta = np.mean(decrypted_deltas, axis=0)

        # Optional: add Gaussian DP noise to the aggregated gradient
        if self.dp_epsilon > 0.0:
            avg_delta = self._add_dp_noise(avg_delta, sensitivity=1.0)

        # Apply delta to global model
        new_params = self.global_model.get_params() + avg_delta
        self.global_model.set_params(new_params)

        # ------------------------------------------------------------------
        # Evaluate on global test set
        # ------------------------------------------------------------------
        acc  = self.global_model.accuracy(dataset_test.X_test, dataset_test.y_test)
        loss = self.global_model.loss(dataset_test.X_test, dataset_test.y_test)

        aggregate_ms   = (time.perf_counter() - t0) * 1000
        total_wire     = grad_bytes + kem_bytes
        overhead_frac  = kem_bytes / total_wire if total_wire > 0 else 0.0

        # Check how many KEM exchanges happened this round
        kem_exchanges = sum(
            1 for r in round_results if r.wire_kem_bytes > 0
        )

        m = RoundMetrics(
            round_idx                  = round_idx,
            accuracy                   = acc,
            loss                       = loss,
            n_clients_active           = len(round_results),
            kem_exchanges_this_round   = kem_exchanges,
            total_wire_bytes_this_round= total_wire,
            gradient_bytes_this_round  = grad_bytes,
            kem_bytes_this_round       = kem_bytes,
            aggregate_ms               = aggregate_ms,
            overhead_fraction          = overhead_frac,
        )
        self.round_metrics.append(m)

        # Accumulate
        self._total_wire_bytes     += total_wire
        self._total_kem_bytes      += kem_bytes
        self._total_gradient_bytes += grad_bytes

        return m

    # ------------------------------------------------------------------
    # Differential Privacy
    # ------------------------------------------------------------------

    def _add_dp_noise(self, gradient: np.ndarray, sensitivity: float) -> np.ndarray:
        """
        Add calibrated Gaussian noise for (epsilon, delta)-DP.
        Noise scale: σ = sensitivity * sqrt(2 * ln(1.25/delta)) / epsilon
        """
        import math
        sigma = sensitivity * math.sqrt(2 * math.log(1.25 / self.dp_delta)) / self.dp_epsilon
        noise = np.random.normal(0, sigma, gradient.shape).astype(np.float32)
        return gradient + noise

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def overhead_summary(self) -> dict:
        n_rounds = len(self.round_metrics)
        avg_acc  = float(np.mean([m.accuracy for m in self.round_metrics])) if self.round_metrics else 0.0
        avg_overhead = float(np.mean([m.overhead_fraction for m in self.round_metrics])) if self.round_metrics else 0.0
        total_kem_exchanges = self._total_kem_exchanges
        return {
            "n_rounds":              n_rounds,
            "lj_fixed":              self.lj,
            "final_accuracy":        float(self.round_metrics[-1].accuracy) if self.round_metrics else 0.0,
            "avg_accuracy":          avg_acc,
            "total_wire_bytes":      self._total_wire_bytes,
            "total_kem_bytes":       self._total_kem_bytes,
            "total_gradient_bytes":  self._total_gradient_bytes,
            "avg_overhead_fraction": round(avg_overhead, 4),
            "kem_bytes_per_round":   round(self._total_kem_bytes / n_rounds, 2) if n_rounds else 0.0,
            "kem_exchanges":         total_kem_exchanges,
        }
