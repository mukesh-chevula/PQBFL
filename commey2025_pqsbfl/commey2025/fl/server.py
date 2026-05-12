"""
fl/server.py
PQS-BFL Aggregation Server — Commey et al. (2025).

Per round:
  1. Receive encrypted gradient + ML-DSA signature from each client
  2. Submit to smart contract → verify signature on-chain
  3. Append verified commitments to PoA blockchain
  4. Decrypt accepted gradients → FedAvg → update global model
  5. Log round metrics (sig overhead, wire bytes, accuracy)
"""
from __future__ import annotations

import io, struct, time
from dataclasses import dataclass
from typing import Dict, List

import numpy as np

from commey2025.crypto.kem  import kem_keygen, kem_decap, KEMKeypair
from commey2025.crypto.aead import aead_decrypt
from commey2025.blockchain.chain   import PQSBFLChain
from commey2025.fl.client  import PQSBFLClient, ClientRoundResult, LocalModel


def _sigmoid(z): return np.where(z>=0, 1/(1+np.exp(-z)), np.exp(z)/(1+np.exp(z)))


@dataclass
class RoundMetrics:
    round_idx:          int
    accuracy:           float
    loss:               float
    n_submitted:        int
    n_accepted:         int       # passed smart contract
    n_rejected:         int
    total_wire_bytes:   int
    sig_wire_bytes:     int
    grad_wire_bytes:    int
    sig_overhead_frac:  float
    block_hash:         str
    chain_height:       int
    aggregate_ms:       float
    avg_sign_ms:        float


class PQSBFLServer:
    def __init__(self, n_features: int):
        self.n_features   = n_features
        self.global_model = LocalModel(n_features, seed=0)
        self.chain        = PQSBFLChain()
        self._keypair: KEMKeypair  = kem_keygen()
        self._session_keys: Dict[int, bytes] = {}
        self.round_metrics: List[RoundMetrics] = []

    @property
    def public_key(self) -> bytes:
        return self._keypair.public_key

    def register_client(self, client: PQSBFLClient, kem_ct: bytes) -> bool:
        """Register client public key on-chain and derive session key."""
        ok = self.chain.contract.register(client.client_id, client.public_key)
        if ok:
            ss = kem_decap(kem_ct, self._keypair.secret_key)
            import hashlib
            self._session_keys[client.client_id] = hashlib.sha256(ss).digest()
        return ok

    def aggregate_round(
        self, round_idx: int,
        results: List[ClientRoundResult],
        dataset_test,
    ) -> RoundMetrics:
        t0 = time.perf_counter()

        accepted_deltas, commitments = [], []
        sig_bytes = grad_bytes_total = 0
        total_wire = 0
        sign_ms_list = []

        for r in results:
            # On-chain signature verification via smart contract
            ok = self.chain.contract.verify_gradient(
                r.client_id, round_idx,
                r.gradient_bytes, r.sign_result,
            )
            total_wire += r.total_wire_bytes
            sig_bytes  += r.wire_sig_bytes
            sign_ms_list.append(r.sign_ms)

            if ok:
                # Decrypt gradient
                key = self._session_keys.get(r.client_id, b'\x00'*32)
                ad  = struct.pack(">II", r.client_id, round_idx)
                raw = aead_decrypt(key, r.encrypted_grad, ad)
                delta = np.load(io.BytesIO(raw))
                accepted_deltas.append(delta)
                grad_bytes_total += r.wire_grad_bytes
                commitments.append(r.make_commitment())

        n_accepted = len(accepted_deltas)
        n_rejected = len(results) - n_accepted

        # FedAvg
        if accepted_deltas:
            avg_delta = np.mean(accepted_deltas, axis=0)
            self.global_model.load(self.global_model.params() + avg_delta)

        # Append block
        block = self.chain.append_round_block(
            round_idx, commitments,
            self.global_model.params(),
        )

        # Evaluate
        p = _sigmoid(dataset_test.X_test @ self.global_model.W + self.global_model.b)
        p = np.clip(p, 1e-8, 1-1e-8)
        acc  = float(np.mean((p >= 0.5).astype(int) == dataset_test.y_test))
        loss = float(-np.mean(dataset_test.y_test*np.log(p) + (1-dataset_test.y_test)*np.log(1-p)))

        agg_ms = (time.perf_counter()-t0)*1000
        sig_frac = sig_bytes / max(1, total_wire)

        m = RoundMetrics(
            round_idx         = round_idx,
            accuracy          = acc,
            loss              = loss,
            n_submitted       = len(results),
            n_accepted        = n_accepted,
            n_rejected        = n_rejected,
            total_wire_bytes  = total_wire,
            sig_wire_bytes    = sig_bytes,
            grad_wire_bytes   = grad_bytes_total,
            sig_overhead_frac = sig_frac,
            block_hash        = block.hash[:16] + "…",
            chain_height      = self.chain.height,
            aggregate_ms      = agg_ms,
            avg_sign_ms       = float(np.mean(sign_ms_list)) if sign_ms_list else 0.0,
        )
        self.round_metrics.append(m)
        return m

    def summary(self) -> dict:
        chain_s = self.chain.chain_summary()
        n = len(self.round_metrics) or 1
        return {
            **chain_s,
            "n_rounds":          n,
            "final_accuracy":    float(self.round_metrics[-1].accuracy) if self.round_metrics else 0.0,
            "avg_accuracy":      float(np.mean([m.accuracy for m in self.round_metrics])),
            "avg_sig_overhead":  round(float(np.mean([m.sig_overhead_frac for m in self.round_metrics])), 4),
            "avg_sign_ms":       round(float(np.mean([m.avg_sign_ms for m in self.round_metrics])), 4),
            "dsa_backend":       "see crypto/dsa.py",
        }
