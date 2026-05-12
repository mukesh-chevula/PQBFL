"""
fl/client.py
PQS-BFL FL Client — Commey et al. (2025).

Each client holds a STATIC ML-DSA keypair registered on-chain at init.
Per round:
  1. Pull global parameters → local SGD → gradient delta Δ
  2. Serialise Δ → sign with static ML-DSA key → encrypt with AES-GCM
  3. Submit {encrypted_gradient, ML-DSA_signature, KEM_ciphertext} to server

KEY DESIGN GAP (static key):
  The ML-DSA signing key is NEVER rotated.  A single key compromise at
  round R lets the adversary forge gradient signatures for ALL subsequent
  rounds and retroactively authenticate malicious past updates.
  JOURNAL-3 closes this via ML-KEM ratcheting (key rotation every L_j rounds).
"""
from __future__ import annotations

import io, struct, time
from dataclasses import dataclass
from typing import Optional
import numpy as np

from commey2025.crypto.dsa  import dsa_keygen, dsa_sign, DSAKeypair, DSASignResult
from commey2025.crypto.kem  import kem_encap, KEMKeypair
from commey2025.crypto.aead import aead_encrypt, AEADPacket
from commey2025.blockchain.block import GradientCommitment

# Simple logistic regression (same as zhang2025 baseline)
def _sigmoid(z): return np.where(z>=0, 1/(1+np.exp(-z)), np.exp(z)/(1+np.exp(z)))


class LocalModel:
    def __init__(self, n: int, seed: int = 0):
        rng = np.random.default_rng(seed)
        self.W = rng.normal(0, 0.01, n).astype(np.float32)
        self.b = 0.0; self.n = n

    def params(self): return np.append(self.W, self.b).astype(np.float32)
    def load(self, p): self.W, self.b = p[:-1].astype(np.float32), float(p[-1])

    def train(self, X, y, lr=0.01, epochs=5, bs=64, l2=1e-4):
        old = self.params().copy()
        rng = np.random.default_rng()
        for _ in range(epochs):
            for s in range(0, len(X), bs):
                idx = rng.integers(0, len(X), min(bs, len(X)))
                Xb, yb = X[idx], y[idx]
                p = _sigmoid(Xb@self.W+self.b)
                e = p - yb.astype(np.float32)
                self.W -= lr*((Xb.T@e)/len(Xb)+l2*self.W)
                self.b -= lr*float(e.mean())
        return self.params() - old


@dataclass
class ClientRoundResult:
    client_id:        int
    round_idx:        int
    encrypted_grad:   AEADPacket
    sign_result:      DSASignResult
    kem_ciphertext:   bytes
    gradient_bytes:   bytes         # raw serialised gradient (for signing)
    gradient_shape:   tuple
    wire_sig_bytes:   int
    wire_grad_bytes:  int
    wire_kem_bytes:   int
    train_ms:         float
    sign_ms:          float

    @property
    def total_wire_bytes(self) -> int:
        return self.wire_sig_bytes + self.wire_grad_bytes + self.wire_kem_bytes

    def make_commitment(self) -> GradientCommitment:
        return GradientCommitment.from_bytes(
            self.client_id,
            self.gradient_bytes,
            self.sign_result.signature,
            self.sign_result.public_key,
            self.total_wire_bytes,
        )


class PQSBFLClient:
    """
    A PQS-BFL federated learning client.

    Holds a STATIC ML-DSA keypair for signing and a one-time KEM session key.
    """

    def __init__(self, client_id: int, dataset, n_features: int,
                 lr=0.01, epochs=5):
        self.client_id = client_id
        self.dataset   = dataset
        self.model     = LocalModel(n_features, seed=client_id)
        self.lr, self.epochs = lr, epochs

        # Static ML-DSA keypair — generated ONCE, never rotated (paper design)
        self.dsa_keypair: DSAKeypair = dsa_keygen()
        self._session_key: Optional[bytes] = None

    def setup_session(self, server_pk: bytes) -> bytes:
        """KEM encapsulation to establish session key."""
        enc = kem_encap(server_pk)
        import hashlib, hmac as _hmac, struct
        self._session_key = hashlib.sha256(enc.shared_secret).digest()
        return enc.ciphertext

    def do_round(self, global_params: np.ndarray, round_idx: int) -> ClientRoundResult:
        self.model.load(global_params.copy())

        # Local SGD
        t0 = time.perf_counter()
        delta = self.model.train(self.dataset.X, self.dataset.y,
                                 lr=self.lr, epochs=self.epochs)
        train_ms = (time.perf_counter()-t0)*1000

        # Serialise gradient
        buf = io.BytesIO(); np.save(buf, delta)
        grad_bytes = buf.getvalue()

        # ML-DSA sign (static key — the design gap)
        t1 = time.perf_counter()
        sig = dsa_sign(grad_bytes, self.dsa_keypair)
        sign_ms = (time.perf_counter()-t1)*1000

        # Encrypt with session key
        key = self._session_key or b'\x00'*32
        ad  = struct.pack(">II", self.client_id, round_idx)
        enc_grad = aead_encrypt(key, grad_bytes, ad)

        return ClientRoundResult(
            client_id       = self.client_id,
            round_idx       = round_idx,
            encrypted_grad  = enc_grad,
            sign_result     = sig,
            kem_ciphertext  = b"",
            gradient_bytes  = grad_bytes,
            gradient_shape  = delta.shape,
            wire_sig_bytes  = sig.wire_size,
            wire_grad_bytes = enc_grad.wire_size,
            wire_kem_bytes  = 0,
            train_ms        = train_ms,
            sign_ms         = sign_ms,
        )

    @property
    def public_key(self) -> bytes:
        return self.dsa_keypair.public_key
