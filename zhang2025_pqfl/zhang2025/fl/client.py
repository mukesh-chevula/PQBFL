"""
fl/client.py
FL Client — Zhang et al. (2025) full-stack PQ-FL implementation.

Each client:
  1. Holds a local dataset and a local model replica.
  2. On session start: receives server PK, performs ML-KEM encapsulation,
     derives session root key, and initialises a StaticRatchet.
  3. Each round: trains locally, serialises gradient delta, derives per-round
     AES-256-GCM key via ratchet.advance(), encrypts gradient, returns
     AEADCiphertext + accounting stats.
  4. After L_j rounds: triggers a new KEM exchange (static re-key).
"""
from __future__ import annotations

import io
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from zhang2025.crypto.kem    import kyber_encap, KyberEncapResult
from zhang2025.crypto.kdf    import derive_root_key
from zhang2025.crypto.ratchet import StaticRatchet
from zhang2025.crypto.aead   import aead_encrypt, AEADCiphertext
from zhang2025.fl.model      import LogisticModel


@dataclass
class RoundResult:
    """Everything the server needs to process one round from this client."""
    client_id: int
    round_idx: int
    session_epoch: int
    # Encrypted gradient
    encrypted_gradient: AEADCiphertext
    # KEM ciphertext (only non-empty during a KEM exchange round)
    kem_ciphertext: bytes
    # Plaintext gradient shape (for server-side decryption size assertion)
    gradient_shape: tuple
    # Timing
    local_train_ms: float
    encrypt_ms: float
    # Overhead accounting
    wire_gradient_bytes: int
    wire_kem_bytes: int


class FLClient:
    """
    A single federated learning participant.

    Parameters
    ----------
    client_id : int
    dataset   : ClientDataset
    n_features: int
    lj        : int   Fixed symmetric ratchet window (Zhang et al. design).
    lr, epochs: Local SGD hyper-parameters.
    """

    def __init__(
        self,
        client_id: int,
        dataset,            # ClientDataset
        n_features: int,
        lj: int = 10,
        lr: float = 0.01,
        epochs: int = 5,
        batch_size: int = 64,
        l2_lambda: float = 1e-4,
    ):
        self.client_id  = client_id
        self.dataset    = dataset
        self.lr         = lr
        self.epochs     = epochs
        self.batch_size = batch_size
        self.l2_lambda  = l2_lambda

        self.model   = LogisticModel(n_features, seed=client_id)
        self.ratchet = StaticRatchet(lj=lj, kem_wire_bytes=2272)

        self._kem_result: Optional[KyberEncapResult] = None

    # ------------------------------------------------------------------
    # Session setup — called once per session epoch
    # ------------------------------------------------------------------

    def setup_session(self, server_public_key: bytes) -> bytes:
        """
        Encapsulate to the server's ML-KEM public key and initialise ratchet.

        Returns:
            The KEM ciphertext to transmit to the server.
        """
        enc = kyber_encap(server_public_key)
        self._kem_result = enc

        root_key = derive_root_key(enc.shared_secret)
        self.ratchet.begin_session(root_key)
        return enc.ciphertext

    # ------------------------------------------------------------------
    # Per-round training and encryption
    # ------------------------------------------------------------------

    def do_round(
        self,
        global_params: np.ndarray,
        round_idx: int,
    ) -> RoundResult:
        """
        Execute one FL training round:
          1. Load global model parameters.
          2. Run local SGD → gradient delta Δ.
          3. Serialise Δ to bytes.
          4. Derive per-round key via ratchet.advance().
          5. Encrypt Δ with AES-256-GCM.
          6. If ratchet needs_rekey after advance, note it (server will call
             setup_session again before next round).

        Returns RoundResult with encrypted gradient + overhead stats.
        """
        # 1. Sync global model
        self.model.set_params(global_params.copy())

        # 2. Local SGD
        t0 = time.perf_counter()
        delta = self.model.local_train(
            self.dataset.X,
            self.dataset.y,
            lr=self.lr,
            epochs=self.epochs,
            batch_size=self.batch_size,
            l2_lambda=self.l2_lambda,
        )
        local_train_ms = (time.perf_counter() - t0) * 1000

        # 3. Serialise gradient delta → bytes
        buf = io.BytesIO()
        np.save(buf, delta)
        gradient_bytes = buf.getvalue()

        # 4. Per-round key from static ratchet
        msg_key = self.ratchet.advance()

        # 5. Encrypt
        t1 = time.perf_counter()
        ad = struct.pack(">II", self.client_id, round_idx)   # associated data
        enc_gradient = aead_encrypt(msg_key, gradient_bytes, ad)
        encrypt_ms   = (time.perf_counter() - t1) * 1000

        return RoundResult(
            client_id          = self.client_id,
            round_idx          = round_idx,
            session_epoch      = self.ratchet.state.session_epoch,
            encrypted_gradient = enc_gradient,
            kem_ciphertext     = b"",          # filled by server orchestration
            gradient_shape     = delta.shape,
            local_train_ms     = local_train_ms,
            encrypt_ms         = encrypt_ms,
            wire_gradient_bytes= enc_gradient.wire_size,
            wire_kem_bytes     = 0,
        )

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def needs_rekey(self) -> bool:
        return self.ratchet.needs_rekey

    def overhead_summary(self) -> dict:
        return {
            "client_id": self.client_id,
            **self.ratchet.overhead_summary(),
        }
