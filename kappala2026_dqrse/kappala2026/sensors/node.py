"""
sensors/node.py
Agricultural IoT Sensor Node — Kappala et al. (2026).

Each node:
  1. Maintains a ThreatEngine that accumulates local security observations.
  2. Consults the SelectiveEncryptionPolicy before each packet transmission.
  3. Applies KYBER_AES / AES_ONLY / PLAINTEXT based on (tier, θ).
  4. Tracks energy consumption and latency per packet.
  5. Maintains a per-session KEM keypair for KYBER_AES packets;
     refreshes it on-demand (no fixed ratchet window — fully reactive).

Key gap vs JOURNAL-3:
  • No blockchain — there is no global, verifiable event log.
  • No ratcheting — session keys are refreshed ad-hoc, not via a formal
    ratchet protocol, so Post-Compromise Security is NOT guaranteed.
  • No FL — nodes send raw readings, not model gradients.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

from kappala2026.adaptive.policy import DataTier, EncryptionMode, SelectiveEncryptionPolicy
from kappala2026.adaptive.threat_engine import ThreatEngine, EventType
from kappala2026.crypto.kem  import kem_keygen, kem_encap, KEMKeypair, KEMEncapResult
from kappala2026.crypto.aead import aead_encrypt, AEADResult
from kappala2026.crypto.kdf  import derive_session_key, derive_psk_key
from kappala2026.sensors.data import SensorReading


# Energy model constants (Kappala et al. Table IV)
ENERGY_KEM_ENCAP_UJ    = 2_150.0   # μJ for Kyber-512 encap on Cortex-M4
ENERGY_AES_PER_BYTE_UJ =     0.12  # μJ per byte AES-256-GCM
ENERGY_IDLE_PER_PKT_UJ =     0.05  # μJ baseline overhead per packet


@dataclass
class TransmittedPacket:
    """Everything the gateway receives for one sensor packet."""
    sensor_id:      int
    packet_id:      int
    tier:           DataTier
    encryption_mode: EncryptionMode
    theta_at_send:  float

    # Encrypted payload (None for PLAINTEXT)
    aead_result:    Optional[AEADResult]
    plaintext:      Optional[bytes]          # only for PLAINTEXT mode

    # KEM ciphertext — only for KYBER_AES, None otherwise
    kem_ciphertext: Optional[bytes]

    # Overhead stats
    wire_size:      int     # total bytes on wire
    energy_uj:      float   # node energy consumed
    latency_ms:     float   # processing latency estimate

    @property
    def used_pq_encryption(self) -> bool:
        return self.encryption_mode == EncryptionMode.KYBER_AES


class SensorNode:
    """
    A single agricultural IoT sensor node.

    Parameters
    ----------
    node_id    : int    Unique node identifier.
    gateway_pk : bytes  Gateway's KEM public key (used for KYBER_AES packets).
    psk        : bytes  Pre-shared symmetric key (used for AES_ONLY packets).
    policy     : SelectiveEncryptionPolicy
    theta_lo/hi: float  Threat thresholds (passed to policy).
    """

    def __init__(
        self,
        node_id:    int,
        gateway_pk: bytes,
        psk:        bytes,
        theta_lo:   float = 0.25,
        theta_hi:   float = 0.65,
    ):
        self.node_id    = node_id
        self.gateway_pk = gateway_pk
        self.psk        = psk
        self.policy     = SelectiveEncryptionPolicy(theta_lo=theta_lo, theta_hi=theta_hi)
        self.threat     = ThreatEngine()

        # Stats
        self.packets_sent:         int   = 0
        self.kyber_packets:        int   = 0
        self.aes_only_packets:     int   = 0
        self.plaintext_packets:    int   = 0
        self.total_energy_uj:      float = 0.0
        self.total_wire_bytes:     int   = 0
        self.total_latency_ms:     float = 0.0

        # KEM session (refreshed when KYBER_AES is needed)
        self._kem_session_ss:     Optional[bytes] = None
        self._kem_ciphertext_buf: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Threat event injection
    # ------------------------------------------------------------------

    def inject_event(self, event_type: EventType, weight: float | None = None) -> float:
        """Record a security event and return new θ."""
        return self.threat.record_event(event_type, weight, sensor_id=self.node_id)

    def time_step(self, seconds: float = 1.0) -> float:
        """Advance simulation time (decays threat)."""
        return self.threat.decay_all(seconds)

    # ------------------------------------------------------------------
    # Packet transmission
    # ------------------------------------------------------------------

    def transmit(self, reading: SensorReading) -> TransmittedPacket:
        """
        Encrypt and "transmit" one sensor reading to the gateway.

        Decision flow:
          1. Get current θ from ThreatEngine.
          2. Query SelectiveEncryptionPolicy for EncryptionMode.
          3. Apply encryption accordingly.
          4. Return TransmittedPacket with all overhead metrics.
        """
        theta = self.threat.theta()
        mode  = self.policy.decide(reading.tier, theta)

        t_start = time.perf_counter()

        aead_result:    Optional[AEADResult] = None
        plaintext_out:  Optional[bytes]      = None
        kem_ct:         Optional[bytes]      = None
        energy_uj:      float                = ENERGY_IDLE_PER_PKT_UJ
        wire_size:      int                  = 0

        ad = bytes([reading.sensor_id, reading.packet_id % 256])

        if mode == EncryptionMode.KYBER_AES:
            # --- Full post-quantum: fresh KEM encap + AES-256-GCM ---
            enc_result = kem_encap(self.gateway_pk)
            kem_ct     = enc_result.ciphertext
            msg_key    = derive_session_key(enc_result.shared_secret,
                                            self.node_id, reading.packet_id)
            aead_result = aead_encrypt(msg_key, reading.payload, ad)
            wire_size   = len(kem_ct) + aead_result.wire_size
            energy_uj  += ENERGY_KEM_ENCAP_UJ + aead_result.energy_uj
            self.kyber_packets += 1

        elif mode == EncryptionMode.AES_ONLY:
            # --- Classical symmetric AES-256-GCM only ---
            msg_key    = derive_psk_key(self.psk, self.node_id, reading.packet_id)
            aead_result = aead_encrypt(msg_key, reading.payload, ad)
            wire_size   = aead_result.wire_size
            energy_uj  += aead_result.energy_uj
            self.aes_only_packets += 1

        else:  # PLAINTEXT
            plaintext_out = reading.payload
            wire_size     = len(reading.payload)
            # No encryption energy — just transmission baseline
            self.plaintext_packets += 1

        latency_ms = (time.perf_counter() - t_start) * 1000 + mode.latency_ms_estimate

        # Accumulate stats
        self.packets_sent    += 1
        self.total_energy_uj  += energy_uj
        self.total_wire_bytes += wire_size
        self.total_latency_ms += latency_ms

        return TransmittedPacket(
            sensor_id        = self.node_id,
            packet_id        = reading.packet_id,
            tier             = reading.tier,
            encryption_mode  = mode,
            theta_at_send    = theta,
            aead_result      = aead_result,
            plaintext        = plaintext_out,
            kem_ciphertext   = kem_ct,
            wire_size        = wire_size,
            energy_uj        = energy_uj,
            latency_ms       = latency_ms,
        )

    # ------------------------------------------------------------------
    # Stats summary
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        n = self.packets_sent or 1
        return {
            "node_id":             self.node_id,
            "packets_sent":        self.packets_sent,
            "kyber_packets":       self.kyber_packets,
            "aes_only_packets":    self.aes_only_packets,
            "plaintext_packets":   self.plaintext_packets,
            "kyber_fraction":      round(self.kyber_packets / n, 4),
            "total_energy_uj":     round(self.total_energy_uj, 2),
            "avg_energy_uj":       round(self.total_energy_uj / n, 4),
            "total_wire_bytes":    self.total_wire_bytes,
            "avg_latency_ms":      round(self.total_latency_ms / n, 4),
            "current_theta":       round(self.threat.last_theta, 4),
        }
