"""
sensors/gateway.py
Field Gateway — Kappala et al. (2026).

The gateway:
  1. Holds the KEM secret key and the PSK.
  2. Receives TransmittedPackets from all sensor nodes.
  3. Decrypts based on the packet's EncryptionMode.
  4. Validates the decrypted payload.
  5. Aggregates per-round statistics for analysis.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from kappala2026.crypto.kem  import kem_decap, kem_keygen, KEMKeypair
from kappala2026.crypto.aead import aead_decrypt, AEADResult
from kappala2026.crypto.kdf  import derive_session_key, derive_psk_key
from kappala2026.adaptive.policy import EncryptionMode
from kappala2026.sensors.node import TransmittedPacket


@dataclass
class GatewayRoundStats:
    round_idx:             int
    n_packets:             int
    kyber_count:           int
    aes_only_count:        int
    plaintext_count:       int
    decryption_errors:     int
    total_wire_bytes:      int
    total_energy_uj:       float
    avg_theta:             float
    kyber_wire_bytes:      int
    gradient_wire_bytes:   int   # AES_ONLY + PLAINTEXT bytes


class FieldGateway:
    """
    Central field gateway that decrypts all incoming sensor packets.

    Parameters
    ----------
    psk : bytes   Pre-shared 32-byte symmetric key (same as on all nodes).
    """

    def __init__(self, psk: bytes):
        self.psk     = psk
        self._keypair: KEMKeypair = kem_keygen()
        self.round_stats: List[GatewayRoundStats] = []

        # Totals
        self._total_packets       = 0
        self._total_kyber         = 0
        self._total_aes_only      = 0
        self._total_plaintext     = 0
        self._total_errors        = 0
        self._total_energy_uj     = 0.0
        self._total_wire_bytes    = 0
        self._total_kyber_bytes   = 0

    @property
    def public_key(self) -> bytes:
        return self._keypair.public_key

    def process_round(
        self,
        round_idx: int,
        packets:   List[TransmittedPacket],
    ) -> GatewayRoundStats:
        """Decrypt and validate all packets in one simulation round."""
        kyber_ct   = 0
        aes_ct     = 0
        plain_ct   = 0
        errors     = 0
        wire_total = 0
        nrg_total  = 0.0
        theta_sum  = 0.0
        kyber_wire = 0
        other_wire = 0

        for pkt in packets:
            wire_total += pkt.wire_size
            nrg_total  += pkt.energy_uj
            theta_sum  += pkt.theta_at_send
            ad = bytes([pkt.sensor_id, pkt.packet_id % 256])

            try:
                if pkt.encryption_mode == EncryptionMode.KYBER_AES:
                    ss  = kem_decap(pkt.kem_ciphertext, self._keypair.secret_key)
                    key = derive_session_key(ss, pkt.sensor_id, pkt.packet_id)
                    aead_decrypt(key, pkt.aead_result, ad)
                    kyber_ct   += 1
                    kyber_wire += pkt.wire_size

                elif pkt.encryption_mode == EncryptionMode.AES_ONLY:
                    key = derive_psk_key(self.psk, pkt.sensor_id, pkt.packet_id)
                    aead_decrypt(key, pkt.aead_result, ad)
                    aes_ct     += 1
                    other_wire += pkt.wire_size

                else:  # PLAINTEXT
                    assert pkt.plaintext is not None
                    plain_ct   += 1
                    other_wire += pkt.wire_size

            except Exception:
                errors += 1

        n = len(packets) or 1
        stats = GatewayRoundStats(
            round_idx           = round_idx,
            n_packets           = len(packets),
            kyber_count         = kyber_ct,
            aes_only_count      = aes_ct,
            plaintext_count     = plain_ct,
            decryption_errors   = errors,
            total_wire_bytes    = wire_total,
            total_energy_uj     = nrg_total,
            avg_theta           = theta_sum / n,
            kyber_wire_bytes    = kyber_wire,
            gradient_wire_bytes = other_wire,
        )
        self.round_stats.append(stats)

        self._total_packets    += len(packets)
        self._total_kyber      += kyber_ct
        self._total_aes_only   += aes_ct
        self._total_plaintext  += plain_ct
        self._total_errors     += errors
        self._total_energy_uj  += nrg_total
        self._total_wire_bytes += wire_total
        self._total_kyber_bytes += kyber_wire

        return stats

    def summary(self) -> dict:
        n = self._total_packets or 1
        return {
            "total_packets":       self._total_packets,
            "kyber_packets":       self._total_kyber,
            "aes_only_packets":    self._total_aes_only,
            "plaintext_packets":   self._total_plaintext,
            "decryption_errors":   self._total_errors,
            "kyber_fraction":      round(self._total_kyber / n, 4),
            "total_energy_uj":     round(self._total_energy_uj, 2),
            "avg_energy_uj":       round(self._total_energy_uj / n, 4),
            "total_wire_bytes":    self._total_wire_bytes,
            "kyber_wire_bytes":    self._total_kyber_bytes,
            "kem_overhead_frac":   round(
                self._total_kyber_bytes / self._total_wire_bytes, 4
            ) if self._total_wire_bytes else 0.0,
        }
