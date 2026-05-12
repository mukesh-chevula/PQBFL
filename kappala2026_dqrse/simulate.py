"""
simulate.py
End-to-end simulation of Kappala et al. (2026) Dynamic Quantum-Resistant
Selective Encryption for agricultural sensor networks.

Run:
    python simulate.py [--sensors 5] [--packets 200] [--rounds 20]
                       [--theta-lo 0.25] [--theta-hi 0.65]
                       [--attack-at 5,12]   (round numbers that inject events)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np

from kappala2026.crypto.kem       import KEM_BACKEND, KEM_PUBLIC_KEY_BYTES, KEM_CIPHERTEXT_BYTES
from kappala2026.adaptive.policy  import DataTier, EncryptionMode, SelectiveEncryptionPolicy
from kappala2026.adaptive.threat_engine import ThreatEngine, EventType
from kappala2026.sensors.data     import generate_packet_stream, TIER_MAP
from kappala2026.sensors.node     import SensorNode
from kappala2026.sensors.gateway  import FieldGateway


BANNER = """
╔══════════════════════════════════════════════════════════════════════╗
║  Kappala et al. (2026) — Dynamic Quantum-Resistant Selective        ║
║  Encryption for Agricultural Sensors — IEEE Access                  ║
╚══════════════════════════════════════════════════════════════════════╝
"""

# Scenario scripts: list of (round, EventType, weight) tuples
SCENARIO_BENIGN = []   # no injected events
SCENARIO_ATTACK = [    # simulated attack timeline
    (3,  EventType.TIMING_JITTER,   None),
    (5,  EventType.REPLAY_ATTEMPT,  None),
    (5,  EventType.CHANNEL_ANOMALY, None),
    (7,  EventType.AUTH_FAILURE,    None),
    (8,  EventType.REPLAY_ATTEMPT,  0.55),
    (10, EventType.PHYSICAL_TAMPER, None),
    (14, EventType.POWER_SPIKE,     None),
    (17, EventType.TIMING_JITTER,   None),
]


def run_simulation(
    n_sensors:      int   = 5,
    packets_per_round: int = 30,
    n_rounds:       int   = 20,
    theta_lo:       float = 0.25,
    theta_hi:       float = 0.65,
    decay_seconds:  float = 2.0,    # simulated seconds between rounds
    attack_scenario: bool = True,
    seed:           int   = 42,
    verbose:        bool  = True,
) -> dict:
    """
    Full simulation loop.

    Returns a dict of per-round metrics and summary statistics.
    """
    if verbose:
        print(BANNER)
        print(f"  KEM backend    : {KEM_BACKEND}")
        print(f"  Sensors        : {n_sensors}")
        print(f"  Rounds         : {n_rounds}")
        print(f"  Packets/round  : {packets_per_round}")
        print(f"  θ_lo / θ_hi    : {theta_lo} / {theta_hi}")
        print(f"  Scenario       : {'Attack timeline' if attack_scenario else 'Benign only'}")
        print(f"  Decay step     : {decay_seconds}s simulated per round\n")

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    psk = os.urandom(32)   # pre-shared key (known to all nodes + gateway)

    gateway = FieldGateway(psk=psk)
    gw_pk   = gateway.public_key

    nodes = [
        SensorNode(
            node_id    = i,
            gateway_pk = gw_pk,
            psk        = psk,
            theta_lo   = theta_lo,
            theta_hi   = theta_hi,
        )
        for i in range(n_sensors)
    ]

    scenario = SCENARIO_ATTACK if attack_scenario else SCENARIO_BENIGN
    # Build lookup: round → list of (EventType, weight)
    attack_map: dict[int, list] = {}
    for (rnd, etype, w) in scenario:
        attack_map.setdefault(rnd, []).append((etype, w))

    all_round_metrics = []
    t_start = time.perf_counter()

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    for rnd in range(n_rounds):

        # 1. Inject attack events (if any scheduled for this round)
        injected_events = []
        if rnd in attack_map:
            for (etype, w) in attack_map[rnd]:
                for node in nodes:
                    theta = node.inject_event(etype, w)
                injected_events.append(etype.name)

        # 2. Generate packet stream for this round
        readings = generate_packet_stream(
            n_sensors   = n_sensors,
            n_packets   = packets_per_round,
            seed        = seed + rnd,
        )

        # 3. Each node transmits its assigned packets
        transmitted = []
        for reading in readings:
            node = nodes[reading.sensor_id]
            pkt  = node.transmit(reading)
            transmitted.append(pkt)

        # 4. Gateway processes the round
        stats = gateway.process_round(rnd, transmitted)

        # 5. Time decay between rounds (simulate elapsed wall-clock time)
        for node in nodes:
            node.time_step(decay_seconds)

        # 6. Collect per-round metrics
        avg_theta    = stats.avg_theta
        kyber_frac   = stats.kyber_count / (stats.n_packets or 1)
        energy_saved = _compute_energy_saved(transmitted)

        round_metric = {
            "round":            rnd,
            "n_packets":        stats.n_packets,
            "kyber_count":      stats.kyber_count,
            "aes_only_count":   stats.aes_only_count,
            "plaintext_count":  stats.plaintext_count,
            "kyber_fraction":   round(kyber_frac, 4),
            "avg_theta":        round(avg_theta, 4),
            "total_energy_uj":  round(stats.total_energy_uj, 2),
            "total_wire_bytes": stats.total_wire_bytes,
            "kyber_wire_bytes": stats.kyber_wire_bytes,
            "decryption_errors":stats.decryption_errors,
            "injected_events":  injected_events,
            "energy_saved_uj":  round(energy_saved, 2),
        }
        all_round_metrics.append(round_metric)

        if verbose:
            evt_tag = f"  ⚠ {', '.join(injected_events)}" if injected_events else ""
            print(
                f"  Round {rnd:>3} | θ={avg_theta:.3f} | "
                f"KEM={stats.kyber_count:>3} AES={stats.aes_only_count:>3} "
                f"PLAIN={stats.plaintext_count:>3} | "
                f"E={stats.total_energy_uj:,.0f}μJ | "
                f"wire={stats.total_wire_bytes:,}B{evt_tag}"
            )

    total_ms = (time.perf_counter() - t_start) * 1000
    gw_summary = gateway.summary()

    # ------------------------------------------------------------------
    # Energy savings vs always-KYBER-AES baseline
    # ------------------------------------------------------------------
    # If every packet used KYBER_AES: energy = n_packets × (KYBER_ENCAP + AES)
    from kappala2026.sensors.node import ENERGY_KEM_ENCAP_UJ, ENERGY_AES_PER_BYTE_UJ
    total_packets   = gw_summary["total_packets"]
    avg_payload     = 32   # bytes — mixed-tier average
    always_kyber_uj = total_packets * (ENERGY_KEM_ENCAP_UJ + avg_payload * ENERGY_AES_PER_BYTE_UJ)
    actual_uj       = gw_summary["total_energy_uj"]
    energy_saving_pct = (1 - actual_uj / always_kyber_uj) * 100 if always_kyber_uj else 0

    summary = {
        **gw_summary,
        "n_rounds":            n_rounds,
        "n_sensors":           n_sensors,
        "packets_per_round":   packets_per_round,
        "theta_lo":            theta_lo,
        "theta_hi":            theta_hi,
        "kem_backend":         KEM_BACKEND,
        "kem_pk_bytes":        KEM_PUBLIC_KEY_BYTES,
        "kem_ct_bytes":        KEM_CIPHERTEXT_BYTES,
        "always_kyber_uj":     round(always_kyber_uj, 2),
        "energy_saving_pct":   round(energy_saving_pct, 2),
        "total_simulation_ms": round(total_ms, 2),
        "attack_scenario":     attack_scenario,
    }

    if verbose:
        print("\n" + "═" * 68)
        print("  KAPPALA et al. (2026) — OVERHEAD ANALYSIS")
        print("═" * 68)
        print(f"  KEM backend           : {KEM_BACKEND}")
        print(f"  Total packets         : {total_packets:,}")
        print(f"  Kyber packets         : {gw_summary['kyber_packets']:,}  ({gw_summary['kyber_fraction']*100:.1f}%)")
        print(f"  AES-only packets      : {gw_summary['aes_only_packets']:,}")
        print(f"  Plaintext packets     : {gw_summary['plaintext_packets']:,}")
        print(f"  Total energy (actual) : {actual_uj:,.0f} μJ")
        print(f"  Energy if always-KEM  : {always_kyber_uj:,.0f} μJ")
        print(f"  Energy saved          : {energy_saving_pct:.1f}%")
        print(f"  KEM wire overhead     : {gw_summary['kem_overhead_frac']*100:.1f}%")
        print(f"  Decryption errors     : {gw_summary['decryption_errors']}")
        print()
        print("  GAP vs JOURNAL-3 (Adaptive PQBFL):")
        print("    ✗ No blockchain event log — threat is node-local only")
        print("    ✗ No ratcheting — no Post-Compromise Security guarantee")
        print("    ✗ No FL — raw readings, not gradient updates")
        print("═" * 68)

    return {
        "config": {
            "n_sensors": n_sensors, "packets_per_round": packets_per_round,
            "n_rounds": n_rounds, "theta_lo": theta_lo, "theta_hi": theta_hi,
            "attack_scenario": attack_scenario,
        },
        "per_round": all_round_metrics,
        "summary":   summary,
    }


def _compute_energy_saved(packets) -> float:
    """Energy saved vs always-encrypting with KYBER_AES."""
    from kappala2026.sensors.node import ENERGY_KEM_ENCAP_UJ, ENERGY_AES_PER_BYTE_UJ
    saved = 0.0
    for pkt in packets:
        if pkt.encryption_mode != EncryptionMode.KYBER_AES:
            saved += ENERGY_KEM_ENCAP_UJ   # each non-KEM packet saves one KEM cost
    return saved


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Kappala et al. (2026) DQRSE simulation")
    p.add_argument("--sensors",      type=int,   default=5)
    p.add_argument("--packets",      type=int,   default=30,
                   help="Packets per round")
    p.add_argument("--rounds",       type=int,   default=20)
    p.add_argument("--theta-lo",     type=float, default=0.25)
    p.add_argument("--theta-hi",     type=float, default=0.65)
    p.add_argument("--decay",        type=float, default=2.0,
                   help="Simulated seconds between rounds (threat decay)")
    p.add_argument("--benign",       action="store_true",
                   help="Use benign-only scenario (no injected events)")
    p.add_argument("--seed",         type=int,   default=42)
    p.add_argument("--out",          type=str,   default="benchmark/")
    p.add_argument("--quiet",        action="store_true")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    results = run_simulation(
        n_sensors        = args.sensors,
        packets_per_round= args.packets,
        n_rounds         = args.rounds,
        theta_lo         = args.theta_lo,
        theta_hi         = args.theta_hi,
        decay_seconds    = args.decay,
        attack_scenario  = not args.benign,
        seed             = args.seed,
        verbose          = not args.quiet,
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    scenario_tag = "attack" if not args.benign else "benign"
    out_path = out_dir / f"kappala2026_{scenario_tag}_{ts}.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[OUT] Results saved → {out_path}")
