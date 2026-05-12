"""
simulate.py — PQS-BFL end-to-end simulation (Commey et al. 2025).

Run:
    python simulate.py [--clients 5] [--rounds 20] [--samples 4000]
"""
from __future__ import annotations
import argparse, json, sys, time
from datetime import datetime
from pathlib import Path

import numpy as np

from commey2025.crypto.dsa  import DSA_BACKEND, DSA_PUBLIC_KEY_BYTES, DSA_SIGNATURE_BYTES
from commey2025.crypto.kem  import KEM_BACKEND, KEM_PUBLIC_KEY_BYTES, KEM_CIPHERTEXT_BYTES
from commey2025.fl.data     import make_healthcare_dataset
from commey2025.fl.client   import PQSBFLClient
from commey2025.fl.server   import PQSBFLServer

BANNER = """
╔══════════════════════════════════════════════════════════════════════╗
║  Commey et al. (2025) — PQS-BFL: Post-Quantum Secure BFL           ║
║  arXiv:2505.01866  |  Healthcare Analytics Domain                   ║
║  ML-DSA (Dilithium) + Blockchain + FedAvg  [No ratcheting]         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

def run_simulation(
    n_clients:  int   = 5,
    n_rounds:   int   = 20,
    n_samples:  int   = 4000,
    n_features: int   = 46,
    lr:         float = 0.01,
    epochs:     int   = 5,
    seed:       int   = 42,
    verbose:    bool  = True,
) -> dict:
    if verbose:
        print(BANNER)
        print(f"  DSA backend    : {DSA_BACKEND}")
        print(f"  DSA sig size   : {DSA_SIGNATURE_BYTES} bytes (per client per round)")
        print(f"  KEM backend    : {KEM_BACKEND}")
        print(f"  Clients        : {n_clients}")
        print(f"  Rounds         : {n_rounds}")
        print(f"  Healthcare data: {n_samples} samples, {n_features} features\n")

    # Setup
    dataset = make_healthcare_dataset(n_clients, n_samples, n_features, seed=seed)
    server  = PQSBFLServer(n_features)

    clients = [
        PQSBFLClient(i, dataset.clients[i], n_features, lr=lr, epochs=epochs)
        for i in range(n_clients)
    ]

    # Registration phase
    for c in clients:
        kem_ct = c.setup_session(server.public_key)
        server.register_client(c, kem_ct)

    # Training
    all_metrics = []
    t_start = time.perf_counter()
    for rnd in range(n_rounds):
        gp = server.global_model.params()
        results = [c.do_round(gp.copy(), rnd) for c in clients]
        m = server.aggregate_round(rnd, results, dataset)

        all_metrics.append({
            "round":             m.round_idx,
            "accuracy":          round(m.accuracy, 4),
            "loss":              round(m.loss, 4),
            "n_accepted":        m.n_accepted,
            "n_rejected":        m.n_rejected,
            "total_wire_bytes":  m.total_wire_bytes,
            "sig_wire_bytes":    m.sig_wire_bytes,
            "grad_wire_bytes":   m.grad_wire_bytes,
            "sig_overhead_frac": round(m.sig_overhead_frac, 4),
            "block_hash":        m.block_hash,
            "chain_height":      m.chain_height,
            "avg_sign_ms":       round(m.avg_sign_ms, 3),
        })

        if verbose:
            print(f"  Round {rnd:>3} | acc={m.accuracy:.4f} loss={m.loss:.4f} | "
                  f"acc={m.n_accepted}/{m.n_submitted} | "
                  f"wire={m.total_wire_bytes:,}B sig_ovhd={m.sig_overhead_frac*100:.1f}% | "
                  f"blk#{m.chain_height}")

    total_ms = (time.perf_counter()-t_start)*1000
    summary  = server.summary()
    summary["total_simulation_ms"] = round(total_ms, 2)
    summary["dsa_backend"]         = DSA_BACKEND
    summary["dsa_sig_bytes"]       = DSA_SIGNATURE_BYTES
    summary["dsa_pk_bytes"]        = DSA_PUBLIC_KEY_BYTES
    summary["kem_backend"]         = KEM_BACKEND

    if verbose:
        print(f"\n{'═'*68}")
        print("  COMMEY et al. (2025) — OVERHEAD ANALYSIS")
        print(f"{'═'*68}")
        print(f"  DSA: {DSA_BACKEND}  sig={DSA_SIGNATURE_BYTES}B / client / round")
        print(f"  Total rounds             : {n_rounds}")
        print(f"  Final accuracy           : {summary['final_accuracy']:.4f}")
        print(f"  Chain height             : {summary['chain_height']} blocks")
        print(f"  Chain valid              : {summary['chain_valid']}")
        print(f"  Total sig verifications  : {summary['total_sig_verifications']}")
        print(f"  Sig overhead fraction    : {summary['avg_sig_overhead']*100:.1f}%")
        print(f"  Accept rate              : {summary['accept_rate']*100:.1f}%")
        print()
        print("  GAP vs JOURNAL-3 (Adaptive PQBFL):")
        print("    ✗ Static ML-DSA key — NEVER rotated → no Post-Compromise Security")
        print("    ✗ No ThreatMonitor / θ signal → no adaptive key management")
        print("    ✗ No ratchet window L_j → key exposure unlimited in time")
        print(f"{'═'*68}")

    return {"config": {"n_clients":n_clients,"n_rounds":n_rounds,"n_samples":n_samples,
                       "n_features":n_features,"lr":lr,"epochs":epochs},
            "per_round": all_metrics, "summary": summary}


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--clients",  type=int,   default=5)
    p.add_argument("--rounds",   type=int,   default=20)
    p.add_argument("--samples",  type=int,   default=4000)
    p.add_argument("--features", type=int,   default=46)
    p.add_argument("--lr",       type=float, default=0.01)
    p.add_argument("--epochs",   type=int,   default=5)
    p.add_argument("--seed",     type=int,   default=42)
    p.add_argument("--out",      type=str,   default="benchmark/")
    p.add_argument("--quiet",    action="store_true")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    res  = run_simulation(args.clients, args.rounds, args.samples, args.features,
                          args.lr, args.epochs, args.seed, not args.quiet)
    out  = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    fp   = out / f"commey2025_{ts}.json"
    fp.write_text(json.dumps(res, indent=2))
    print(f"\n[OUT] → {fp}")
