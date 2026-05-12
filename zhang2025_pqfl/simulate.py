"""
simulate.py
End-to-end simulation of the Zhang et al. (2025) full-stack PQ-FL protocol.

Run:
    python simulate.py [--rounds 30] [--clients 5] [--lj 10] [--dp-epsilon 0]

Output:
    • Per-round metrics printed to stdout
    • JSON results saved to benchmark/results_<timestamp>.json
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import time
from datetime import datetime
from pathlib import Path

import numpy as np

from zhang2025.crypto.kem    import KEM_BACKEND, KEM_PUBLIC_KEY_BYTES, KEM_CIPHERTEXT_BYTES
from zhang2025.fl.data       import make_synthetic_dataset
from zhang2025.fl.client     import FLClient
from zhang2025.fl.server     import FLServer
from zhang2025.privacy.dp    import GaussianDP, compute_rdp_epsilon


BANNER = """
╔══════════════════════════════════════════════════════════════════════╗
║  Zhang et al. (2025) — Full-Stack Private Federated Deep Learning   ║
║  with Post-Quantum Security — Simulation                             ║
║  IEEE Transactions on Dependable and Secure Computing                ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def run_simulation(
    n_rounds:   int   = 30,
    n_clients:  int   = 5,
    lj:         int   = 10,
    n_samples:  int   = 5_000,
    n_features: int   = 46,
    lr:         float = 0.01,
    epochs:     int   = 5,
    iid:        bool  = True,
    dp_epsilon: float = 0.0,
    dp_delta:   float = 1e-5,
    dp_max_norm:float = 1.0,
    seed:       int   = 42,
    verbose:    bool  = True,
) -> dict:
    """
    Full simulation loop.

    Returns a dict of all round metrics and summary statistics.
    """
    if verbose:
        print(BANNER)
        print(f"  KEM backend   : {KEM_BACKEND}")
        print(f"  Clients       : {n_clients}")
        print(f"  Rounds        : {n_rounds}")
        print(f"  Lj (fixed)    : {lj}  ← static, never changes")
        print(f"  Features      : {n_features}")
        print(f"  Data split    : {'IID' if iid else 'non-IID (Dirichlet)'}")
        if dp_epsilon > 0:
            dp = GaussianDP(dp_epsilon, dp_delta, dp_max_norm)
            print(f"  DP            : ε={dp_epsilon}, δ={dp_delta:.0e}, σ={dp.sigma:.4f}")
        else:
            print(f"  DP            : disabled")
        print()

    # ------------------------------------------------------------------
    # 1. Dataset
    # ------------------------------------------------------------------
    dataset = make_synthetic_dataset(
        n_clients=n_clients,
        n_samples=n_samples,
        n_features=n_features,
        iid=iid,
        seed=seed,
    )
    if verbose:
        print(f"[DATA] {dataset.total_train_samples} train samples across "
              f"{dataset.n_clients} clients | {len(dataset.X_test)} test samples")

    # ------------------------------------------------------------------
    # 2. Server initialisation
    # ------------------------------------------------------------------
    server = FLServer(
        n_features=n_features,
        lj=lj,
        dp_epsilon=dp_epsilon,
        dp_delta=dp_delta,
    )
    dp_mechanism = GaussianDP(dp_epsilon, dp_delta, dp_max_norm) if dp_epsilon > 0 else None

    # ------------------------------------------------------------------
    # 3. Client initialisation
    # ------------------------------------------------------------------
    clients = [
        FLClient(
            client_id=i,
            dataset=dataset.clients[i],
            n_features=n_features,
            lj=lj,
            lr=lr,
            epochs=epochs,
        )
        for i in range(n_clients)
    ]

    # ------------------------------------------------------------------
    # 4. Initial KEM session setup (session epoch 0)
    # ------------------------------------------------------------------
    server_pk = server.new_session()
    session_kem_bytes = len(server_pk) + KEM_CIPHERTEXT_BYTES  # pk broadcast + ct per client

    if verbose:
        print(f"\n[SETUP] Session 0 — KEM key broadcast")
        print(f"        Server PK size : {len(server_pk):,} bytes")
        print(f"        Client CT size : {KEM_CIPHERTEXT_BYTES:,} bytes")
        print(f"        Total KEM cost : {n_clients * KEM_CIPHERTEXT_BYTES + len(server_pk):,} bytes\n")

    # Each client encapsulates
    for client in clients:
        ct = client.setup_session(server_pk)
        server.register_client_kem(client.client_id, ct)

    # ------------------------------------------------------------------
    # 5. Main federated training loop
    # ------------------------------------------------------------------
    all_round_metrics = []
    total_time_ms = 0.0
    t_start = time.perf_counter()

    for rnd in range(n_rounds):
        # --- Check if any client needs re-keying (Lj exhausted) ---
        need_rekey = any(c.needs_rekey for c in clients)
        kem_this_round_bytes = 0

        if need_rekey:
            if verbose:
                print(f"  [KEM ↻] Round {rnd:>3} — L_j={lj} exhausted → new KEM session")
            server_pk = server.new_session()
            for client in clients:
                ct = client.setup_session(server_pk)
                server.register_client_kem(client.client_id, ct)
            # Account for KEM bytes this round
            kem_this_round_bytes = len(server_pk) + n_clients * KEM_CIPHERTEXT_BYTES

        # --- Global params broadcast ---
        global_params = server.global_model.get_params()

        # --- Each client trains and encrypts ---
        round_results = []
        for client in clients:
            result = client.do_round(global_params, rnd)
            result.wire_kem_bytes = kem_this_round_bytes // n_clients if need_rekey else 0
            round_results.append(result)

        # --- Server decrypts, aggregates, evaluates ---
        metrics = server.aggregate_round(rnd, round_results, dataset)

        # --- Update overhead for KEM exchange rounds ---
        if need_rekey:
            metrics.kem_bytes_this_round += kem_this_round_bytes
            metrics.kem_exchanges_this_round = n_clients

        all_round_metrics.append(metrics)

        if verbose:
            kem_tag = f" [+KEM {kem_this_round_bytes:,}B]" if need_rekey else ""
            print(
                f"  Round {rnd:>3} | acc={metrics.accuracy:.4f} | "
                f"loss={metrics.loss:.4f} | "
                f"wire={metrics.total_wire_bytes_this_round:,}B{kem_tag}"
            )

    total_ms = (time.perf_counter() - t_start) * 1000

    # ------------------------------------------------------------------
    # 6. Results & summary
    # ------------------------------------------------------------------
    summary = server.overhead_summary()
    summary["total_simulation_ms"]     = round(total_ms, 2)
    summary["kem_backend"]             = KEM_BACKEND
    summary["kem_pk_bytes"]            = KEM_PUBLIC_KEY_BYTES
    summary["kem_ct_bytes"]            = KEM_CIPHERTEXT_BYTES
    summary["n_clients"]               = n_clients
    summary["n_features"]              = n_features
    summary["iid"]                     = iid

    # DP budget
    if dp_epsilon > 0:
        dp = GaussianDP(dp_epsilon, dp_delta, dp_max_norm)
        actual_eps = compute_rdp_epsilon(
            sigma=dp.sigma,
            q=1.0 / n_clients,
            n_rounds=n_rounds,
            delta=dp_delta,
        )
        summary["dp_epsilon_spent"] = round(actual_eps, 4)
        summary["dp_sigma"]         = round(dp.sigma, 4)

    if verbose:
        print("\n" + "═" * 68)
        print("  OVERHEAD ANALYSIS  (reproduced from Zhang et al. §IV)")
        print("═" * 68)
        print(f"  KEM backend                  : {KEM_BACKEND}")
        print(f"  Fixed L_j                    : {lj}")
        print(f"  Total KEM bytes              : {summary['total_kem_bytes']:,}")
        print(f"  Total gradient bytes         : {summary['total_gradient_bytes']:,}")
        print(f"  Total wire bytes             : {summary['total_wire_bytes']:,}")
        print(f"  Avg KEM overhead fraction    : {summary['avg_overhead_fraction']*100:.1f}%")
        print(f"  KEM bytes/round (amortised)  : {summary['kem_bytes_per_round']:.1f}")
        print(f"  Final accuracy               : {summary['final_accuracy']:.4f}")
        print(f"  Total simulation time        : {total_ms:.1f} ms")
        print()
        print("  NOTE: Adaptive PQBFL (JOURNAL-3) reduces KEM overhead by ~76%")
        print("        by only triggering KEM when threat signal t > threshold.")
        print("═" * 68)

    return {
        "config": {
            "n_rounds": n_rounds, "n_clients": n_clients, "lj": lj,
            "n_samples": n_samples, "n_features": n_features,
            "lr": lr, "epochs": epochs, "iid": iid,
            "dp_epsilon": dp_epsilon, "dp_delta": dp_delta,
        },
        "per_round": [
            {
                "round": m.round_idx,
                "accuracy": round(m.accuracy, 6),
                "loss": round(m.loss, 6),
                "kem_exchanges": m.kem_exchanges_this_round,
                "wire_bytes": m.total_wire_bytes_this_round,
                "gradient_bytes": m.gradient_bytes_this_round,
                "kem_bytes": m.kem_bytes_this_round,
                "overhead_fraction": round(m.overhead_fraction, 4),
                "aggregate_ms": round(m.aggregate_ms, 3),
            }
            for m in all_round_metrics
        ],
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Zhang et al. (2025) PQ-FL simulation"
    )
    p.add_argument("--rounds",      type=int,   default=30)
    p.add_argument("--clients",     type=int,   default=5)
    p.add_argument("--lj",          type=int,   default=10,
                   help="Fixed symmetric ratchet window (Zhang et al. design)")
    p.add_argument("--samples",     type=int,   default=5000)
    p.add_argument("--features",    type=int,   default=46)
    p.add_argument("--lr",          type=float, default=0.01)
    p.add_argument("--epochs",      type=int,   default=5)
    p.add_argument("--non-iid",     action="store_true", default=False)
    p.add_argument("--dp-epsilon",  type=float, default=0.0,
                   help="DP epsilon (0 = disabled)")
    p.add_argument("--dp-delta",    type=float, default=1e-5)
    p.add_argument("--dp-max-norm", type=float, default=1.0)
    p.add_argument("--seed",        type=int,   default=42)
    p.add_argument("--out",         type=str,   default="benchmark/",
                   help="Output directory for JSON results")
    p.add_argument("--quiet",       action="store_true", default=False)
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    results = run_simulation(
        n_rounds    = args.rounds,
        n_clients   = args.clients,
        lj          = args.lj,
        n_samples   = args.samples,
        n_features  = args.features,
        lr          = args.lr,
        epochs      = args.epochs,
        iid         = not args.non_iid,
        dp_epsilon  = args.dp_epsilon,
        dp_delta    = args.dp_delta,
        dp_max_norm = args.dp_max_norm,
        seed        = args.seed,
        verbose     = not args.quiet,
    )

    # Save JSON
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"zhang2025_lj{args.lj}_{ts}.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[OUT] Results saved → {out_path}")
