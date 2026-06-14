#!/usr/bin/env python3
"""
benchmark_high_scale_compare.py

Runs a high-scale benchmark comparing:
- Baseline PQBFL:      pqbfl_project
- SCR + Adaptive PQBFL: pqbfl_project new adaptive side channel resistant

Outputs:
- benchmark_results/high_scale/baseline_vs_scr_results.json
- benchmark_results/high_scale/graph_accuracy_high_scale.png
- benchmark_results/high_scale/graph_latency_high_scale.png
- benchmark_results/high_scale/graph_cost_high_scale.png
- benchmark_results/high_scale/graph_adaptive_high_scale.png
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

BASE = Path("/Users/mchevula/PQBFL")
OUT_DIR = BASE / "benchmark_results" / "high_scale"
CHAIN_URL = "http://127.0.0.1:8545"

BASELINE_DIR = BASE / "pqbfl_project" / "python"
SCR_DIR = BASE / "pqbfl_project new adaptive side channel resistant" / "python"

RUNNER_BASELINE = """
import json, sys, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, PKG_ROOT)
from pqbfl.scripts.demo_end_to_end import DemoConfig, run_demo

cfg = DemoConfig(
    chain_url=CHAIN_URL,
    rounds=ROUNDS,
    n_clients=N_CLIENTS,
    project_id=PROJECT_ID,
    dataset_type="synthetic",
    L_j=10,
)
res = run_demo(cfg)
out = {
    "variant": "baseline",
    "initial_accuracy": res.initial_accuracy,
    "final_accuracy": res.final_accuracy,
    "round_accuracies": res.round_accuracies,
    "total_transactions": res.total_transactions,
    "avg_transaction_time_ms": res.avg_transaction_time_ms,
    "min_transaction_time_ms": res.min_transaction_time_ms,
    "max_transaction_time_ms": res.max_transaction_time_ms,
    "total_operations": res.total_operations,
    "avg_operation_time_ms": res.avg_operation_time_ms,
    "min_operation_time_ms": res.min_operation_time_ms,
    "max_operation_time_ms": res.max_operation_time_ms,
    "tx_by_round": {},
    "op_by_round": {},
    "adaptive_enabled": False,
    "L_j_per_round": [],
    "threat_level_per_round": [],
    "ratchet_adjustments": [],
    "threat_events": [],
    "asymmetric_ratchet_rounds": [],
}
for t in res.transaction_timings:
    r = int(t.get("round", 0))
    out["tx_by_round"][r] = out["tx_by_round"].get(r, 0.0) + float(t.get("duration_ms", 0.0))
for op in res.operation_timings:
    r = int(op.get("round", 0))
    out["op_by_round"][r] = out["op_by_round"].get(r, 0.0) + float(op.get("duration_ms", 0.0))
print("__RESULT__:" + json.dumps(out))
"""

RUNNER_SCR = """
import json, sys, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, PKG_ROOT)
from pqbfl.scripts.demo_end_to_end import DemoConfig, run_demo

cfg = DemoConfig(
    chain_url=CHAIN_URL,
    rounds=ROUNDS,
    n_clients=N_CLIENTS,
    project_id=PROJECT_ID,
    dataset_type="synthetic",
    adaptive_enabled=True,
    L_min=2,
    L_max=20,
    L_default=10,
)
res = run_demo(cfg)
out = {
    "variant": "scr_adaptive",
    "initial_accuracy": res.initial_accuracy,
    "final_accuracy": res.final_accuracy,
    "round_accuracies": res.round_accuracies,
    "total_transactions": res.total_transactions,
    "avg_transaction_time_ms": res.avg_transaction_time_ms,
    "min_transaction_time_ms": res.min_transaction_time_ms,
    "max_transaction_time_ms": res.max_transaction_time_ms,
    "total_operations": res.total_operations,
    "avg_operation_time_ms": res.avg_operation_time_ms,
    "min_operation_time_ms": res.min_operation_time_ms,
    "max_operation_time_ms": res.max_operation_time_ms,
    "tx_by_round": {},
    "op_by_round": {},
    "adaptive_enabled": bool(res.adaptive_enabled),
    "L_j_per_round": list(getattr(res, "L_j_per_round", [])),
    "threat_level_per_round": [float(x) for x in getattr(res, "threat_level_per_round", [])],
    "ratchet_adjustments": list(getattr(res, "ratchet_adjustments", [])),
    "threat_events": list(getattr(res, "threat_events", [])),
    "asymmetric_ratchet_rounds": list(getattr(res, "asymmetric_ratchet_rounds", [])),
}
for t in res.transaction_timings:
    r = int(t.get("round", 0))
    out["tx_by_round"][r] = out["tx_by_round"].get(r, 0.0) + float(t.get("duration_ms", 0.0))
for op in res.operation_timings:
    r = int(op.get("round", 0))
    out["op_by_round"][r] = out["op_by_round"].get(r, 0.0) + float(op.get("duration_ms", 0.0))
print("__RESULT__:" + json.dumps(out))
"""


def _run_variant(
    python_exe: str,
    pkg_root: Path,
    script_template: str,
    rounds: int,
    n_clients: int,
    project_id: int,
    timeout_s: int,
) -> tuple[dict, float]:
    script = (
        script_template
        .replace("PKG_ROOT", repr(str(pkg_root)))
        .replace("CHAIN_URL", repr(CHAIN_URL))
        .replace("ROUNDS", str(rounds))
        .replace("N_CLIENTS", str(n_clients))
        .replace("PROJECT_ID", str(project_id))
    )

    t0 = time.time()
    proc = subprocess.run(
        [python_exe, "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout_s,
        env={**os.environ, "PYTHONWARNINGS": "ignore"},
    )
    elapsed = time.time() - t0

    if proc.returncode != 0:
        raise RuntimeError(
            "Variant run failed with exit code {}\nSTDOUT:\n{}\nSTDERR:\n{}".format(
                proc.returncode,
                proc.stdout[-5000:],
                proc.stderr[-5000:],
            )
        )

    marker = "__RESULT__:"
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith(marker)), None)
    if not line:
        raise RuntimeError("No __RESULT__ marker found in subprocess output")

    data = json.loads(line[len(marker):])
    return data, elapsed


def _series_from_per_round(per_round: dict, rounds: int) -> list[float]:
    vals = []
    for r in range(1, rounds + 1):
        vals.append(float(per_round.get(str(r), per_round.get(r, 0.0))))
    return vals


def _plot_accuracy(rounds: int, baseline: dict, scr: dict, out_path: Path) -> None:
    x = np.arange(0, rounds + 1)
    b = baseline["round_accuracies"]
    s = scr["round_accuracies"]

    plt.figure(figsize=(11, 5))
    plt.plot(x, b, label="Baseline PQBFL", color="#2D6CDF", linewidth=2.5)
    plt.plot(x, s, label="SCR + Adaptive PQBFL", color="#17986E", linewidth=2.5)
    plt.title("High-Scale Accuracy Curve")
    plt.xlabel("Round")
    plt.ylabel("Test Accuracy")
    plt.grid(alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def _plot_latency(rounds: int, baseline: dict, scr: dict, out_path: Path) -> None:
    x = np.arange(1, rounds + 1)
    b_tx = _series_from_per_round(baseline["tx_by_round"], rounds)
    b_op = _series_from_per_round(baseline["op_by_round"], rounds)
    s_tx = _series_from_per_round(scr["tx_by_round"], rounds)
    s_op = _series_from_per_round(scr["op_by_round"], rounds)

    b_total = np.array(b_tx) + np.array(b_op)
    s_total = np.array(s_tx) + np.array(s_op)

    plt.figure(figsize=(12, 5.5))
    plt.plot(x, b_total, label="Baseline total overhead/round", color="#2D6CDF", linewidth=2.2)
    plt.plot(x, s_total, label="SCR+Adaptive total overhead/round", color="#17986E", linewidth=2.2)
    plt.axhline(np.mean(b_total), color="#2D6CDF", linestyle=":", alpha=0.8)
    plt.axhline(np.mean(s_total), color="#17986E", linestyle=":", alpha=0.8)
    plt.title("High-Scale Per-Round Overhead (tx + off-chain ops)")
    plt.xlabel("Round")
    plt.ylabel("Time (ms)")
    plt.grid(alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def _plot_cost_bars(baseline: dict, scr: dict, out_path: Path) -> None:
    labels = ["Total tx", "Avg tx ms", "Total ops", "Avg op ms"]
    b_vals = [
        baseline["total_transactions"],
        baseline["avg_transaction_time_ms"],
        baseline["total_operations"],
        baseline["avg_operation_time_ms"],
    ]
    s_vals = [
        scr["total_transactions"],
        scr["avg_transaction_time_ms"],
        scr["total_operations"],
        scr["avg_operation_time_ms"],
    ]

    x = np.arange(len(labels))
    w = 0.35

    plt.figure(figsize=(10, 5))
    plt.bar(x - w / 2, b_vals, width=w, label="Baseline", color="#2D6CDF", alpha=0.9)
    plt.bar(x + w / 2, s_vals, width=w, label="SCR+Adaptive", color="#17986E", alpha=0.9)
    plt.xticks(x, labels)
    plt.title("High-Scale Cost Comparison")
    plt.grid(axis="y", alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def _plot_adaptive(rounds: int, scr: dict, out_path: Path) -> None:
    x = np.arange(1, rounds + 1)
    lj = np.array(scr.get("L_j_per_round", [])[:rounds], dtype=float)
    th = np.array(scr.get("threat_level_per_round", [])[:rounds], dtype=float)

    fig, ax1 = plt.subplots(figsize=(11, 5))
    ax2 = ax1.twinx()

    if lj.size:
        ax1.step(x[:lj.size], lj, where="post", color="#17986E", linewidth=2.4, label="L_j")
    if th.size:
        ax2.plot(x[:th.size], th, color="#D35400", linewidth=2.0, linestyle="--", label="Threat")

    for rnd in scr.get("asymmetric_ratchet_rounds", []):
        if 1 <= int(rnd) <= rounds:
            ax1.axvline(int(rnd), color="#AA2222", linestyle=":", alpha=0.5)

    ax1.set_title("Adaptive Behavior in SCR Variant")
    ax1.set_xlabel("Round")
    ax1.set_ylabel("L_j", color="#17986E")
    ax2.set_ylabel("Threat level", color="#D35400")
    ax1.grid(alpha=0.25)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper right")

    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="High-scale baseline vs SCR benchmark")
    parser.add_argument("--rounds", type=int, default=20, help="Number of FL rounds")
    parser.add_argument("--clients", type=int, default=8, help="Number of clients")
    parser.add_argument("--python", type=str, default=sys.executable, help="Python executable to use")
    parser.add_argument("--timeout", type=int, default=3600, help="Timeout per variant in seconds")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("[1/4] Running baseline variant...")
    baseline, baseline_elapsed = _run_variant(
        python_exe=args.python,
        pkg_root=BASELINE_DIR,
        script_template=RUNNER_BASELINE,
        rounds=args.rounds,
        n_clients=args.clients,
        project_id=1001,
        timeout_s=args.timeout,
    )

    print("[2/4] Running SCR+adaptive variant...")
    scr, scr_elapsed = _run_variant(
        python_exe=args.python,
        pkg_root=SCR_DIR,
        script_template=RUNNER_SCR,
        rounds=args.rounds,
        n_clients=args.clients,
        project_id=1002,
        timeout_s=args.timeout,
    )

    comparison = {
        "config": {
            "rounds": args.rounds,
            "clients": args.clients,
            "chain_url": CHAIN_URL,
            "python": args.python,
            "timestamp": int(time.time()),
        },
        "baseline": baseline,
        "scr_adaptive": scr,
        "runtime_seconds": {
            "baseline": round(baseline_elapsed, 2),
            "scr_adaptive": round(scr_elapsed, 2),
        },
    }

    b_final = float(baseline["final_accuracy"])
    s_final = float(scr["final_accuracy"])
    b_tx = float(baseline["avg_transaction_time_ms"])
    s_tx = float(scr["avg_transaction_time_ms"])
    b_op = float(baseline["avg_operation_time_ms"])
    s_op = float(scr["avg_operation_time_ms"])

    comparison["derived"] = {
        "final_accuracy_delta_scr_minus_baseline": round(s_final - b_final, 6),
        "avg_tx_time_delta_ms_scr_minus_baseline": round(s_tx - b_tx, 4),
        "avg_op_time_delta_ms_scr_minus_baseline": round(s_op - b_op, 4),
        "tx_speedup_percent_scr_vs_baseline": round(((b_tx - s_tx) / b_tx * 100.0) if b_tx else 0.0, 3),
        "op_speedup_percent_scr_vs_baseline": round(((b_op - s_op) / b_op * 100.0) if b_op else 0.0, 3),
    }

    out_json = OUT_DIR / "baseline_vs_scr_results.json"
    with out_json.open("w", encoding="utf-8") as f:
        json.dump(comparison, f, indent=2)

    print("[3/4] Generating graphs...")
    _plot_accuracy(args.rounds, baseline, scr, OUT_DIR / "graph_accuracy_high_scale.png")
    _plot_latency(args.rounds, baseline, scr, OUT_DIR / "graph_latency_high_scale.png")
    _plot_cost_bars(baseline, scr, OUT_DIR / "graph_cost_high_scale.png")
    _plot_adaptive(args.rounds, scr, OUT_DIR / "graph_adaptive_high_scale.png")

    print("[4/4] Done.")
    print("Results:", out_json)
    print("Graphs:", OUT_DIR)
    print("Summary:")
    print("  Final accuracy baseline   :", round(b_final, 4))
    print("  Final accuracy SCR+adapt  :", round(s_final, 4))
    print("  Avg tx time baseline (ms) :", round(b_tx, 3))
    print("  Avg tx time SCR+adapt (ms):", round(s_tx, 3))
    print("  Avg op time baseline (ms) :", round(b_op, 3))
    print("  Avg op time SCR+adapt (ms):", round(s_op, 3))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
