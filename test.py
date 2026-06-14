"""
compare_all_variants.py
=======================
Runs all five PQBFL project variants against a shared Hardhat node and
produces side-by-side comparison graphs on the same axes:

  Variants
  --------
  V1  pqbfl_project                            (baseline, original)
  V2  pqbfl_project new                        (baseline, new chain layer)
  V3  pqbfl_project adaptive ratcheting        (adaptive ratcheting, old)
  V4  pqbfl_project new adaptive ratcheting    (adaptive ratcheting, new)
  V5  pqbfl_project new adaptive side channel  (adaptive + SC-resistant)

  Graphs produced
  ---------------
  G1  Accuracy over rounds          — all 5 on same axes
  G2  Per-round transaction time    — all 5 on same axes
  G3  Per-round off-chain op time   — all 5 on same axes
  G4  Cumulative total time         — all 5 on same axes
  G5  Key-metrics bar chart         — avg tx time, avg op time, final acc
"""
from __future__ import annotations

import importlib
import os
import sys
import types
import warnings
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

warnings.filterwarnings("ignore")

# ── paths ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent

VARIANTS: list[dict] = [
    {
        "key":   "v1",
        "label": "V1 · Baseline (orig)",
        "dir":   ROOT / "pqbfl_project",
    },
    {
        "key":   "v2",
        "label": "V2 · Baseline (new)",
        "dir":   ROOT / "pqbfl_project new",
    },
    {
        "key":   "v3",
        "label": "V3 · Adaptive Ratchet (orig)",
        "dir":   ROOT / "pqbfl_project adaptive ratcheting",
    },
    {
        "key":   "v4",
        "label": "V4 · Adaptive Ratchet (new)",
        "dir":   ROOT / "pqbfl_project new adaptive ratcheting",
    },
    {
        "key":   "v5",
        "label": "V5 · Adaptive + SC-Resistant",
        "dir":   ROOT / "pqbfl_project new adaptive side channel resistant",
    },
]

# Shared run settings
CHAIN_URL  = os.getenv("PQBFL_CHAIN_URL", "http://127.0.0.1:8545")
ROUNDS     = 50
N_CLIENTS  = 10

OUTPUT_DIR = ROOT / "benchmark_results" / "all_variants"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ── palette ───────────────────────────────────────────────────────────────────
COLORS = ["#1F6FEB", "#0D9E6E", "#D04F00", "#8B44EB", "#CC2222"]
MARKERS = ["o", "s", "^", "D", "v"]

C_BG      = "#FFFFFF"
C_AX      = "#F5F7FA"
C_GRID    = "#D0D7E3"
C_BORDER  = "#9BA8BB"
C_TEXT    = "#1A1E2E"
C_SUBTEXT = "#4A5568"

plt.rcParams.update({
    "figure.facecolor":  C_BG,
    "axes.facecolor":    C_AX,
    "axes.edgecolor":    C_BORDER,
    "axes.labelcolor":   C_TEXT,
    "xtick.color":       C_SUBTEXT,
    "ytick.color":       C_SUBTEXT,
    "text.color":        C_TEXT,
    "grid.color":        C_GRID,
    "grid.linewidth":    0.8,
    "grid.alpha":        1.0,
    "legend.facecolor":  "#FFFFFF",
    "legend.edgecolor":  C_BORDER,
    "legend.framealpha": 1.0,
    "font.family":       "DejaVu Sans",
    "axes.titlepad":     10,
    "axes.titlesize":    12,
    "axes.labelsize":    10,
    "xtick.labelsize":   9,
    "ytick.labelsize":   9,
})


# ── dynamic import helper ─────────────────────────────────────────────────────

def _load_demo(variant: dict):
    """
    Import `pqbfl.scripts.demo_end_to_end` from the variant's python/ dir.
    Registers the module in sys.modules BEFORE exec_module so that
    @dataclass can find cls.__module__ during decoration.
    """
    python_dir = str(variant["dir"] / "python")
    key = variant["key"]
    mod_name = f"demo_{key}"

    # Temporarily prepend variant's python dir so its imports resolve correctly.
    sys.path.insert(0, python_dir)

    # Purge any previously cached pqbfl modules to avoid cross-variant bleed.
    to_del = [m for m in sys.modules if m == "pqbfl" or m.startswith("pqbfl.")]
    for m in to_del:
        del sys.modules[m]

    spec = importlib.util.spec_from_file_location(
        mod_name,
        python_dir + "/pqbfl/scripts/demo_end_to_end.py",
    )
    mod = importlib.util.module_from_spec(spec)
    # MUST register before exec_module so @dataclass can resolve cls.__module__
    sys.modules[mod_name] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        # Clean up: remove variant path and the temp module name
        try:
            sys.path.remove(python_dir)
        except ValueError:
            pass
        sys.modules.pop(mod_name, None)

    return mod


# ── run all variants ──────────────────────────────────────────────────────────

def run_all() -> list[dict]:
    results = []
    for v in VARIANTS:
        print(f"\n{'='*60}")
        print(f"  Running {v['label']}")
        print(f"{'='*60}")
        try:
            demo = _load_demo(v)
            # Build config — only pass fields DemoConfig actually accepts
            import inspect
            cfg_fields = {f for f in inspect.signature(demo.DemoConfig).parameters}
            cfg_kwargs = {}
            if "chain_url"  in cfg_fields: cfg_kwargs["chain_url"]  = CHAIN_URL
            if "rounds"     in cfg_fields: cfg_kwargs["rounds"]     = ROUNDS
            if "n_clients"  in cfg_fields: cfg_kwargs["n_clients"]  = N_CLIENTS

            cfg = demo.DemoConfig(**cfg_kwargs)
            result = demo.run_demo(cfg)
            results.append({"variant": v, "result": result, "error": None})
            print(f"  ✅ Done — final acc={result.final_accuracy:.4f}")
        except Exception as exc:
            import traceback
            print(f"  ❌ FAILED: {exc}")
            traceback.print_exc()
            results.append({"variant": v, "result": None, "error": str(exc)})
    return results


# ── helper ────────────────────────────────────────────────────────────────────

def _ms(arr: list[float]) -> list[float]:
    return [v * 1000 for v in arr] if arr and isinstance(arr[0], float) and arr[0] < 1 else list(arr)


def _get(result, attr, default=None):
    return getattr(result, attr, default)


# ── Graph 1 — Accuracy over rounds ───────────────────────────────────────────

def plot_accuracy(runs: list[dict]):
    fig, ax = plt.subplots(figsize=(13, 6))
    fig.patch.set_facecolor(C_BG)
    fig.text(0.5, 0.97, "Graph 1 — Model Accuracy Over FL Rounds",
             ha="center", va="top", fontsize=14, fontweight="bold", color=C_TEXT)
    fig.text(0.5, 0.92, f"All 5 PQBFL variants  ·  {ROUNDS} rounds  ·  {N_CLIENTS} clients",
             ha="center", va="top", fontsize=9.5, color=C_SUBTEXT)

    for i, run in enumerate(runs):
        if run["result"] is None:
            continue
        r = run["result"]
        v = run["variant"]
        accs = r.round_accuracies
        xs = list(range(len(accs)))
        ax.plot(xs, accs, color=COLORS[i], marker=MARKERS[i],
                lw=2.2, markersize=5, label=v["label"])

    ax.set_xlabel("Round", fontsize=11)
    ax.set_ylabel("Test Accuracy", fontsize=11)
    ax.set_ylim(0, 1.05)
    ax.set_xlim(0, ROUNDS)
    ax.grid(True)
    ax.legend(fontsize=9, loc="lower right", framealpha=1, edgecolor=C_BORDER)
    plt.tight_layout(rect=[0, 0, 1, 0.90])
    out = OUTPUT_DIR / "g1_accuracy.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"✅ G1 saved → {out}")


# ── Graph 2 — Per-round avg transaction time ──────────────────────────────────

def plot_tx_time(runs: list[dict]):
    fig, ax = plt.subplots(figsize=(13, 6))
    fig.patch.set_facecolor(C_BG)
    fig.text(0.5, 0.97, "Graph 2 — Per-Round Average Transaction Time (ms)",
             ha="center", va="top", fontsize=14, fontweight="bold", color=C_TEXT)
    fig.text(0.5, 0.92, "On-chain Hardhat transactions  ·  averaged per round",
             ha="center", va="top", fontsize=9.5, color=C_SUBTEXT)

    for i, run in enumerate(runs):
        if run["result"] is None:
            continue
        r = run["result"]
        v = run["variant"]
        tx = r.transaction_timings
        if not tx:
            continue
        # Group by round
        from collections import defaultdict
        by_round: dict[int, list[float]] = defaultdict(list)
        for t in tx:
            by_round[t["round"]].append(t["duration_ms"])
        rounds_sorted = sorted(by_round)
        avgs = [float(np.mean(by_round[rnd])) for rnd in rounds_sorted]
        ax.plot(rounds_sorted, avgs, color=COLORS[i], marker=MARKERS[i],
                lw=2.2, markersize=5, label=v["label"])

    ax.set_xlabel("Round", fontsize=11)
    ax.set_ylabel("Avg Transaction Time (ms)", fontsize=11)
    ax.grid(True)
    ax.legend(fontsize=9, loc="upper right", framealpha=1, edgecolor=C_BORDER)
    plt.tight_layout(rect=[0, 0, 1, 0.90])
    out = OUTPUT_DIR / "g2_tx_time.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"✅ G2 saved → {out}")


# ── Graph 3 — Per-round avg off-chain op time ─────────────────────────────────

def plot_op_time(runs: list[dict]):
    fig, ax = plt.subplots(figsize=(13, 6))
    fig.patch.set_facecolor(C_BG)
    fig.text(0.5, 0.97, "Graph 3 — Per-Round Average Off-Chain Operation Time (ms)",
             ha="center", va="top", fontsize=14, fontweight="bold", color=C_TEXT)
    fig.text(0.5, 0.92, "Cryptographic + training operations  ·  averaged per round",
             ha="center", va="top", fontsize=9.5, color=C_SUBTEXT)

    for i, run in enumerate(runs):
        if run["result"] is None:
            continue
        r = run["result"]
        v = run["variant"]
        ops = r.operation_timings
        if not ops:
            continue
        from collections import defaultdict
        by_round: dict[int, list[float]] = defaultdict(list)
        for o in ops:
            by_round[o["round"]].append(o["duration_ms"])
        rounds_sorted = sorted(by_round)
        avgs = [float(np.mean(by_round[rnd])) for rnd in rounds_sorted]
        ax.plot(rounds_sorted, avgs, color=COLORS[i], marker=MARKERS[i],
                lw=2.2, markersize=5, label=v["label"])

    ax.set_xlabel("Round", fontsize=11)
    ax.set_ylabel("Avg Off-Chain Op Time (ms)", fontsize=11)
    ax.grid(True)
    ax.legend(fontsize=9, loc="upper right", framealpha=1, edgecolor=C_BORDER)
    plt.tight_layout(rect=[0, 0, 1, 0.90])
    out = OUTPUT_DIR / "g3_op_time.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"✅ G3 saved → {out}")


# ── Graph 4 — Cumulative total time (tx + ops) ────────────────────────────────

def plot_cumulative(runs: list[dict]):
    fig, ax = plt.subplots(figsize=(13, 6))
    fig.patch.set_facecolor(C_BG)
    fig.text(0.5, 0.97, "Graph 4 — Cumulative Total Time (ms) Over Rounds",
             ha="center", va="top", fontsize=14, fontweight="bold", color=C_TEXT)
    fig.text(0.5, 0.92, "Sum of all transaction + off-chain operation durations  ·  cumulative",
             ha="center", va="top", fontsize=9.5, color=C_SUBTEXT)

    for i, run in enumerate(runs):
        if run["result"] is None:
            continue
        r = run["result"]
        v = run["variant"]

        from collections import defaultdict
        by_round: dict[int, float] = defaultdict(float)
        for t in r.transaction_timings:
            by_round[t["round"]] += t["duration_ms"]
        for o in r.operation_timings:
            by_round[o["round"]] += o["duration_ms"]

        rounds_sorted = sorted(by_round)
        totals = [by_round[rnd] for rnd in rounds_sorted]
        cumulative = list(np.cumsum(totals))
        ax.plot(rounds_sorted, cumulative, color=COLORS[i], marker=MARKERS[i],
                lw=2.2, markersize=5, label=v["label"])

    ax.set_xlabel("Round", fontsize=11)
    ax.set_ylabel("Cumulative Time (ms)", fontsize=11)
    ax.grid(True)
    ax.legend(fontsize=9, loc="upper left", framealpha=1, edgecolor=C_BORDER)
    plt.tight_layout(rect=[0, 0, 1, 0.90])
    out = OUTPUT_DIR / "g4_cumulative.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"✅ G4 saved → {out}")


# ── Graph 5 — Bar chart: key metrics ─────────────────────────────────────────

def plot_bar_metrics(runs: list[dict]):
    labels     = []
    final_accs = []
    avg_tx     = []
    avg_op     = []

    for run in runs:
        v = run["variant"]
        labels.append(v["label"].replace(" · ", "\n"))
        if run["result"] is None:
            final_accs.append(0.0)
            avg_tx.append(0.0)
            avg_op.append(0.0)
        else:
            r = run["result"]
            final_accs.append(r.final_accuracy)
            avg_tx.append(r.avg_transaction_time_ms)
            avg_op.append(r.avg_operation_time_ms)

    x  = np.arange(len(labels))
    bw = 0.25

    fig, axes = plt.subplots(1, 3, figsize=(16, 6))
    fig.patch.set_facecolor(C_BG)
    fig.text(0.5, 0.97, "Graph 5 — Key Metrics Comparison Across All 5 Variants",
             ha="center", va="top", fontsize=14, fontweight="bold", color=C_TEXT)
    fig.text(0.5, 0.92, "Final accuracy (higher=better)  ·  Avg tx time (lower=better)  ·  Avg op time (lower=better)",
             ha="center", va="top", fontsize=9.5, color=C_SUBTEXT)

    for ax, vals, title, ylabel in zip(
        axes,
        [final_accs, avg_tx, avg_op],
        ["Final Test Accuracy", "Avg Transaction Time (ms)", "Avg Off-Chain Op Time (ms)"],
        ["Accuracy", "ms", "ms"],
    ):
        bars = ax.bar(x, vals, color=COLORS[:len(labels)], alpha=0.88, zorder=3,
                      edgecolor="white", linewidth=0.8)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + max(vals) * 0.02,
                    f"{val:.3f}" if val < 1 else f"{val:.2f}",
                    ha="center", va="bottom", fontsize=8.5, fontweight="bold",
                    color=C_TEXT)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=7.5, rotation=15, ha="right")
        ax.set_ylabel(ylabel, fontsize=10)
        ax.set_title(title, fontsize=11, fontweight="bold")
        ax.set_facecolor(C_AX)
        ax.grid(True, axis="y", alpha=0.7)
        ax.set_ylim(0, max(vals) * 1.18 if max(vals) > 0 else 1)

    plt.tight_layout(rect=[0, 0, 1, 0.90])
    out = OUTPUT_DIR / "g5_bar_metrics.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"✅ G5 saved → {out}")


# ── console summary ───────────────────────────────────────────────────────────

def print_summary(runs: list[dict]):
    print(f"\n{'='*72}")
    print(f"  ALL-VARIANTS SUMMARY")
    print(f"{'='*72}")
    hdr = f"  {'Variant':<36} {'FinalAcc':>9} {'AvgTx(ms)':>10} {'AvgOp(ms)':>10} {'Txns':>6} {'Ops':>6}"
    print(hdr)
    print(f"  {'─'*70}")
    for run in runs:
        v = run["variant"]
        if run["result"] is None:
            print(f"  {v['label']:<36}  FAILED: {run['error'][:30]}")
            continue
        r = run["result"]
        print(f"  {v['label']:<36} {r.final_accuracy:>9.4f} "
              f"{r.avg_transaction_time_ms:>10.2f} "
              f"{r.avg_operation_time_ms:>10.2f} "
              f"{r.total_transactions:>6} "
              f"{r.total_operations:>6}")
    print(f"{'='*72}\n")
    print(f"  Output → {OUTPUT_DIR}/\n")


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{'='*72}")
    print(f"  PQBFL All-Variants Comparison")
    print(f"  Rounds={ROUNDS}  Clients={N_CLIENTS}  Chain={CHAIN_URL}")
    print(f"{'='*72}")

    runs = run_all()

    ok = [r for r in runs if r["result"] is not None]
    if not ok:
        print("❌ All variants failed — cannot generate graphs.")
        return

    print(f"\n{'='*72}\n  Generating graphs…\n{'='*72}")
    plot_accuracy(runs)
    plot_tx_time(runs)
    plot_op_time(runs)
    plot_cumulative(runs)
    plot_bar_metrics(runs)
    print_summary(runs)


if __name__ == "__main__":
    main()
