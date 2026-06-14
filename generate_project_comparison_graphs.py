#!/usr/bin/env python3
"""
Generate comparison graphs for baseline vs attached PQBFL projects.

By default, this script reads:
  benchmark_results/high_scale/baseline_ours_synth_real_highscale.json

It produces:
  - graph_dataset_pairwise_comparison.png
  - graph_dataset_delta_percentages.png
  - graph_side_channel_adaptive_summary.png
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def _load_results(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Input JSON not found: {path}")
    return json.loads(path.read_text())


def _get_runs(data: dict) -> tuple[dict, dict, dict, dict]:
    runs = data.get("runs", {})
    required = [
        "baseline_synthetic",
        "ours_synthetic",
        "baseline_real",
        "ours_real",
    ]
    missing = [k for k in required if k not in runs]
    if missing:
        raise KeyError(f"Missing run keys in JSON: {missing}")
    return (
        runs["baseline_synthetic"],
        runs["ours_synthetic"],
        runs["baseline_real"],
        runs["ours_real"],
    )


def _plot_pairwise_metrics(data: dict, out_dir: Path) -> Path:
    b_syn, o_syn, b_real, o_real = _get_runs(data)

    metrics = [
        ("Final Accuracy", "final_accuracy", None),
        ("Avg Tx Latency (ms)", "avg_transaction_time_ms", "ms"),
        ("Avg Off-Chain Latency (ms)", "avg_operation_time_ms", "ms"),
        ("Runtime (s)", "runtime_seconds", "s"),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(13, 8))
    axes = axes.flatten()

    x_labels = ["Synthetic", "Real"]
    width = 0.34
    x = [0, 1]

    for ax, (title, key, _unit) in zip(axes, metrics):
        baseline_vals = [b_syn[key], b_real[key]]
        ours_vals = [o_syn[key], o_real[key]]

        ax.bar([i - width / 2 for i in x], baseline_vals, width=width, label="Baseline", color="#2D6CDF")
        ax.bar([i + width / 2 for i in x], ours_vals, width=width, label="Ours", color="#17986E")

        ax.set_title(title)
        ax.set_xticks(x)
        ax.set_xticklabels(x_labels)
        ax.grid(axis="y", alpha=0.25)

        for i, val in enumerate(baseline_vals):
            ax.text(i - width / 2, val, f"{val:.3f}", ha="center", va="bottom", fontsize=8)
        for i, val in enumerate(ours_vals):
            ax.text(i + width / 2, val, f"{val:.3f}", ha="center", va="bottom", fontsize=8)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=2, frameon=False)
    fig.suptitle("Baseline vs Ours Across Synthetic and Real Data (High Scale)", y=0.98)
    fig.tight_layout(rect=[0, 0, 1, 0.95])

    out_path = out_dir / "graph_dataset_pairwise_comparison.png"
    fig.savefig(out_path, dpi=170)
    plt.close(fig)
    return out_path


def _safe_speedup_percent(baseline: float, ours: float, higher_is_better: bool) -> float:
    if baseline == 0:
        return 0.0
    if higher_is_better:
        return (ours - baseline) / abs(baseline) * 100.0
    return (baseline - ours) / abs(baseline) * 100.0


def _plot_delta_percentages(data: dict, out_dir: Path) -> Path:
    b_syn, o_syn, b_real, o_real = _get_runs(data)

    categories = [
        "Accuracy",
        "Tx latency",
        "Off-chain latency",
        "Runtime",
    ]

    syn_delta = [
        _safe_speedup_percent(b_syn["final_accuracy"], o_syn["final_accuracy"], True),
        _safe_speedup_percent(b_syn["avg_transaction_time_ms"], o_syn["avg_transaction_time_ms"], False),
        _safe_speedup_percent(b_syn["avg_operation_time_ms"], o_syn["avg_operation_time_ms"], False),
        _safe_speedup_percent(b_syn["runtime_seconds"], o_syn["runtime_seconds"], False),
    ]
    real_delta = [
        _safe_speedup_percent(b_real["final_accuracy"], o_real["final_accuracy"], True),
        _safe_speedup_percent(b_real["avg_transaction_time_ms"], o_real["avg_transaction_time_ms"], False),
        _safe_speedup_percent(b_real["avg_operation_time_ms"], o_real["avg_operation_time_ms"], False),
        _safe_speedup_percent(b_real["runtime_seconds"], o_real["runtime_seconds"], False),
    ]

    x = list(range(len(categories)))
    width = 0.35

    fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar([i - width / 2 for i in x], syn_delta, width=width, label="Synthetic", color="#7A5CFA")
    ax.bar([i + width / 2 for i in x], real_delta, width=width, label="Real", color="#00A6A6")

    ax.axhline(0, color="black", linewidth=1, alpha=0.6)
    ax.set_title("Percentage Change of Ours vs Baseline")
    ax.set_ylabel("Change (%)")
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False)

    for i, v in enumerate(syn_delta):
        ax.text(i - width / 2, v, f"{v:+.2f}%", ha="center", va="bottom" if v >= 0 else "top", fontsize=8)
    for i, v in enumerate(real_delta):
        ax.text(i + width / 2, v, f"{v:+.2f}%", ha="center", va="bottom" if v >= 0 else "top", fontsize=8)

    fig.tight_layout()
    out_path = out_dir / "graph_dataset_delta_percentages.png"
    fig.savefig(out_path, dpi=170)
    plt.close(fig)
    return out_path


def _plot_side_channel_adaptive_summary(data: dict, out_dir: Path) -> Path:
    b_syn, o_syn, b_real, o_real = _get_runs(data)

    labels = ["Baseline+Syn", "Ours+Syn", "Baseline+Real", "Ours+Real"]
    adaptive_counts = [
        len(b_syn.get("ratchet_adjustments", [])),
        len(o_syn.get("ratchet_adjustments", [])),
        len(b_real.get("ratchet_adjustments", [])),
        len(o_real.get("ratchet_adjustments", [])),
    ]
    threat_events = [
        b_syn.get("threat_events_count", 0),
        o_syn.get("threat_events_count", 0),
        b_real.get("threat_events_count", 0),
        o_real.get("threat_events_count", 0),
    ]

    fig, ax1 = plt.subplots(figsize=(11, 5))
    ax2 = ax1.twinx()

    x = list(range(len(labels)))
    bars = ax1.bar(x, adaptive_counts, width=0.55, color="#F39C12", alpha=0.85, label="Adaptive updates")
    line = ax2.plot(x, threat_events, marker="o", linewidth=2.2, color="#D35454", label="Threat events")

    ax1.set_xticks(x)
    ax1.set_xticklabels(labels)
    ax1.set_ylabel("Adaptive updates (count)")
    ax2.set_ylabel("Threat events (count)")
    ax1.set_title("Adaptive Behavior and Threat Signal Summary")
    ax1.grid(axis="y", alpha=0.25)

    for b in bars:
        h = b.get_height()
        ax1.text(b.get_x() + b.get_width() / 2, h, f"{int(h)}", ha="center", va="bottom", fontsize=9)
    for i, y in enumerate(threat_events):
        ax2.text(i, y, f"{int(y)}", ha="center", va="bottom", fontsize=9)

    handles1, labels1 = ax1.get_legend_handles_labels()
    handles2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(handles1 + handles2, labels1 + labels2, loc="upper left", frameon=False)

    fig.tight_layout()
    out_path = out_dir / "graph_side_channel_adaptive_summary.png"
    fig.savefig(out_path, dpi=170)
    plt.close(fig)
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate project comparison graphs from benchmark JSON.")
    parser.add_argument(
        "--input",
        type=str,
        default="benchmark_results/high_scale/baseline_ours_synth_real_highscale.json",
        help="Path to input JSON benchmark artifact",
    )
    parser.add_argument(
        "--out-dir",
        type=str,
        default="benchmark_results/high_scale",
        help="Output directory for generated graph images",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    data = _load_results(input_path)

    p1 = _plot_pairwise_metrics(data, out_dir)
    p2 = _plot_delta_percentages(data, out_dir)
    p3 = _plot_side_channel_adaptive_summary(data, out_dir)

    print("Generated graphs:")
    print(f"- {p1}")
    print(f"- {p2}")
    print(f"- {p3}")


if __name__ == "__main__":
    main()
