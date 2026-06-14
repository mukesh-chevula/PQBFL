#!/usr/bin/env python3
"""
Generate the dataset-wise pairwise comparison figure for the journal.
Replaces graph_dataset_pairwise_comparison.png in JOURNAL__Copy_/
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "JOURNAL__Copy_")

# Data from Table: High-Scale Dataset-Wise Comparison (50 Rounds, 10 Clients)
metrics = ["Final\nAccuracy", "Avg Tx\nLatency (ms)", "Avg Off-Chain\nLatency (ms)", "Runtime (s)"]

# Values
baseline_synth = [0.8250, 9.37, 1.78, 22.49]
ours_synth     = [0.8050, 9.26, 0.23, 12.81]
baseline_real  = [0.98860, 9.13, 1.79, 25.82]
ours_real      = [0.98892, 8.89, 1.07, 17.15]

# Colors
C_BASE = "#2563EB"   # blue - baseline
C_OURS = "#059669"   # green - ours (SCR+Adaptive)

plt.rcParams.update({
    "figure.facecolor": "#FFFFFF",
    "axes.facecolor": "#FFFFFF",
    "axes.grid": True,
    "grid.linestyle": "--",
    "grid.alpha": 0.4,
    "axes.edgecolor": "#333333",
    "text.color": "#000000",
    "font.family": "serif",
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.titlesize": 12,
})

fig, axes = plt.subplots(2, 2, figsize=(12, 8))
fig.suptitle("High-Scale Dataset-Wise Comparison (50 Rounds, 10 Clients)",
             fontsize=14, fontweight="bold", y=0.98)

x = np.arange(2)  # Synthetic, Real
width = 0.32
dataset_labels = ["Synthetic", "Real"]

for idx, (ax, metric) in enumerate(zip(axes.flat, metrics)):
    baseline_vals = [baseline_synth[idx], baseline_real[idx]]
    ours_vals = [ours_synth[idx], ours_real[idx]]

    bars_b = ax.bar(x - width/2, baseline_vals, width, color=C_BASE, alpha=0.85,
                    edgecolor='black', linewidth=0.5, label="Baseline PQBFL")
    bars_o = ax.bar(x + width/2, ours_vals, width, color=C_OURS, alpha=0.85,
                    edgecolor='black', linewidth=0.5, label="Ours (SCR+Adaptive)")

    # Value labels on bars
    for bar in bars_b:
        h = bar.get_height()
        fmt = f"{h:.4f}" if idx == 0 else (f"{h:.2f}" if idx < 3 else f"{h:.2f}")
        if idx == 0 and h > 0.9:
            fmt = f"{h:.5f}"
        elif idx == 0:
            fmt = f"{h:.4f}"
        ax.text(bar.get_x() + bar.get_width()/2, h, fmt,
                ha='center', va='bottom', fontsize=8, fontweight='bold', color=C_BASE)

    for bar in bars_o:
        h = bar.get_height()
        fmt = f"{h:.4f}" if idx == 0 else (f"{h:.2f}" if idx < 3 else f"{h:.2f}")
        if idx == 0 and h > 0.9:
            fmt = f"{h:.5f}"
        elif idx == 0:
            fmt = f"{h:.4f}"
        ax.text(bar.get_x() + bar.get_width()/2, h, fmt,
                ha='center', va='bottom', fontsize=8, fontweight='bold', color=C_OURS)

    # Delta annotations
    deltas_synth = [ours_synth[i] - baseline_synth[i] for i in range(4)]
    deltas_real = [ours_real[i] - baseline_real[i] for i in range(4)]

    for j, (ds, dr) in enumerate([(deltas_synth[idx], deltas_real[idx])]):
        pass

    # Improvement arrows between bars
    for j, (bv, ov) in enumerate(zip(baseline_vals, ours_vals)):
        delta = ov - bv
        # For latency/runtime, negative is better; for accuracy, positive is better
        if idx == 0:
            better = delta > 0
            pct = f"+{delta:.5f}" if delta > 0 else f"{delta:.4f}"
        else:
            better = delta < 0
            pct_val = (delta / bv) * 100
            pct = f"{pct_val:+.1f}%"

        color = C_OURS if better else "#CC2222"
        mid_y = max(bv, ov) * 1.08
        ax.annotate(pct, xy=(x[j], mid_y),
                    ha='center', fontsize=7.5, color=color, fontweight='bold',
                    style='italic')

    ax.set_xticks(x)
    ax.set_xticklabels(dataset_labels, fontsize=10)
    ax.set_title(metric.replace("\n", " "), fontsize=11, fontweight='bold')

    # Adjust y-axis padding
    all_vals = baseline_vals + ours_vals
    ymin = min(all_vals) * 0.85 if min(all_vals) > 0 else 0
    ymax = max(all_vals) * 1.2
    if idx == 0:
        # For accuracy, narrow the range to show differences
        ymin = min(all_vals) * 0.95
        ymax = max(all_vals) * 1.05
    ax.set_ylim(ymin, ymax)

plt.tight_layout(rect=[0, 0, 1, 0.95])

# Single shared legend at top right
handles, labels = axes[0, 0].get_legend_handles_labels()
fig.legend(handles, labels, loc='upper right', fontsize=9, framealpha=0.9,
           bbox_to_anchor=(0.98, 0.96))

path = os.path.join(OUT, "graph_dataset_pairwise_comparison.png")
plt.savefig(path, dpi=300, bbox_inches="tight", facecolor="white")
plt.close()
print(f"Saved: {path}")
