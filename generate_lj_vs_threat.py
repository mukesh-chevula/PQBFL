#!/usr/bin/env python3
"""
generate_lj_vs_threat.py
Generates graph2_lj_vs_threat.png — the adaptive ratcheting window L_j as a
function of composite threat level t ∈ [0,1], using the power-curve policy:

    L_j(t) = round( L_max - (L_max - L_min) · t^γ )   bounded to [L_min, L_max]

Parameters (matching the paper):
    γ     = 2.0   (quadratic sensitivity)
    L_min = 2     (maximum security / minimum window)
    L_max = 20    (minimum security / maximum window)
    L_base= 10    (fixed baseline comparator)

Output: saves to benchmark_results/graph2_lj_vs_threat.png
        and also to JOURNAL__Copy_/graph2_lj_vs_threat.png
"""

import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.ticker import MultipleLocator

# ── Parameters ─────────────────────────────────────────────────────────────
L_MIN   = 2
L_MAX   = 20
GAMMA   = 2.0
L_BASE  = 10          # fixed baseline window for comparison
DPI     = 300

# ── Output paths ────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_PATHS = [
    os.path.join(SCRIPT_DIR, "benchmark_results", "graph2_lj_vs_threat.png"),
    os.path.join(SCRIPT_DIR, "JOURNAL__Copy_",   "graph2_lj_vs_threat.png"),
]

# ── Adaptive policy function ────────────────────────────────────────────────
def lj(t, l_min=L_MIN, l_max=L_MAX, gamma=GAMMA):
    """Continuous (float) version for the smooth curve."""
    return l_max - (l_max - l_min) * np.power(t, gamma)

def lj_discrete(t, l_min=L_MIN, l_max=L_MAX, gamma=GAMMA):
    """Rounded integer version (actual protocol value)."""
    raw = l_max - (l_max - l_min) * np.power(t, gamma)
    return np.clip(np.round(raw).astype(int), l_min, l_max)

# ── Plot ────────────────────────────────────────────────────────────────────
def make_plot():
    t_cont  = np.linspace(0, 1, 500)          # smooth curve
    t_disc  = np.linspace(0, 1, 200)          # discrete step markers
    lj_cont = lj(t_cont)
    lj_disc = lj_discrete(t_disc)

    # find crossover point where L_j = L_BASE
    t_cross = ((L_MAX - L_BASE) / (L_MAX - L_MIN)) ** (1.0 / GAMMA)

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("#F9FAFB")

    # ── Shaded zones ────────────────────────────────────────────────────────
    # Green zone: t < t_cross  → L_j > L_BASE  (adaptive beats fixed baseline)
    ax.axvspan(0, t_cross, alpha=0.12, color="#16A34A", zorder=0,
               label=f"Adaptive better than baseline ($L_j > {L_BASE}$)")
    # Blue zone:  t > t_cross  → L_j < L_BASE  (adaptive more conservative)
    ax.axvspan(t_cross, 1.0, alpha=0.10, color="#2563EB", zorder=0,
               label=f"Adaptive more conservative ($L_j < {L_BASE}$)")

    # ── Baseline reference line ──────────────────────────────────────────────
    ax.axhline(L_BASE, color="#6B7280", linewidth=1.4, linestyle="--",
               label=f"Fixed baseline ($L_j = {L_BASE}$)", zorder=1)

    # ── Discrete step plot (protocol actual values) ──────────────────────────
    ax.step(t_disc, lj_disc, where="post", color="#9CA3AF", linewidth=0.8,
            alpha=0.55, zorder=2, label="Discrete $L_j$ (protocol)")

    # ── Continuous smooth curve ──────────────────────────────────────────────
    ax.plot(t_cont, lj_cont, color="#059669", linewidth=2.5, zorder=3,
            label=r"$L_j(t)=\lfloor L_{max}-(L_{max}-L_{min})\cdot t^{\gamma}\rceil$")

    # ── Annotate crossover ───────────────────────────────────────────────────
    ax.axvline(t_cross, color="#DC2626", linewidth=1.0, linestyle=":",
               alpha=0.7, zorder=2)
    ax.annotate(
        f"Crossover\n$t={t_cross:.2f}$",
        xy=(t_cross, L_BASE),
        xytext=(t_cross + 0.06, L_BASE + 2.5),
        fontsize=8.5,
        color="#DC2626",
        arrowprops=dict(arrowstyle="->", color="#DC2626", lw=1.2),
        ha="left",
    )

    # ── Zero-threat operating point (green dot) ──────────────────────────────
    ax.scatter([0], [L_MAX], s=90, color="#16A34A", zorder=5,
               label=f"Zero-threat op. point ($L_j={L_MAX}$)")
    ax.annotate(
        f"  $L_j={L_MAX}$ (no threat)",
        xy=(0, L_MAX), xytext=(0.04, L_MAX - 0.8),
        fontsize=8.5, color="#16A34A", va="top",
    )

    # ── Example point from the paper: t=0.553, L_j=14 ───────────────────────
    t_ex, lj_ex = 0.553, 14
    ax.scatter([t_ex], [lj_ex], s=60, color="#7C3AED", zorder=5,
               marker="D", label=f"Example: $t=0.553 \\Rightarrow L_j=14$")
    ax.annotate(
        f"  $L_j=14$\n  ($t=0.553$)",
        xy=(t_ex, lj_ex), xytext=(t_ex + 0.05, lj_ex - 2.0),
        fontsize=8, color="#7C3AED",
        arrowprops=dict(arrowstyle="->", color="#7C3AED", lw=1.0),
    )

    # ── Boundary labels ──────────────────────────────────────────────────────
    ax.axhline(L_MAX, color="#D1D5DB", linewidth=0.8, linestyle=":", zorder=1)
    ax.axhline(L_MIN, color="#D1D5DB", linewidth=0.8, linestyle=":", zorder=1)
    ax.text(1.01, L_MAX, f"$L_{{max}}={L_MAX}$", va="center", fontsize=8,
            color="#374151", transform=ax.get_yaxis_transform())
    ax.text(1.01, L_MIN, f"$L_{{min}}={L_MIN}$",  va="center", fontsize=8,
            color="#374151", transform=ax.get_yaxis_transform())

    # ── Zone labels ──────────────────────────────────────────────────────────
    ax.text(t_cross / 2, 3.5, "GREEN\nZONE", fontsize=8, color="#16A34A",
            ha="center", alpha=0.8, fontstyle="italic")
    ax.text((t_cross + 1) / 2, 3.5, "BLUE\nZONE", fontsize=8, color="#2563EB",
            ha="center", alpha=0.8, fontstyle="italic")

    # ── Axes formatting ──────────────────────────────────────────────────────
    ax.set_xlabel("Composite Threat Level $t$", fontsize=12, fontweight="bold")
    ax.set_ylabel("Adaptive Ratcheting Window $L_j$", fontsize=12, fontweight="bold")
    ax.set_title(
        r"Adaptive Ratcheting Window $L_j$ vs Threat Level $t$" + "\n"
        r"$\gamma=2.0,\ L_{min}=2,\ L_{max}=20$",
        fontsize=12, fontweight="bold", pad=10,
    )

    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(0, L_MAX + 1.5)
    ax.xaxis.set_major_locator(MultipleLocator(0.1))
    ax.xaxis.set_minor_locator(MultipleLocator(0.05))
    ax.yaxis.set_major_locator(MultipleLocator(2))
    ax.grid(True, which="major", linestyle="--", alpha=0.5, linewidth=0.7)
    ax.grid(True, which="minor", linestyle=":",  alpha=0.3, linewidth=0.5)
    ax.tick_params(axis="both", labelsize=9)

    # ── Legend ───────────────────────────────────────────────────────────────
    handles, labels = ax.get_legend_handles_labels()
    ax.legend(handles, labels, fontsize=8, loc="upper right",
              framealpha=0.92, edgecolor="#D1D5DB")

    plt.tight_layout()

    # ── Save ─────────────────────────────────────────────────────────────────
    for path in OUT_PATHS:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fig.savefig(path, dpi=DPI, bbox_inches="tight", facecolor="white")
        print(f"Saved: {path}")

    plt.close(fig)


if __name__ == "__main__":
    make_plot()
    print("Done.")
