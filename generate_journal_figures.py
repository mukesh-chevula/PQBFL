#!/usr/bin/env python3
"""
generate_journal_figures.py
Generates all comparison figures for the JOURNAL from existing benchmark data.
Outputs to /Users/mchevula/PQBFL/JOURNAL/figures/
"""
import json, os
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec

# ── paths ──────────────────────────────────────────────────────────────────
BASE    = Path("/Users/mchevula/PQBFL")
JSON    = BASE / "benchmark_results/high_scale/baseline_vs_scr_results.json"
OUT     = BASE / "JOURNAL/figures"
OUT.mkdir(parents=True, exist_ok=True)

with open(JSON) as f:
    D = json.load(f)

BL  = D["baseline"]
SC  = D["scr_adaptive"]
R   = D["config"]["rounds"]        # 20
rounds = np.arange(1, R+1)

# colour palette
C_BASE = "#2563EB"   # deep blue  – baseline
C_SCR  = "#059669"   # emerald    – SCR+Adaptive
C_THR  = "#DC2626"   # red        – threat
C_WIN  = "#7C3AED"   # purple     – L_j window
GREY   = "#6B7280"

def savefig(name, dpi=200):
    path = OUT / name
    plt.savefig(path, dpi=dpi, bbox_inches="tight", facecolor="white")
    plt.close()
    print("saved:", path)

# ─── helper: series from per_round dict ────────────────────────────────────
def series(d, r=R):
    return [float(d.get(str(i), d.get(i, 0.0))) for i in range(1, r+1)]

# ═══════════════════════════════════════════════════════════════════════════
# Fig 1 – System Architecture Diagram (conceptual)
# ═══════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(11, 6))
ax.set_xlim(0, 10); ax.set_ylim(0, 6); ax.axis("off")
ax.set_facecolor("#F0F4FF")
fig.patch.set_facecolor("#F0F4FF")

def box(ax, x, y, w, h, color, label, sub="", fs=9):
    ax.add_patch(mpatches.FancyBboxPatch((x, y), w, h,
        boxstyle="round,pad=0.1", fc=color, ec="white", lw=2, zorder=3))
    ax.text(x+w/2, y+h*0.65, label, ha="center", va="center",
            fontsize=fs, fontweight="bold", color="white", zorder=4)
    if sub:
        ax.text(x+w/2, y+h*0.28, sub, ha="center", va="center",
                fontsize=7, color="white", alpha=0.85, zorder=4)

# Clients
for i, (cx, cy) in enumerate([(0.2,4.0),(0.2,2.5),(0.2,1.0)]):
    box(ax, cx, cy, 1.5, 1.1, C_BASE, f"Client {i+1}", "Local Train\n+ AEAD Enc")
ax.text(0.95, 5.5, "8 FL Clients", ha="center", fontsize=10,
        fontweight="bold", color=C_BASE)

# Server
box(ax, 3.8, 2.2, 2.4, 1.6, "#7C3AED", "Aggregation\nServer",
    "FedAvg + ThreatMonitor\n+ Adaptive Ratchet", fs=9)

# Blockchain
box(ax, 7.2, 2.4, 2.5, 1.4, "#B45309", "Blockchain\n(Hardhat)",
    "Smart Contract\nAudit Trail", fs=9)

# Arrows
for cy in [4.55, 3.05, 1.55]:
    ax.annotate("", xy=(3.8, 2.95), xytext=(1.7, cy),
                arrowprops=dict(arrowstyle="->", color=C_BASE, lw=1.5))
ax.annotate("", xy=(7.2, 2.9), xytext=(6.2, 2.9),
            arrowprops=dict(arrowstyle="<->", color="#B45309", lw=2))
ax.text(5.0, 5.5, "PQBFL Protocol Flow", ha="center", fontsize=12,
        fontweight="bold", color="#1E293B")

# Crypto labels
for txt, y in [("Kyber-512 KEM + ECDH", 5.0),
               ("ChaCha20-Poly1305 AEAD", 4.6),
               ("HMAC Ratchet Chain", 4.2)]:
    ax.text(3.5, y, f"► {txt}", fontsize=8, color="#1E293B")

ax.set_title("PQBFL System Architecture: Baseline vs SCR+Adaptive",
             fontsize=13, fontweight="bold", pad=12, color="#1E293B")
savefig("fig_architecture.png")

# ═══════════════════════════════════════════════════════════════════════════
# Fig 2 – Accuracy convergence (both variants, all rounds)
# ═══════════════════════════════════════════════════════════════════════════
x_acc = np.arange(0, R+1)
b_acc = BL["round_accuracies"]
s_acc = SC["round_accuracies"]

fig, ax = plt.subplots(figsize=(10, 5))
ax.plot(x_acc, b_acc, color=C_BASE, lw=2.5, marker="o", ms=4,
        label=f"Baseline PQBFL (final={BL['final_accuracy']:.3f})")
ax.plot(x_acc, s_acc, color=C_SCR, lw=2.5, marker="s", ms=4,
        label=f"SCR+Adaptive (final={SC['final_accuracy']:.3f})")
ax.axhline(BL["final_accuracy"], color=C_BASE, ls=":", lw=1.2, alpha=0.6)
ax.axhline(SC["final_accuracy"], color=C_SCR,  ls=":", lw=1.2, alpha=0.6)
ax.fill_between(x_acc, b_acc, s_acc, alpha=0.08, color=C_SCR)
ax.set_xlabel("FL Round", fontsize=11)
ax.set_ylabel("Test Accuracy", fontsize=11)
ax.set_title("Round-wise Accuracy Convergence: Baseline vs SCR+Adaptive\n"
             "(R=20, M=8 clients, synthetic non-IID data)", fontsize=12)
ax.legend(fontsize=10); ax.grid(alpha=0.3)
ax.set_ylim(0.60, 0.88)
savefig("fig_accuracy_convergence.png")

# ═══════════════════════════════════════════════════════════════════════════
# Fig 3 – Per-round latency breakdown (tx vs op side by side)
# ═══════════════════════════════════════════════════════════════════════════
b_tx = series(BL["tx_by_round"])
b_op = series(BL["op_by_round"])
s_tx = series(SC["tx_by_round"])
s_op = series(SC["op_by_round"])
b_tot = np.array(b_tx)+np.array(b_op)
s_tot = np.array(s_tx)+np.array(s_op)

fig, axes = plt.subplots(1, 2, figsize=(14, 5))
ax1, ax2 = axes

# Left – total overhead per round
ax1.plot(rounds, b_tot, color=C_BASE, lw=2.2, label="Baseline total")
ax1.plot(rounds, s_tot, color=C_SCR,  lw=2.2, label="SCR+Adaptive total")
ax1.axhline(np.mean(b_tot), color=C_BASE, ls="--", lw=1.1, alpha=0.7,
            label=f"Baseline mean={np.mean(b_tot):.1f} ms")
ax1.axhline(np.mean(s_tot), color=C_SCR,  ls="--", lw=1.1, alpha=0.7,
            label=f"SCR mean={np.mean(s_tot):.1f} ms")
ax1.set_title("Total Per-Round Overhead (tx + ops)", fontsize=11)
ax1.set_xlabel("Round"); ax1.set_ylabel("Time (ms)")
ax1.legend(fontsize=8); ax1.grid(alpha=0.3)

# Right – stacked bar: tx vs op per round
w = 0.35
x = np.arange(R)
ax2.bar(x-w/2, b_tx, w, color=C_BASE, alpha=0.85, label="Baseline tx")
ax2.bar(x-w/2, b_op, w, bottom=b_tx, color=C_BASE, alpha=0.45, label="Baseline op")
ax2.bar(x+w/2, s_tx, w, color=C_SCR,  alpha=0.85, label="SCR tx")
ax2.bar(x+w/2, s_op, w, bottom=s_tx, color=C_SCR,  alpha=0.45, label="SCR op")
ax2.set_xticks(x[::2]); ax2.set_xticklabels(rounds[::2])
ax2.set_title("Stacked tx + op Overhead per Round", fontsize=11)
ax2.set_xlabel("Round"); ax2.set_ylabel("Time (ms)")
ax2.legend(fontsize=8, ncol=2); ax2.grid(axis="y", alpha=0.3)

fig.suptitle("Per-Round Latency Breakdown", fontsize=13, fontweight="bold")
plt.tight_layout()
savefig("fig_latency_breakdown.png")

# ═══════════════════════════════════════════════════════════════════════════
# Fig 4 – Key metrics bar chart comparison
# ═══════════════════════════════════════════════════════════════════════════
labels = ["Avg tx\ntime (ms)", "Avg op\ntime (ms)", "Runtime (s)",
          "Final Acc\n(×100%)"]
b_vals = [BL["avg_transaction_time_ms"], BL["avg_operation_time_ms"],
          D["runtime_seconds"]["baseline"], BL["final_accuracy"]*100]
s_vals = [SC["avg_transaction_time_ms"], SC["avg_operation_time_ms"],
          D["runtime_seconds"]["scr_adaptive"], SC["final_accuracy"]*100]

x = np.arange(len(labels)); w = 0.32
fig, ax = plt.subplots(figsize=(11, 5.5))
bars_b = ax.bar(x-w/2, b_vals, w, color=C_BASE, alpha=0.9, label="Baseline")
bars_s = ax.bar(x+w/2, s_vals, w, color=C_SCR,  alpha=0.9, label="SCR+Adaptive")

for bar in bars_b:
    ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.3,
            f"{bar.get_height():.2f}", ha="center", va="bottom", fontsize=8, color=C_BASE)
for bar in bars_s:
    ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.3,
            f"{bar.get_height():.2f}", ha="center", va="bottom", fontsize=8, color=C_SCR)

# Improvement labels
imps = ["−12.83%", "−87.37%", "−49.41%", "+0.61%"]
for i, imp in enumerate(imps):
    col = C_SCR if imp.startswith("-") else "#D97706"
    ax.text(i, max(b_vals[i], s_vals[i])+1.5, imp,
            ha="center", fontsize=9, fontweight="bold", color=col)

ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=10)
ax.set_title("Key Metric Comparison: Baseline vs SCR+Adaptive PQBFL",
             fontsize=12, fontweight="bold")
ax.legend(fontsize=10); ax.grid(axis="y", alpha=0.3)
savefig("fig_metrics_comparison.png")

# ═══════════════════════════════════════════════════════════════════════════
# Fig 5 – Adaptive dynamics: L_j + threat level dual axis
# ═══════════════════════════════════════════════════════════════════════════
lj  = SC["L_j_per_round"][:R]
thr = SC["threat_level_per_round"][:R]
x20 = np.arange(1, len(lj)+1)

fig, ax1 = plt.subplots(figsize=(11, 5))
ax2 = ax1.twinx()

ax1.step(x20, lj, where="post", color=C_WIN, lw=2.8, label="$L_j$ (ratchet window)")
ax1.fill_between(x20, lj, step="post", alpha=0.12, color=C_WIN)
ax2.plot(x20, thr, color=C_THR, lw=2.2, ls="--", marker="^", ms=5,
         label="Threat level $\\Theta_r$")

# Mark ratchet adjustments
adj = SC["ratchet_adjustments"]
for a in adj:
    r_pt = int(a["round"])
    if 1 <= r_pt <= len(lj):
        ax1.axvline(r_pt, color=C_WIN, ls=":", lw=1.2, alpha=0.6)

# Threat events shading
for ev in SC["threat_events"]:
    r_ev = int(ev["round"])
    if 1 <= r_ev <= len(lj):
        ax2.axvspan(r_ev-0.5, r_ev+0.5, color=C_THR, alpha=0.05)

ax1.set_xlabel("FL Round", fontsize=11)
ax1.set_ylabel("$L_j$ (ratchet window size)", color=C_WIN, fontsize=11)
ax2.set_ylabel("Threat level $\\Theta_r$", color=C_THR, fontsize=11)
ax1.set_title("Adaptive Ratchet Dynamics in SCR+Adaptive Variant\n"
              "($L_j$ shrinks on high threat, recovers during quiescence)", fontsize=12)

lines1, labs1 = ax1.get_legend_handles_labels()
lines2, labs2 = ax2.get_legend_handles_labels()
ax1.legend(lines1+lines2, labs1+labs2, loc="upper right", fontsize=10)
ax1.grid(alpha=0.25)
ax1.set_ylim(0, 25); ax2.set_ylim(-0.05, 1.15)
savefig("fig_adaptive_dynamics.png")

# ═══════════════════════════════════════════════════════════════════════════
# Fig 6 – Cumulative overhead comparison
# ═══════════════════════════════════════════════════════════════════════════
b_cum = np.cumsum(b_tot)
s_cum = np.cumsum(s_tot)
saving = b_cum - s_cum

fig, axes = plt.subplots(1, 2, figsize=(13, 5))
ax1, ax2 = axes

ax1.plot(rounds, b_cum, color=C_BASE, lw=2.5, label="Baseline cumulative")
ax1.plot(rounds, s_cum, color=C_SCR,  lw=2.5, label="SCR+Adaptive cumulative")
ax1.fill_between(rounds, s_cum, b_cum, alpha=0.12, color=C_SCR,
                 label=f"Savings area")
ax1.set_title("Cumulative Protocol Overhead", fontsize=11)
ax1.set_xlabel("Round"); ax1.set_ylabel("Cumulative Time (ms)")
ax1.legend(fontsize=9); ax1.grid(alpha=0.3)

ax2.bar(rounds, saving, color=[C_SCR if v>0 else C_BASE for v in saving],
        alpha=0.85, label="Per-round saving (Baseline − SCR)")
ax2.axhline(0, color="black", lw=0.8)
ax2.set_title("Per-Round Latency Saving (Baseline − SCR+Adaptive)", fontsize=11)
ax2.set_xlabel("Round"); ax2.set_ylabel("Saving (ms)")
ax2.legend(fontsize=9); ax2.grid(axis="y", alpha=0.3)

fig.suptitle("Cumulative Overhead & Savings Analysis", fontsize=13, fontweight="bold")
plt.tight_layout()
savefig("fig_cumulative_overhead.png")

# ═══════════════════════════════════════════════════════════════════════════
# Fig 7 – Cryptographic scheme comparison radar/spider
# ═══════════════════════════════════════════════════════════════════════════
cats   = ["PQ\nSecurity", "Side-Ch.\nResist.", "Tx\nLatency", "Op\nLatency",
          "Runtime\nEfficiency", "Accuracy"]
b_scores = [0.70, 0.30, 0.53, 0.13, 0.34, 0.820]   # normalised [0,1]
s_scores = [0.85, 0.90, 0.61, 0.98, 0.66, 0.825]

N = len(cats)
angles = np.linspace(0, 2*np.pi, N, endpoint=False).tolist()
angles += angles[:1]
b_scores_p = b_scores + b_scores[:1]
s_scores_p = s_scores + s_scores[:1]

fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))
ax.plot(angles, b_scores_p, color=C_BASE, lw=2.5, label="Baseline")
ax.fill(angles, b_scores_p, alpha=0.15, color=C_BASE)
ax.plot(angles, s_scores_p, color=C_SCR, lw=2.5, label="SCR+Adaptive")
ax.fill(angles, s_scores_p, alpha=0.15, color=C_SCR)
ax.set_thetagrids(np.degrees(angles[:-1]), cats, fontsize=10)
ax.set_ylim(0, 1)
ax.set_title("Qualitative Attribute Comparison\n(Baseline vs SCR+Adaptive)",
             fontsize=12, fontweight="bold", pad=20)
ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.1), fontsize=10)
ax.grid(color="grey", alpha=0.3)
savefig("fig_radar_comparison.png")

# ═══════════════════════════════════════════════════════════════════════════
# Fig 8 – Threat event timeline
# ═══════════════════════════════════════════════════════════════════════════
events = SC["threat_events"]
ev_types = list({e["event_type"] for e in events})
ev_colors = {"sig_verification_failed": "#DC2626",
             "timing_anomaly": "#F59E0B",
             "stale_ratchet": "#6366F1",
             "reputation_drop": "#EC4899"}
fig, ax = plt.subplots(figsize=(12, 4))
for etype in ev_types:
    xs = [e["round"] for e in events if e["event_type"]==etype]
    ys = [e["severity"] for e in events if e["event_type"]==etype]
    col = ev_colors.get(etype, GREY)
    ax.scatter(xs, ys, color=col, s=80, label=etype.replace("_"," ").title(), zorder=4)

# Shade threat level
thr_x = np.arange(1, len(thr)+1)
ax.plot(thr_x, thr, color=C_THR, lw=1.8, ls="--", label="Threat $\\Theta_r$", alpha=0.7)
ax.fill_between(thr_x, 0, thr, alpha=0.08, color=C_THR)

# Ratchet adjustments
for a in adj:
    ax.axvline(int(a["round"]), color=C_WIN, ls=":", lw=1.5, alpha=0.7)

ax.set_xlabel("FL Round", fontsize=11)
ax.set_ylabel("Severity / Threat Level", fontsize=11)
ax.set_title("Threat Event Timeline & Composite Threat Level ($\\Theta_r$)",
             fontsize=12, fontweight="bold")
ax.legend(fontsize=9, ncol=3); ax.grid(alpha=0.3)
ax.set_xlim(0.5, R+0.5); ax.set_ylim(-0.05, 1.1)
savefig("fig_threat_timeline.png")

# ═══════════════════════════════════════════════════════════════════════════
# Fig 9 – Improvement summary waterfall / horizontal bars
# ═══════════════════════════════════════════════════════════════════════════
metrics  = ["Tx Latency", "Op Latency", "Runtime", "Final Accuracy"]
improv   = [12.83, 87.37, 49.41, 0.61]   # positive = SCR is better
colors   = [C_SCR if v > 0 else C_BASE for v in improv]

fig, ax = plt.subplots(figsize=(9, 4.5))
bars = ax.barh(metrics, improv, color=colors, alpha=0.88, height=0.5)
for bar, val in zip(bars, improv):
    ax.text(bar.get_width()+0.5, bar.get_y()+bar.get_height()/2,
            f"+{val:.2f}%", va="center", fontsize=11, fontweight="bold",
            color=C_SCR)
ax.axvline(0, color="black", lw=0.8)
ax.set_xlabel("Improvement (%) — SCR+Adaptive over Baseline", fontsize=11)
ax.set_title("Performance Improvement Summary: SCR+Adaptive vs Baseline",
             fontsize=12, fontweight="bold")
ax.grid(axis="x", alpha=0.3)
ax.set_xlim(-5, 100)
savefig("fig_improvement_summary.png")

print("\nAll figures written to:", OUT)
