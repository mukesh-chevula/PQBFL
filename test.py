"""
benchmark_zero_threat.py
========================
Performance comparison: Constant-L_j PQBFL (baseline) vs
Adaptive-Ratchet PQBFL under a ZERO-THREAT scenario.

Zero-threat behaviour
---------------------
* ThreatMonitor() sees no security events → threat_level = 0.0 always.
* AdaptiveRatchetPolicy.compute_L_j(0.0) = L_max  (maximum window).
* Asymmetric (expensive PQ) ratchet fires only every L_max rounds.
* Constant-L_j baseline fires every CONSTANT_L_J rounds (smaller = more overhead).

Graphs produced (light theme)
----------------------------
1. L_j over FL rounds  — adaptive stays at L_max; constant fixed at L_j
2. L_j vs threat level — theoretical mapping curve + zero-threat marker
3. Timing comparison   — total latency + cumulative overhead side-by-side
"""
from __future__ import annotations

import sys
import os
import time
import warnings

warnings.filterwarnings("ignore", category=RuntimeWarning)

# ── path setup ────────────────────────────────────────────────────────────────
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PYTHON_DIR = os.path.join(_SCRIPT_DIR, "pqbfl_project adaptive ratcheting", "python")
if _PYTHON_DIR not in sys.path:
    sys.path.insert(0, _PYTHON_DIR)

# ── third-party / project imports ────────────────────────────────────────────
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
from matplotlib.lines import Line2D

from pqbfl.protocol import (
    server_generate_keys, client_generate_keys,
    server_send_pubkeys, client_process_server_pubkeys,
    client_send_epk_and_ct, server_finish_session, client_finish_session,
    session_from_root, update_L_j, get_effective_L_j, should_asymmetric_ratchet,
    next_model_key, encrypt_round_message, decrypt_round_message,
)
from pqbfl.fl.model import LogisticModel, accuracy
from pqbfl.fl.aggregator import fedavg
from pqbfl.fl.data import make_synthetic_federated_binary
from pqbfl.adaptive.adaptive_ratchet import AdaptiveRatchetPolicy
from pqbfl.adaptive.threat_monitor import ThreatMonitor

# ── config ────────────────────────────────────────────────────────────────────
N_ROUNDS       = 40
N_CLIENTS      = 4
N_TRAIN        = 200
N_TEST         = 500
D              = 10
CONSTANT_L_J   = 10          # baseline: asymmetric ratchet every 10 rounds
ADAPTIVE_L_MIN = 2
ADAPTIVE_L_MAX = 20           # zero-threat: asymmetric ratchet every 20 rounds
ADAPTIVE_L_DEF = 10
SEED           = 42

OUTPUT_DIR = os.path.join(_SCRIPT_DIR, "benchmark_results")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── light theme palette ───────────────────────────────────────────────────────
C_CONST   = "#1F6FEB"    # strong blue   – baseline
C_ADAPT   = "#0D9E6E"    # vivid green   – adaptive (winner)
C_THREAT  = "#D04F00"    # burnt orange  – threat curve
C_RATCHET = "#CC2222"    # red spike     – asymmetric ratchet events
C_WIN_BG  = "#E8F5EE"    # light green bg for "better" regions
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

# ── credentials (test keys) ───────────────────────────────────────────────────
_SIG_PRIV = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
_SIG_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_CLI_PRIV = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
_CLI_ADDR = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


# ─────────────────────────────────────────────────────────────────────────────
# Session helper
# ─────────────────────────────────────────────────────────────────────────────

def _do_session_setup() -> tuple[bytes, bytes, float]:
    """Full 3-way PQ handshake → (server_root, client_root, elapsed_s)."""
    from pqbfl.utils import sha256
    t0 = time.perf_counter()
    server = server_generate_keys(_SIG_PRIV, _SIG_ADDR)
    client = client_generate_keys(_CLI_PRIV, _CLI_ADDR)
    tx_r   = {"block": 1, "hash": "0x" + "ab" * 32}
    id_p   = 1

    server_pub = server_send_pubkeys(server, tx_r=tx_r, id_p=id_p)
    kpk_b = server_pub.payload["kpk_b"]
    epk_b = server_pub.payload["epk_b"]
    h_pks = sha256(kpk_b + epk_b)

    encap = client_process_server_pubkeys(
        client, server_sig_addr=_SIG_ADDR, signed=server_pub,
        expected_h_pks=h_pks,
    )
    h_epk_a   = sha256(client.ecdh.public_key_bytes)
    client_msg = client_send_epk_and_ct(client, tx_r=tx_r, id_p=id_p, ct=encap.ciphertext)
    server_root = server_finish_session(
        server, client_sig_addr=_CLI_ADDR, signed=client_msg,
        expected_h_epk_a=h_epk_a,
    )
    client_root = client_finish_session(client, server_pub=server_pub, encap=encap)
    return server_root, client_root, time.perf_counter() - t0


# ─────────────────────────────────────────────────────────────────────────────
# Simulation
# ─────────────────────────────────────────────────────────────────────────────

def run_simulation(*, use_adaptive: bool, data, n_rounds: int = N_ROUNDS) -> dict:
    label = "ADAPTIVE (zero-threat)" if use_adaptive else f"CONSTANT L_j={CONSTANT_L_J}"
    print(f"\n{'='*56}\n  Variant: {label}\n{'='*56}")

    server_root, client_root, setup_time = _do_session_setup()
    L_j_init = ADAPTIVE_L_DEF if use_adaptive else CONSTANT_L_J
    s_state  = session_from_root(server_root, L_j=L_j_init)
    c_state  = session_from_root(client_root, L_j=L_j_init)

    policy  = AdaptiveRatchetPolicy(
        L_min=ADAPTIVE_L_MIN, L_max=ADAPTIVE_L_MAX, L_default=ADAPTIVE_L_DEF,
    ) if use_adaptive else None
    monitor = ThreatMonitor() if use_adaptive else None

    global_model = LogisticModel.init(D, seed=SEED)

    rounds, lj_values, threat_levels, asym_ratchet_at = [], [], [], []
    time_session, time_sym_ratchet = [], []
    time_encrypt, time_decrypt, time_fl, time_total = [], [], [], []
    accuracies = []

    for rnd in range(1, n_rounds + 1):
        t_round = time.perf_counter()

        # ── threat level: always 0.0 (zero-threat scenario) ──────
        threat_level = 0.0
        if use_adaptive and monitor is not None:
            threat_level = monitor.get_threat_level()

        # ── adaptive L_j update ───────────────────────────────────
        if use_adaptive and policy is not None:
            new_lj = policy.evaluate(threat_level, round_num=rnd,
                                     reason=f"rnd {rnd}: threat={threat_level:.4f}")
            update_L_j(s_state, new_lj)
            update_L_j(c_state, new_lj)

        effective_lj = get_effective_L_j(s_state)

        # ── asymmetric ratchet (PQ key re-gen) check ─────────────
        t_sess = time.perf_counter()
        if should_asymmetric_ratchet(s_state):
            sr2, cr2, _ = _do_session_setup()
            s_state = session_from_root(sr2, L_j=effective_lj)
            c_state = session_from_root(cr2, L_j=effective_lj)
            if use_adaptive and policy is not None:
                update_L_j(s_state, effective_lj)
                update_L_j(c_state, effective_lj)
            asym_ratchet_at.append(rnd)
            print(f"  Round {rnd:3d}: ⚡ ASYMMETRIC RATCHET (L_j={effective_lj})")
        t_sess = time.perf_counter() - t_sess

        # ── symmetric ratchet ─────────────────────────────────────
        t_sym = time.perf_counter()
        s_state, s_key = next_model_key(s_state)
        c_state, c_key = next_model_key(c_state)
        t_sym = time.perf_counter() - t_sym

        # ── FL training ───────────────────────────────────────────
        t_fl = time.perf_counter()
        trained = []
        for k, cd in enumerate(data.clients):
            local = global_model.copy()
            local.train_sgd(cd.x, cd.y, lr=0.05, epochs=2, seed=SEED + rnd + k)
            trained.append((local, len(cd.x)))
        t_fl = time.perf_counter() - t_fl

        agg     = fedavg(trained)
        payload = {"w": agg.w.tolist(), "b": float(agg.b)}

        # ── encrypt / decrypt ─────────────────────────────────────
        t_enc = time.perf_counter()
        ct = encrypt_round_message(s_key, round_num=rnd, direction="s2c", payload=payload)
        t_enc = time.perf_counter() - t_enc

        t_dec = time.perf_counter()
        dec = decrypt_round_message(c_key, round_num=rnd, direction="s2c", ciphertext=ct)
        t_dec = time.perf_counter() - t_dec

        import json
        global_model.w = np.array(dec["w"], dtype=np.float64)
        global_model.b = float(dec["b"])
        acc = accuracy(global_model, data.x_test, data.y_test)
        t_total_val = time.perf_counter() - t_round

        rounds.append(rnd);           lj_values.append(effective_lj)
        threat_levels.append(threat_level)
        time_session.append(t_sess);  time_sym_ratchet.append(t_sym)
        time_encrypt.append(t_enc);   time_decrypt.append(t_dec)
        time_fl.append(t_fl);         time_total.append(t_total_val)
        accuracies.append(acc)

        print(f"  Round {rnd:3d}: L_j={effective_lj:2d}  threat={threat_level:.3f}"
              f"  acc={acc:.3f}  {t_total_val*1000:.2f}ms")

    return dict(variant="adaptive" if use_adaptive else "constant",
                rounds=rounds, lj_values=lj_values, threat_levels=threat_levels,
                asym_ratchet_at=asym_ratchet_at, time_session=time_session,
                time_sym_ratchet=time_sym_ratchet, time_encrypt=time_encrypt,
                time_decrypt=time_decrypt, time_fl=time_fl,
                time_total=time_total, accuracies=accuracies,
                setup_time=setup_time)


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def ms(arr): return [v * 1000 for v in arr]


def _badge(ax, text, xy, color, fontsize=9):
    """Draw a pill-shaped annotation badge."""
    ax.annotate(text, xy=xy, fontsize=fontsize, fontweight="bold",
                color="white", ha="center", va="center",
                bbox=dict(boxstyle="round,pad=0.35", facecolor=color,
                          edgecolor="none", alpha=0.92))


# ─────────────────────────────────────────────────────────────────────────────
# Graph 1 — L_j over rounds
# ─────────────────────────────────────────────────────────────────────────────

def plot_lj_over_rounds(const_r, adapt_r, out_path: str):
    fig, ax = plt.subplots(figsize=(13, 5.5))
    fig.patch.set_facecolor(C_BG)

    # Title
    fig.text(0.5, 0.97,
             "Graph 1 — Ratcheting Window (L_j) Over FL Rounds",
             ha="center", va="top", fontsize=14, fontweight="bold", color=C_TEXT)
    fig.text(0.5, 0.91,
             "Zero-Threat Scenario  ·  Adaptive PQBFL keeps L_j at maximum (L_max = 20)  ·  "
             "Fewer asymmetric ratchets = lower overhead",
             ha="center", va="top", fontsize=9.5, color=C_SUBTEXT)

    rounds = const_r["rounds"]

    # Green "advantage zone" between the two lines
    ax.fill_between(rounds,
                    const_r["lj_values"], adapt_r["lj_values"],
                    alpha=0.12, color=C_ADAPT, label="_nolegend_")

    # Lines
    ax.step(rounds, const_r["lj_values"], where="post",
            color=C_CONST, lw=2.5,
            label=f"Baseline PQBFL — Constant L_j = {CONSTANT_L_J}")
    ax.step(rounds, adapt_r["lj_values"], where="post",
            color=C_ADAPT, lw=2.8, linestyle="-",
            label=f"Adaptive PQBFL — Zero-threat → L_j = {ADAPTIVE_L_MAX}  ✓ BETTER")

    # Asymmetric ratchet verticals
    for i, rnd in enumerate(const_r["asym_ratchet_at"]):
        ax.axvline(rnd, color=C_RATCHET, alpha=0.55, lw=1.6, linestyle="--")
        ax.text(rnd + 0.3, CONSTANT_L_J + 2.5,
                f"⚡ Ratchet\n(rnd {rnd})",
                fontsize=7.5, color=C_RATCHET, va="bottom")

    for rnd in adapt_r["asym_ratchet_at"]:
        ax.axvline(rnd, color=C_ADAPT, alpha=0.5, lw=1.6, linestyle="--")
        ax.text(rnd + 0.3, ADAPTIVE_L_MAX + 1.4,
                f"⚡ Ratchet\n(rnd {rnd})",
                fontsize=7.5, color=C_ADAPT, va="bottom")

    # "ADAPTIVE WINS" badge in the gap region
    mid_rnd = N_ROUNDS // 2
    ax.annotate("",
                xy=(mid_rnd, (CONSTANT_L_J + ADAPTIVE_L_MAX) / 2 + 1),
                xytext=(mid_rnd, (CONSTANT_L_J + ADAPTIVE_L_MAX) / 2 - 1),
                arrowprops=dict(arrowstyle="<->", color=C_ADAPT, lw=1.5))
    ax.text(mid_rnd + 1.5, (CONSTANT_L_J + ADAPTIVE_L_MAX) / 2,
            f"+{ADAPTIVE_L_MAX - CONSTANT_L_J} rounds\nbetween ratchets",
            fontsize=8, color=C_ADAPT, fontweight="bold", va="center")

    # Info callout
    n_c = len(const_r["asym_ratchet_at"])
    n_a = len(adapt_r["asym_ratchet_at"])
    info_lines = (
        f"Asymmetric ratchets (40 rounds):\n"
        f"  Baseline  :  {n_c}×  (every {CONSTANT_L_J} rounds)\n"
        f"  Adaptive  :  {n_a}×  (every {ADAPTIVE_L_MAX} rounds)  ← {n_c-n_a} fewer!"
    )
    ax.text(0.01, 0.98, info_lines, transform=ax.transAxes,
            fontsize=9, color=C_TEXT, va="top", ha="left", linespacing=1.5,
            bbox=dict(boxstyle="round,pad=0.5", facecolor="white",
                      edgecolor=C_BORDER, alpha=0.95))

    ax.set_xlabel("FL Round", fontsize=11)
    ax.set_ylabel("Effective L_j  (symmetric ratchet window)", fontsize=11)
    ax.set_xlim(1, N_ROUNDS)
    ax.set_ylim(0, ADAPTIVE_L_MAX + 8)
    ax.grid(True)
    leg = ax.legend(fontsize=10, loc="upper right",
                    framealpha=1, edgecolor=C_BORDER)
    # Green tint on the "adaptive" legend entry
    leg.get_texts()[1].set_color(C_ADAPT)
    leg.get_texts()[1].set_fontweight("bold")

    plt.tight_layout(rect=[0, 0, 1, 0.89])
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\n✅ Graph 1 saved → {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Graph 2 — L_j vs threat level
# ─────────────────────────────────────────────────────────────────────────────

def plot_lj_vs_threat(out_path: str):
    policy = AdaptiveRatchetPolicy(
        L_min=ADAPTIVE_L_MIN, L_max=ADAPTIVE_L_MAX, L_default=ADAPTIVE_L_DEF,
    )
    tv  = np.linspace(0.0, 1.0, 600)
    ljv = [policy.compute_L_j(t) for t in tv]

    fig, ax = plt.subplots(figsize=(11, 5.5))
    fig.patch.set_facecolor(C_BG)
    fig.text(0.5, 0.97,
             "Graph 2 — Adaptive L_j vs Threat Level",
             ha="center", va="top", fontsize=14, fontweight="bold", color=C_TEXT)
    fig.text(0.5, 0.91,
             "L_j = L_max − (L_max − L_min) × threat^sensitivity  "
             "·  At zero threat → L_j = L_max (maximum efficiency)",
             ha="center", va="top", fontsize=9.5, color=C_SUBTEXT)

    # Shade: zero-threat advantage region (adaptive > constant)
    ax.fill_between(tv, CONSTANT_L_J, ljv,
                    where=[l > CONSTANT_L_J for l in ljv],
                    alpha=0.15, color=C_ADAPT,
                    label=f"Adaptive BETTER than baseline (L_j > {CONSTANT_L_J})")

    # Shade: below baseline (extreme threat, adaptive is more restrictive)
    ax.fill_between(tv, ljv, CONSTANT_L_J,
                    where=[l < CONSTANT_L_J for l in ljv],
                    alpha=0.10, color=C_CONST,
                    label=f"High-threat: adaptive tightens L_j (more secure)")

    # Main adaptive curve
    ax.plot(tv, ljv, color=C_THREAT, lw=3,
            label=f"Adaptive L_j curve  (sensitivity = {policy.sensitivity})")

    # Baseline constant line
    ax.axhline(CONSTANT_L_J, color=C_CONST, lw=2, linestyle="--",
               label=f"Baseline Constant L_j = {CONSTANT_L_J}")

    # Zero-threat marker
    ax.scatter([0.0], [ADAPTIVE_L_MAX], s=160, color=C_ADAPT,
               zorder=6, label=f"Zero-threat operating point  (L_j = {ADAPTIVE_L_MAX})  ← Current")
    ax.annotate(f"  Zero-Threat\n  L_j = {ADAPTIVE_L_MAX}  ✓",
                xy=(0.0, ADAPTIVE_L_MAX),
                xytext=(0.08, ADAPTIVE_L_MAX - 2.5),
                arrowprops=dict(arrowstyle="->", color=C_ADAPT, lw=1.5),
                fontsize=10, fontweight="bold", color=C_ADAPT)

    # Current scenario shading
    ax.axvspan(0, 0.015, color=C_ADAPT, alpha=0.12, zorder=0)
    ax.text(0.022, ADAPTIVE_L_MAX - 1, "← We are\n   here",
            fontsize=8.5, color=C_ADAPT, va="top")

    # L_max / L_min labels
    ax.text(1.01, ADAPTIVE_L_MAX, f"L_max={ADAPTIVE_L_MAX}", va="center",
            fontsize=8.5, color=C_ADAPT, transform=ax.get_yaxis_transform())
    ax.text(1.01, ADAPTIVE_L_MIN, f"L_min={ADAPTIVE_L_MIN}", va="center",
            fontsize=8.5, color=C_RATCHET, transform=ax.get_yaxis_transform())

    ax.set_xlabel("Composite Threat Level  (0 = no threat,  1 = maximum threat)", fontsize=11)
    ax.set_ylabel("Effective L_j  (symmetric ratchet window)", fontsize=11)
    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(0, ADAPTIVE_L_MAX + 5)
    ax.set_xticks(np.arange(0, 1.1, 0.1))
    ax.grid(True)
    ax.legend(fontsize=9, loc="upper right", framealpha=1, edgecolor=C_BORDER)

    plt.tight_layout(rect=[0, 0, 1, 0.89])
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"✅ Graph 2 saved → {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Graph 3 — Timing comparison (main ask)
# ─────────────────────────────────────────────────────────────────────────────

def _timing_common(const_r, adapt_r):
    """Pre-compute shared values used by all three timing graphs."""
    t_const = ms(const_r["time_total"])
    t_adapt = ms(adapt_r["time_total"])
    avg_c   = float(np.mean(t_const))
    avg_a   = float(np.mean(t_adapt))
    speedup = (avg_c - avg_a) / avg_c * 100
    n_c     = len(const_r["asym_ratchet_at"])
    n_a     = len(adapt_r["asym_ratchet_at"])
    cum_c   = list(np.cumsum(t_const))
    cum_a   = list(np.cumsum(t_adapt))
    return t_const, t_adapt, avg_c, avg_a, speedup, n_c, n_a, cum_c, cum_a


def plot_timing_per_round(const_r, adapt_r, out_path: str):
    """Graph 3a — per-round total latency."""
    rounds = const_r["rounds"]
    t_const, t_adapt, avg_c, avg_a, speedup, n_c, n_a, _, _ = _timing_common(const_r, adapt_r)

    fig, ax = plt.subplots(figsize=(13, 5.5))
    fig.patch.set_facecolor(C_BG)
    fig.text(0.5, 0.97,
             "Graph 3a — Per-Round Total Latency (ms)",
             ha="center", va="top", fontsize=14, fontweight="bold", color=C_TEXT)
    fig.text(0.5, 0.91,
             f"Zero-Threat Scenario  ·  Adaptive is {speedup:.0f}% faster on average  "
             f"·  Spikes = asymmetric (PQ) ratchet events",
             ha="center", va="top", fontsize=9.5, color=C_SUBTEXT)

    ax.fill_between(rounds, t_const, t_adapt,
                    where=[c >= a for c, a in zip(t_const, t_adapt)],
                    alpha=0.13, color=C_ADAPT)
    ax.plot(rounds, t_const, color=C_CONST, lw=2.2,
            label=f"Baseline PQBFL  (Constant L_j = {CONSTANT_L_J})")
    ax.plot(rounds, t_adapt, color=C_ADAPT, lw=2.5,
            label=f"Adaptive PQBFL  (Zero-Threat, L_j = {ADAPTIVE_L_MAX})  — FASTER")

    for rnd in const_r["asym_ratchet_at"]:
        ax.axvspan(rnd - 0.45, rnd + 0.45, alpha=0.18, color=C_RATCHET)
        ax.text(rnd, max(t_const) * 1.01, "Ratchet", ha="center",
                fontsize=7.5, color=C_RATCHET, rotation=90, va="bottom")
    for rnd in adapt_r["asym_ratchet_at"]:
        ax.axvspan(rnd - 0.45, rnd + 0.45, alpha=0.13, color=C_ADAPT)
        ax.text(rnd, max(t_adapt) * 0.80, "Ratchet", ha="center",
                fontsize=7.5, color=C_ADAPT, rotation=90, va="bottom")

    ax.axhline(avg_c, color=C_CONST, lw=1.2, linestyle=":", alpha=0.75)
    ax.axhline(avg_a, color=C_ADAPT, lw=1.2, linestyle=":", alpha=0.75)
    ax.text(N_ROUNDS + 0.4, avg_c, f"avg {avg_c:.2f}ms",
            va="center", fontsize=8.5, color=C_CONST)
    ax.text(N_ROUNDS + 0.4, avg_a, f"avg {avg_a:.2f}ms",
            va="center", fontsize=8.5, color=C_ADAPT, fontweight="bold")

    ax.set_xlabel("FL Round", fontsize=11)
    ax.set_ylabel("Latency (ms)", fontsize=11)
    ax.set_xlim(1, N_ROUNDS + 5)
    ax.grid(True)
    leg = ax.legend(fontsize=10, loc="upper left", framealpha=1, edgecolor=C_BORDER)
    leg.get_texts()[1].set_color(C_ADAPT)
    leg.get_texts()[1].set_fontweight("bold")

    # Summary banner
    acc_c = float(np.mean(const_r["accuracies"]))
    acc_a = float(np.mean(adapt_r["accuracies"]))
    fig.text(0.5, 0.03,
             f"  Adaptive PQBFL is {speedup:.0f}% faster  |  "
             f"Same accuracy ({acc_c:.3f} vs {acc_a:.3f})  |  "
             f"{n_c - n_a} fewer ratchets over {N_ROUNDS} rounds  ",
             ha="center", va="bottom", fontsize=10, fontweight="bold", color="white",
             bbox=dict(boxstyle="round,pad=0.45", facecolor=C_ADAPT,
                       edgecolor="none", alpha=0.93))

    plt.tight_layout(rect=[0, 0.08, 1, 0.89])
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"✅ Graph 3a saved → {out_path}")


def plot_timing_cumulative(const_r, adapt_r, out_path: str):
    """Graph 3b — cumulative total overhead."""
    rounds = const_r["rounds"]
    t_const, t_adapt, avg_c, avg_a, speedup, n_c, n_a, cum_c, cum_a = _timing_common(const_r, adapt_r)
    saved = cum_c[-1] - cum_a[-1]

    fig, ax = plt.subplots(figsize=(11, 5.5))
    fig.patch.set_facecolor(C_BG)
    fig.text(0.5, 0.97,
             "Graph 3b — Cumulative Round Overhead (ms)",
             ha="center", va="top", fontsize=14, fontweight="bold", color=C_TEXT)
    fig.text(0.5, 0.91,
             f"Zero-Threat Scenario  ·  Green shading = time saved by Adaptive PQBFL",
             ha="center", va="top", fontsize=9.5, color=C_SUBTEXT)

    ax.fill_between(rounds, cum_c, cum_a,
                    alpha=0.18, color=C_ADAPT, label=f"Time saved ({saved:.1f} ms total)")
    ax.plot(rounds, cum_c, color=C_CONST, lw=2.4,
            label=f"Baseline PQBFL  (Constant L_j = {CONSTANT_L_J})")
    ax.plot(rounds, cum_a, color=C_ADAPT, lw=2.7,
            label=f"Adaptive PQBFL  (Zero-Threat, L_j = {ADAPTIVE_L_MAX})  — BETTER")

    # Jump markers at ratchet rounds
    for rnd in const_r["asym_ratchet_at"]:
        ax.axvline(rnd, color=C_RATCHET, lw=1.3, linestyle="--", alpha=0.55)
        ax.text(rnd + 0.4, cum_c[rnd - 1] * 0.85,
                f"Ratchet\n(rnd {rnd})", fontsize=7.5, color=C_RATCHET)
    for rnd in adapt_r["asym_ratchet_at"]:
        ax.axvline(rnd, color=C_ADAPT, lw=1.3, linestyle="--", alpha=0.45)

    # "Saved" annotation
    mid = N_ROUNDS * 3 // 4
    ax.annotate(f"Saved\n{saved:.1f} ms\ntotal",
                xy=(N_ROUNDS, (cum_c[-1] + cum_a[-1]) / 2),
                xytext=(mid, (cum_c[mid - 1] + cum_a[mid - 1]) / 2 + 5),
                arrowprops=dict(arrowstyle="->", color=C_ADAPT, lw=1.5),
                fontsize=10, color=C_ADAPT, fontweight="bold")

    ax.set_xlabel("FL Round", fontsize=11)
    ax.set_ylabel("Cumulative Time (ms)", fontsize=11)
    ax.set_xlim(1, N_ROUNDS)
    ax.grid(True)
    leg = ax.legend(fontsize=10, loc="upper left", framealpha=1, edgecolor=C_BORDER)
    leg.get_texts()[2].set_color(C_ADAPT)
    leg.get_texts()[2].set_fontweight("bold")

    acc_c = float(np.mean(const_r["accuracies"]))
    acc_a = float(np.mean(adapt_r["accuracies"]))
    fig.text(0.5, 0.03,
             f"  Adaptive PQBFL is {speedup:.0f}% faster  |  "
             f"Same accuracy ({acc_c:.3f} vs {acc_a:.3f})  |  "
             f"{n_c - n_a} fewer ratchets over {N_ROUNDS} rounds  ",
             ha="center", va="bottom", fontsize=10, fontweight="bold", color="white",
             bbox=dict(boxstyle="round,pad=0.45", facecolor=C_ADAPT,
                       edgecolor="none", alpha=0.93))

    plt.tight_layout(rect=[0, 0.08, 1, 0.89])
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"✅ Graph 3b saved → {out_path}")


def plot_timing_bar_metrics(const_r, adapt_r, out_path: str):
    """Graph 3c — key metrics bar chart comparison."""
    t_const, t_adapt, avg_c, avg_a, speedup, n_c, n_a, _, _ = _timing_common(const_r, adapt_r)
    acc_c = float(np.mean(const_r["accuracies"]))
    acc_a = float(np.mean(adapt_r["accuracies"]))

    fig, ax = plt.subplots(figsize=(10, 5.5))
    fig.patch.set_facecolor(C_BG)
    fig.text(0.5, 0.97,
             "Graph 3c — Key Performance Metrics: Baseline vs Adaptive PQBFL",
             ha="center", va="top", fontsize=14, fontweight="bold", color=C_TEXT)
    fig.text(0.5, 0.91,
             "Zero-Threat Scenario  ·  Lower bars are better for Ratchets & Latency; "
             "Higher bar is better for Speedup",
             ha="center", va="top", fontsize=9.5, color=C_SUBTEXT)

    categories  = ["Asymmetric\nRatchets (count)", "Avg Round\nLatency (ms)", "Speedup (%)"]
    const_vals  = [n_c,    round(avg_c, 2), 0.0]
    adapt_vals  = [n_a,    round(avg_a, 2), round(speedup, 1)]
    x           = np.arange(len(categories))
    bw          = 0.32

    bars_c = ax.bar(x - bw / 2, const_vals, bw, color=C_CONST,
                    alpha=0.85, label=f"Baseline PQBFL  (L_j = {CONSTANT_L_J})", zorder=3)
    bars_a = ax.bar(x + bw / 2, adapt_vals, bw, color=C_ADAPT,
                    alpha=0.90, label=f"Adaptive PQBFL  (L_j = {ADAPTIVE_L_MAX})  — BETTER", zorder=3)

    for bar in bars_c:
        v = bar.get_height()
        if v > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, v + 0.08,
                    f"{v}", ha="center", va="bottom",
                    fontsize=11, color=C_CONST, fontweight="bold")
    for bar in bars_a:
        v = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, v + 0.08,
                f"{v}", ha="center", va="bottom",
                fontsize=11, color=C_ADAPT, fontweight="bold")

    # Improvement arrows for ratchets and latency
    for xi in [0, 1]:
        hc = const_vals[xi]
        ha_ = adapt_vals[xi]
        top = max(hc, ha_)
        ax.annotate("", xy=(xi + bw / 2, ha_ + 0.5),
                    xytext=(xi - bw / 2, hc + 0.5),
                    arrowprops=dict(arrowstyle="->", color="#555", lw=1.4))

    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=10.5)
    ax.set_ylabel("Value", fontsize=11)
    ax.grid(True, axis="y")
    leg = ax.legend(fontsize=10, loc="upper center", framealpha=1, edgecolor=C_BORDER)
    leg.get_texts()[1].set_color(C_ADAPT)
    leg.get_texts()[1].set_fontweight("bold")

    fig.text(0.5, 0.03,
             f"  Adaptive PQBFL is {speedup:.0f}% faster  |  "
             f"Same accuracy ({acc_c:.3f} vs {acc_a:.3f})  |  "
             f"{n_c - n_a} fewer ratchets over {N_ROUNDS} rounds  ",
             ha="center", va="bottom", fontsize=10, fontweight="bold", color="white",
             bbox=dict(boxstyle="round,pad=0.45", facecolor=C_ADAPT,
                       edgecolor="none", alpha=0.93))

    plt.tight_layout(rect=[0, 0.08, 1, 0.89])
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"✅ Graph 3c saved → {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "=" * 56)
    print("  PQBFL Zero-Threat Performance Benchmark")
    print(f"  Constant L_j = {CONSTANT_L_J}  vs  Adaptive (L_max = {ADAPTIVE_L_MAX})")
    print("=" * 56)

    data = make_synthetic_federated_binary(
        n_clients=N_CLIENTS, n_train_per_client=N_TRAIN,
        n_test=N_TEST, d=D, seed=SEED, non_iid=True,
    )

    const_r = run_simulation(use_adaptive=False, data=data)
    adapt_r = run_simulation(use_adaptive=True,  data=data)

    print("\n" + "="*56 + "\n  Generating graphs…\n" + "="*56)

    plot_lj_over_rounds(const_r, adapt_r,
        out_path=os.path.join(OUTPUT_DIR, "graph1_lj_over_rounds.png"))
    plot_lj_vs_threat(
        out_path=os.path.join(OUTPUT_DIR, "graph2_lj_vs_threat.png"))
    plot_timing_per_round(const_r, adapt_r,
        out_path=os.path.join(OUTPUT_DIR, "graph3a_per_round_latency.png"))
    plot_timing_cumulative(const_r, adapt_r,
        out_path=os.path.join(OUTPUT_DIR, "graph3b_cumulative_overhead.png"))
    plot_timing_bar_metrics(const_r, adapt_r,
        out_path=os.path.join(OUTPUT_DIR, "graph3c_key_metrics.png"))

    # ── console summary ───────────────────────────────────────────
    avg_c  = np.mean(const_r["time_total"]) * 1000
    avg_a  = np.mean(adapt_r["time_total"]) * 1000
    pct    = (avg_c - avg_a) / avg_c * 100
    n_ac   = len(const_r["asym_ratchet_at"])
    n_aa   = len(adapt_r["asym_ratchet_at"])
    acc_c  = np.mean(const_r["accuracies"])
    acc_a  = np.mean(adapt_r["accuracies"])

    print(f"\n{'='*56}\n  RESULTS SUMMARY\n{'='*56}")
    print(f"  {'':32} {'Baseline':>10} {'Adaptive':>10}")
    print(f"  {'─'*54}")
    print(f"  {'Avg round latency (ms)':.<32} {avg_c:>10.2f} {avg_a:>10.2f}")
    print(f"  {'Asymmetric ratchets':.<32} {n_ac:>10} {n_aa:>10}")
    print(f"  {'L_j (zero-threat)':.<32} {CONSTANT_L_J:>10} {ADAPTIVE_L_MAX:>10}")
    print(f"  {'Avg FL accuracy':.<32} {acc_c:>10.3f} {acc_a:>10.3f}")
    print(f"  {'Adaptive speedup':.<32} {'—':>10} {pct:>9.1f}%")
    print(f"\n  Graphs → {OUTPUT_DIR}/\n{'='*56}\n")


if __name__ == "__main__":
    main()
