"""
sc_masking_diagram.py
=====================
Generates a publication-quality diagram of the side-channel masking
pipeline used across all cryptographic primitives in the
PQBFL adaptive side-channel-resistant framework.

Three defence layers are illustrated:
  1. Boolean masking of the secret  →  share1 ⊕ share2 = secret
  2. Leakage trace simulation       →  Hamming-weight model + Gaussian noise + jitter
  3. Adaptive trace defence         →  noise injection / random temporal shift

Applies to: Kyber KEM decap, ECDH (secp256k1 & X25519), ChaCha20-Poly1305 AEAD.

Usage
-----
  python sc_masking_diagram.py
Output saved to ./sc_masking_diagram.png
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
import numpy as np

OUT_PATH = Path(__file__).resolve().parent / "sc_masking_diagram.png"

# ── palette ───────────────────────────────────────────────────────────────────
C_BG        = "#0F1117"
C_PANEL     = "#1A1E2E"
C_BORDER    = "#2E3450"
C_SECRET    = "#E05252"   # red  – secret key (sensitive)
C_SHARE1    = "#4A9EEB"   # blue – share 1
C_SHARE2    = "#3EC98A"   # green – share 2
C_TRACE     = "#F0A500"   # amber – raw trace
C_DEFENDED  = "#B06EF5"   # purple – defended trace
C_CRYPTO    = "#5BC8F5"   # sky  – crypto op
C_XOR       = "#FFFFFF"
C_TEXT      = "#E8ECF4"
C_SUBTEXT   = "#8A92B2"
C_ARROW     = "#5A6490"
C_ADAPT     = "#3EC98A"
C_PRIM_BG   = "#12192B"

FONT_TITLE  = {"fontsize": 15, "fontweight": "bold", "color": C_TEXT}
FONT_LABEL  = {"fontsize": 9,  "fontweight": "bold", "color": C_TEXT}
FONT_SMALL  = {"fontsize": 7.5, "color": C_SUBTEXT}
FONT_CODE   = {"fontsize": 7.5, "color": C_SHARE1, "family": "monospace"}

plt.rcParams.update({
    "figure.facecolor": C_BG,
    "text.color":       C_TEXT,
    "font.family":      "DejaVu Sans",
})


def _box(ax, x, y, w, h, fc, ec=C_BORDER, lw=1.4, radius=0.015, zorder=3, alpha=1.0):
    box = FancyBboxPatch((x, y), w, h,
                         boxstyle=f"round,pad=0,rounding_size={radius}",
                         facecolor=fc, edgecolor=ec, linewidth=lw,
                         zorder=zorder, alpha=alpha)
    ax.add_patch(box)
    return box


def _arrow(ax, x0, y0, x1, y1, color=C_ARROW, lw=1.5, zorder=4, style="->"):
    ax.annotate("", xy=(x1, y1), xytext=(x0, y0),
                arrowprops=dict(arrowstyle=style, color=color,
                                lw=lw, connectionstyle="arc3,rad=0.0"),
                zorder=zorder)


def _text(ax, x, y, s, **kw):
    ax.text(x, y, s, ha="center", va="center", **kw)


def _label(ax, x, y, s, **kw):
    kw = {**FONT_LABEL, **kw}
    ax.text(x, y, s, ha="center", va="center", **kw)


# ── synthetic traces for illustration ────────────────────────────────────────

def _hw(x):
    return bin(x).count("1")

def make_traces(n=32):
    rng = np.random.default_rng(42)
    secret = rng.integers(0, 256, n, dtype=np.uint8)
    mask   = rng.integers(0, 256, n, dtype=np.uint8)
    s1 = np.bitwise_xor(secret, mask)
    s2 = mask

    hw_s  = np.array([_hw(b) for b in secret], dtype=float)
    hw_s1 = np.array([_hw(b) for b in s1],     dtype=float)
    hw_s2 = np.array([_hw(b) for b in s2],     dtype=float)

    noise_std = 0.9
    raw_s  = hw_s  + rng.normal(0, noise_std, n)
    raw_s1 = hw_s1 + rng.normal(0, noise_std, n)
    raw_s2 = hw_s2 + rng.normal(0, noise_std, n)
    combined = raw_s1 + raw_s2

    # adaptive: noise + jitter
    defended = combined + rng.normal(0, 2.5, n)
    defended = np.roll(defended, rng.integers(1, 5))

    xs = np.arange(n)
    return xs, raw_s, raw_s1, raw_s2, combined, defended


# ── main figure ───────────────────────────────────────────────────────────────

def draw():
    fig = plt.figure(figsize=(18, 13), facecolor=C_BG)
    ax  = fig.add_axes([0, 0, 1, 1])   # full-canvas axes
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.set_aspect("auto")
    ax.axis("off")
    ax.set_facecolor(C_BG)

    xs, raw_s, raw_s1, raw_s2, combined, defended = make_traces()
    xs_n = xs / xs.max()   # normalised to [0,1]

    # ── Title ─────────────────────────────────────────────────────────────────
    ax.text(0.5, 0.965,
            "Side-Channel Masking Pipeline — PQBFL Adaptive SC-Resistant Variant",
            ha="center", va="top", fontsize=16, fontweight="bold", color=C_TEXT)
    ax.text(0.5, 0.940,
            "Boolean masking  ·  Hamming-weight leakage simulation  ·  Adaptive noise + jitter defence",
            ha="center", va="top", fontsize=10, color=C_SUBTEXT)

    # ══════════════════════════════════════════════════════════════════════════
    # ROW 1 — Secret key masking
    # ══════════════════════════════════════════════════════════════════════════
    ROW1_Y = 0.73   # top of row 1 boxes

    # Section label
    ax.text(0.02, ROW1_Y + 0.065, "① BOOLEAN MASKING  (mask_bytes)",
            fontsize=10, fontweight="bold", color=C_SHARE2, va="center")

    # [Secret Key k]
    _box(ax, 0.04, ROW1_Y, 0.17, 0.055, fc=C_SECRET + "33", ec=C_SECRET, lw=2)
    _label(ax, 0.125, ROW1_Y + 0.0275, "Secret Key  k", color=C_SECRET, fontsize=10)
    ax.text(0.125, ROW1_Y + 0.008, "32 bytes  (KEM sk / ECDH priv / AEAD key)",
            ha="center", va="bottom", **FONT_SMALL)

    # arrow →
    _arrow(ax, 0.21, ROW1_Y + 0.0275, 0.265, ROW1_Y + 0.0275, color=C_SECRET, lw=1.8)

    # [mask_bytes(k)]
    _box(ax, 0.265, ROW1_Y, 0.18, 0.055, fc=C_PANEL, ec=C_BORDER, lw=1.4)
    _label(ax, 0.355, ROW1_Y + 0.032, "mask_bytes(k)", color=C_SHARE1, fontsize=9)
    ax.text(0.355, ROW1_Y + 0.010, "rand mask ← U(0,255)ⁿ", ha="center", va="center", **FONT_CODE)

    # XOR symbol
    ax.text(0.466, ROW1_Y + 0.0275, "⊕", ha="center", va="center",
            fontsize=16, color=C_XOR, fontweight="bold")

    # → Share 1
    _arrow(ax, 0.445, ROW1_Y + 0.0275, 0.48, ROW1_Y + 0.068, color=C_SHARE1, lw=1.6)
    _box(ax, 0.48, ROW1_Y + 0.055, 0.16, 0.048, fc=C_SHARE1 + "22", ec=C_SHARE1, lw=1.8)
    _label(ax, 0.56, ROW1_Y + 0.079, "Share 1  =  k ⊕ mask", color=C_SHARE1, fontsize=8.5)

    # → Share 2
    _arrow(ax, 0.445, ROW1_Y + 0.0275, 0.48, ROW1_Y - 0.010, color=C_SHARE2, lw=1.6)
    _box(ax, 0.48, ROW1_Y - 0.025, 0.16, 0.048, fc=C_SHARE2 + "22", ec=C_SHARE2, lw=1.8)
    _label(ax, 0.56, ROW1_Y - 0.001, "Share 2  =  mask", color=C_SHARE2, fontsize=8.5)

    # Recovery: share1 ⊕ share2 = k
    _box(ax, 0.66, ROW1_Y - 0.01, 0.27, 0.075, fc=C_PANEL, ec=C_BORDER, lw=1.2, alpha=0.85)
    ax.text(0.795, ROW1_Y + 0.047, "✔  Recovery guarantee:", ha="center",
            fontsize=8.5, color=C_ADAPT, fontweight="bold")
    ax.text(0.795, ROW1_Y + 0.027, "share₁ ⊕ share₂ = (k ⊕ mask) ⊕ mask = k",
            ha="center", fontsize=8, color=C_TEXT, family="monospace")
    ax.text(0.795, ROW1_Y + 0.006, "No individual share leaks k", ha="center",
            fontsize=8, color=C_SUBTEXT)

    # ══════════════════════════════════════════════════════════════════════════
    # ROW 2 — Leakage trace simulation
    # ══════════════════════════════════════════════════════════════════════════
    ROW2_TOP = 0.62

    ax.text(0.02, ROW2_TOP + 0.01, "② LEAKAGE SIMULATION  (simulate_trace)",
            fontsize=10, fontweight="bold", color=C_TRACE, va="center")

    # Unmasked trace (what an attacker would see without masking)
    inset_raw = fig.add_axes([0.04, 0.44, 0.19, 0.12], facecolor=C_PRIM_BG)
    inset_raw.plot(xs_n, raw_s, color=C_SECRET, lw=1.3, alpha=0.85)
    inset_raw.set_title("Unmasked trace\n(k, no defence)", fontsize=7, color=C_SECRET, pad=2)
    inset_raw.set_xticks([]); inset_raw.set_yticks([])
    for sp in inset_raw.spines.values(): sp.set_color(C_SECRET); sp.set_linewidth(0.8)

    # Trace share1
    inset_s1 = fig.add_axes([0.265, 0.44, 0.19, 0.12], facecolor=C_PRIM_BG)
    inset_s1.plot(xs_n, raw_s1, color=C_SHARE1, lw=1.3)
    inset_s1.set_title("HW trace — share₁\n(k ⊕ mask)", fontsize=7, color=C_SHARE1, pad=2)
    inset_s1.set_xticks([]); inset_s1.set_yticks([])
    for sp in inset_s1.spines.values(): sp.set_color(C_SHARE1); sp.set_linewidth(0.8)

    # Trace share2
    inset_s2 = fig.add_axes([0.48, 0.44, 0.19, 0.12], facecolor=C_PRIM_BG)
    inset_s2.plot(xs_n, raw_s2, color=C_SHARE2, lw=1.3)
    inset_s2.set_title("HW trace — share₂\n(mask)", fontsize=7, color=C_SHARE2, pad=2)
    inset_s2.set_xticks([]); inset_s2.set_yticks([])
    for sp in inset_s2.spines.values(): sp.set_color(C_SHARE2); sp.set_linewidth(0.8)

    # "+" label between s1 and s2 traces
    ax.text(0.465, 0.502, "+", ha="center", va="center", fontsize=22,
            color=C_TRACE, fontweight="bold")

    # Combined trace
    inset_comb = fig.add_axes([0.695, 0.44, 0.19, 0.12], facecolor=C_PRIM_BG)
    inset_comb.plot(xs_n, combined, color=C_TRACE, lw=1.3)
    inset_comb.set_title("Combined trace\n(share₁ + share₂)", fontsize=7, color=C_TRACE, pad=2)
    inset_comb.set_xticks([]); inset_comb.set_yticks([])
    for sp in inset_comb.spines.values(): sp.set_color(C_TRACE); sp.set_linewidth(0.8)

    ax.text(0.88, 0.502, "=", ha="center", va="center", fontsize=22,
            color=C_TRACE, fontweight="bold")

    # Equation under traces
    ax.text(0.5, 0.432,
            "trace(share₁) + trace(share₂)  =  combined trace  ←  attacker observes this  (NOT k directly)",
            ha="center", fontsize=8.5, color=C_SUBTEXT)

    # HW model callout
    _box(ax, 0.04, 0.387, 0.85, 0.038, fc=C_PANEL, ec=C_BORDER, lw=1, alpha=0.8)
    ax.text(0.465, 0.407,
            "Hamming-weight model:  trace[i] = HW(byte[i]) + N(0, σ²)   "
            "    Jitter:  trace = roll(trace, Δ),  Δ ~ U(0, 2)",
            ha="center", fontsize=8.5, color=C_TEXT, family="monospace")

    # ══════════════════════════════════════════════════════════════════════════
    # ROW 3 — Adaptive defence
    # ══════════════════════════════════════════════════════════════════════════
    ROW3_TOP = 0.36

    ax.text(0.02, ROW3_TOP + 0.01, "③ ADAPTIVE DEFENCE  (apply_defense)",
            fontsize=10, fontweight="bold", color=C_DEFENDED, va="center")

    modes = [
        ("none",     "No defence\n(baseline)",             C_SUBTEXT, "σ = 0,  Δ = 0"),
        ("masking",  "Masking mode\n(low noise)",          C_SHARE1,  "σ = 0.5,  Δ = 0"),
        ("noise",    "Noise injection\n(medium noise)",    C_TRACE,   "σ = 2.0,  Δ = 0"),
        ("adaptive", "Adaptive mode\n(noise + jitter)",   C_DEFENDED,"σ = 2.5,  Δ ~ U(1,4)"),
    ]

    bx = 0.04
    for i, (mode, label, color, params) in enumerate(modes):
        bw = 0.205
        _box(ax, bx, ROW3_TOP - 0.07, bw, 0.065, fc=color + "18", ec=color, lw=1.6)
        ax.text(bx + bw / 2, ROW3_TOP - 0.015, label,
                ha="center", va="center", fontsize=8.5, fontweight="bold", color=color)
        ax.text(bx + bw / 2, ROW3_TOP - 0.043, params,
                ha="center", va="center", fontsize=7.5, color=C_SUBTEXT, family="monospace")
        ax.text(bx + bw / 2, ROW3_TOP - 0.063, f'mode="{mode}"',
                ha="center", va="center", fontsize=7, color=color, family="monospace")
        bx += bw + 0.015

    # arrow from combined trace to defended
    ax.annotate("", xy=(0.39, ROW3_TOP + 0.01), xytext=(0.795, 0.44),
                arrowprops=dict(arrowstyle="->", color=C_DEFENDED, lw=1.5,
                                connectionstyle="arc3,rad=-0.25"), zorder=5)

    # Defended trace plot
    inset_def = fig.add_axes([0.695, 0.27, 0.19, 0.12], facecolor=C_PRIM_BG)
    inset_def.plot(xs_n, defended, color=C_DEFENDED, lw=1.3)
    inset_def.set_title("Defended trace\n(adaptive: σ=2.5 + jitter)", fontsize=7,
                         color=C_DEFENDED, pad=2)
    inset_def.set_xticks([]); inset_def.set_yticks([])
    for sp in inset_def.spines.values(): sp.set_color(C_DEFENDED); sp.set_linewidth(0.8)

    ax.annotate("", xy=(0.695 + 0.095, 0.27 + 0.06), xytext=(0.39 + 0.205, ROW3_TOP - 0.035),
                arrowprops=dict(arrowstyle="->", color=C_DEFENDED, lw=1.4,
                                connectionstyle="arc3,rad=0.25"), zorder=5)

    # ══════════════════════════════════════════════════════════════════════════
    # ROW 4 — Primitives that use the pipeline
    # ══════════════════════════════════════════════════════════════════════════
    ROW4_TOP = 0.205

    ax.text(0.02, ROW4_TOP + 0.01, "④ PROTECTED CRYPTOGRAPHIC PRIMITIVES",
            fontsize=10, fontweight="bold", color=C_CRYPTO, va="center")

    prims = [
        ("kyber_decap()\n(KEM Decapsulation)",    "kyber.py",  C_SECRET),
        ("kyber_encap()\n(KEM Encapsulation)",    "kyber.py",  C_SHARE1),
        ("ecdh_shared_secret\n_secp256k1()",      "ecdh.py",   C_SHARE2),
        ("ecdh_shared_secret\n_x25519()",         "ecdh.py",   C_ADAPT),
        ("aead_encrypt()\n(ChaCha20-Poly1305)",   "aead.py",   C_TRACE),
        ("aead_decrypt()\n(ChaCha20-Poly1305)",   "aead.py",   C_DEFENDED),
    ]

    bx = 0.04
    pw = 0.148
    gap = 0.012
    for fn, src, color in prims:
        _box(ax, bx, ROW4_TOP - 0.075, pw, 0.065, fc=color + "15", ec=color, lw=1.4)
        ax.text(bx + pw / 2, ROW4_TOP - 0.027, fn,
                ha="center", va="center", fontsize=7.5, fontweight="bold", color=color)
        ax.text(bx + pw / 2, ROW4_TOP - 0.063, src,
                ha="center", va="center", fontsize=7, color=C_SUBTEXT, family="monospace")
        # upward arrow to pipeline
        _arrow(ax, bx + pw / 2, ROW4_TOP - 0.0, bx + pw / 2, ROW3_TOP - 0.075,
               color=color, lw=1.1)
        bx += pw + gap

    # Label on arrows
    ax.text(0.5, ROW4_TOP + 0.025,
            "All primitives call  mask_bytes( secret ) → simulate_trace( share ) → apply_defense( trace )",
            ha="center", fontsize=8.5, color=C_SUBTEXT)

    # ══════════════════════════════════════════════════════════════════════════
    # Legend box
    # ══════════════════════════════════════════════════════════════════════════
    LX, LY = 0.04, 0.06
    _box(ax, LX, LY, 0.91, 0.10, fc=C_PANEL, ec=C_BORDER, lw=1)
    ax.text(LX + 0.455, LY + 0.095, "Security Guarantee",
            ha="center", va="top", fontsize=9, fontweight="bold", color=C_ADAPT)

    row1 = [
        (C_SECRET,   "Secret never processed as a whole — always split into shares"),
        (C_SHARE1,   "share₁ = k ⊕ mask  →  indistinguishable from random"),
        (C_SHARE2,   "share₂ = mask  →  uniform random, no correlation to k"),
    ]
    row2 = [
        (C_TRACE,    "Combined HW traces decorrelate k — attacker observes sum of two independent share traces"),
        (C_DEFENDED, "Adaptive mode: σ=2.5 Gaussian noise + random temporal jitter defeats DPA/CPA attacks"),
    ]

    tx = LX + 0.01
    for color, text in row1:
        ax.plot([tx + 0.01], [LY + 0.065], "o", color=color, markersize=7, zorder=5)
        ax.text(tx + 0.03, LY + 0.065, text, va="center", fontsize=8, color=C_TEXT)
        tx += 0.305

    tx = LX + 0.01
    for color, text in row2:
        ax.plot([tx + 0.01], [LY + 0.033], "o", color=color, markersize=7, zorder=5)
        ax.text(tx + 0.03, LY + 0.033, text, va="center", fontsize=8, color=C_TEXT)
        tx += 0.455

    # ── Footer ────────────────────────────────────────────────────────────────
    ax.text(0.5, 0.012,
            "pqbfl_project new adaptive side channel resistant  ·  "
            "leakage.py / kyber.py / ecdh.py / aead.py",
            ha="center", fontsize=7.5, color=C_SUBTEXT)

    plt.savefig(str(OUT_PATH), dpi=180, bbox_inches="tight", facecolor=C_BG)
    plt.close()
    print(f"✅ Diagram saved → {OUT_PATH}")


if __name__ == "__main__":
    draw()
