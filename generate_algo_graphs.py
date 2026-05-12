"""
generate_algo_graphs.py
Generates visual comparisons for individual cryptographic algorithms.
Covers KEMs (ECDH, X25519, Kyber), Signatures (ECDSA, EdDSA, RSA, Dilithium),
and AEADs.
"""
import os, sys, warnings
warnings.filterwarnings("ignore")
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "algo_comparison_results")
os.makedirs(OUT, exist_ok=True)

# Colors
C = dict(bg="#FFFFFF", ax="#F5F7FA", grid="#D0D7E3", border="#9BA8BB",
         text="#1A1E2E", sub="#4A5568", blue="#1F6FEB", green="#0D9E6E",
         orange="#D04F00", red="#CC2222", purple="#7C3AED", teal="#0891B2")

plt.rcParams.update({
    "figure.facecolor": C["bg"], "axes.facecolor": C["ax"],
    "axes.edgecolor": C["border"], "axes.labelcolor": C["text"],
    "xtick.color": C["sub"], "ytick.color": C["sub"],
    "text.color": C["text"], "grid.color": C["grid"],
    "grid.linewidth": 0.8, "legend.facecolor": "#FFF",
    "legend.edgecolor": C["border"], "font.family": "DejaVu Sans",
    "axes.titlesize": 12, "axes.labelsize": 10,
})

# 1. KEM / Key Exchange Data
kem_labels = ["ECDH\n(P-256)", "X25519", "ML-KEM-512\n(Kyber512)", "ML-KEM-768\n(Kyber768)"]
kem_latency = [0.75, 0.45, 0.08, 0.12] # ms (approx execution time)
kem_pk_size = [64, 32, 800, 1184] # bytes
kem_ct_size = [64, 32, 768, 1088] # bytes
kem_class_sec = [128, 128, 128, 192] # classical security bits
kem_quant_sec = [0, 0, 128, 192] # quantum security bits (Shor's makes ECC 0)

# 2. Signature Data
sig_labels = ["RSA-3072", "ECDSA\n(P-256)", "EdDSA\n(Ed25519)", "ML-DSA-44\n(Dil2)", "ML-DSA-65\n(Dil3)"]
sig_latency_sign = [3.5, 0.6, 0.2, 0.15, 0.25] # ms
sig_latency_verify = [0.1, 0.8, 0.4, 0.05, 0.08] # ms
sig_pk_size = [384, 64, 32, 1312, 1952] # bytes
sig_sig_size = [384, 64, 64, 2420, 3293] # bytes
sig_quant_sec = [0, 0, 0, 128, 192] # quantum security bits

# 3. Time to Crack (Log10 Years) - Assuming 10^12 ops/sec classical, unknown quantum scale but effectively instant for vulnerable
# 128 bits = 3.4e38 ops -> ~1e19 years classical. 0 quantum.
years_class = [19, 19, 19, 29, 29] # ECDH, X25519, Kyber512, Kyber768, Dilithium3
years_quant = [0, 0, 19, 29, 29]

def plot_kem_latency_size():
    fig, ax1 = plt.subplots(figsize=(10, 6))
    x = np.arange(len(kem_labels))
    width = 0.35

    ax1.bar(x - width/2, kem_latency, width, color=C["blue"], label="Latency (ms)")
    ax1.set_ylabel("Latency (ms)", color=C["blue"])
    ax1.tick_params(axis="y", labelcolor=C["blue"])
    
    ax2 = ax1.twinx()
    ax2.bar(x + width/2, kem_pk_size, width, color=C["orange"], label="Public Key Size (Bytes)")
    ax2.set_ylabel("Size (Bytes)", color=C["orange"])
    ax2.tick_params(axis="y", labelcolor=C["orange"])

    ax1.set_xticks(x)
    ax1.set_xticklabels(kem_labels)
    ax1.set_title("KEM / Key Exchange: Latency vs Size")
    
    fig.legend(loc="upper left", bbox_to_anchor=(0.1, 0.9))
    plt.tight_layout()
    plt.savefig(os.path.join(OUT, "algo_kem_latency_size.png"), dpi=150)
    plt.close()

def plot_sig_latency_size():
    fig, ax1 = plt.subplots(figsize=(11, 6))
    x = np.arange(len(sig_labels))
    width = 0.25

    ax1.bar(x - width, sig_latency_sign, width, color=C["teal"], label="Sign Latency (ms)")
    ax1.bar(x, sig_latency_verify, width, color=C["blue"], label="Verify Latency (ms)")
    ax1.set_ylabel("Latency (ms)", color=C["text"])
    
    ax2 = ax1.twinx()
    ax2.bar(x + width, sig_sig_size, width, color=C["purple"], label="Signature Size (Bytes)")
    ax2.set_ylabel("Size (Bytes)", color=C["purple"])
    ax2.tick_params(axis="y", labelcolor=C["purple"])

    ax1.set_xticks(x)
    ax1.set_xticklabels(sig_labels)
    ax1.set_title("Digital Signatures: Latency vs Signature Size")
    
    fig.legend(loc="upper left", bbox_to_anchor=(0.1, 0.9))
    plt.tight_layout()
    plt.savefig(os.path.join(OUT, "algo_sig_latency_size.png"), dpi=150)
    plt.close()

def plot_security_levels():
    fig, ax = plt.subplots(figsize=(10, 6))
    labels = ["ECDH/ECDSA\n(Classical)", "X25519/Ed25519\n(Classical)", "Kyber512/Dil2\n(PQ Level 1)", "Kyber768/Dil3\n(PQ Level 3)"]
    class_sec = [128, 128, 128, 192]
    quant_sec = [0, 0, 128, 192]
    
    x = np.arange(len(labels))
    width = 0.35

    ax.bar(x - width/2, class_sec, width, color=C["blue"], label="Classical Security (Bits)")
    ax.bar(x + width/2, quant_sec, width, color=C["green"], label="Quantum Security (Bits)")

    ax.axhline(128, color="red", linestyle="--", alpha=0.5, label="Standard Minimum")

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Security Strength (Bits)")
    ax.set_title("Classical vs Quantum Security Levels")
    ax.legend(loc="upper left")

    plt.tight_layout()
    plt.savefig(os.path.join(OUT, "algo_security_levels.png"), dpi=150)
    plt.close()

def plot_time_to_crack():
    fig, ax = plt.subplots(figsize=(10, 6))
    labels = ["X25519\n(Classical)", "Ed25519\n(Classical)", "Kyber768\n(PQ Level 3)", "Dilithium3\n(PQ Level 3)"]
    years_class = [19, 19, 29, 29] # Log10 Years
    years_quant = [0, 0, 29, 29]
    
    x = np.arange(len(labels))
    width = 0.35

    ax.bar(x - width/2, years_class, width, color=C["orange"], label="Classical Supercomputer (Log10 Years)")
    ax.bar(x + width/2, years_quant, width, color=C["green"], label="CRQC (Quantum Computer) (Log10 Years)")

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Time to Crack (Log10 Years)")
    ax.set_title("Estimated Time to Crack (Logarithmic Scale)")
    ax.legend(loc="upper right")
    
    # Add annotations
    for i, v in enumerate(years_quant):
        if v == 0:
            ax.text(x[i] + width/2, v + 1, "Instant (Shor's)", ha='center', va='bottom', color='red', fontweight='bold', fontsize=9)
            
    plt.tight_layout()
    plt.savefig(os.path.join(OUT, "algo_time_to_crack.png"), dpi=150)
    plt.close()

if __name__ == "__main__":
    plot_kem_latency_size()
    plot_sig_latency_size()
    plot_security_levels()
    plot_time_to_crack()
    print("Generated all algorithm comparison graphs.")
