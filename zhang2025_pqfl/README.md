# Zhang et al. (2025) — Full-Stack Private Federated Deep Learning with Post-Quantum Security

> **IEEE Transactions on Dependable and Secure Computing, 2025**  
> Implementation of the static PQC-FL baseline cited in JOURNAL-3 (Adaptive PQBFL).

---

## Overview

This folder implements the **Zhang et al. (2025)** architecture — the state-of-the-art
full-stack privacy-preserving federated learning system with post-quantum security,
as cited in JOURNAL-3 (`\cite{zhang2025}`).

Its role in the JOURNAL-3 paper is as the **static overhead baseline**: it demonstrates
the **~40–50% communication overhead** imposed by fixed lattice (Kyber/ML-KEM) parameters
when L_j (the symmetric ratchet window) is a constant — the exact cost that
**Threat-Adaptive PQBFL** (JOURNAL-3) reduces by 76%.

---

## Architecture

```
zhang2025_pqfl/
│
├── zhang2025/                   # Core implementation package
│   ├── crypto/
│   │   ├── kem.py               # ML-KEM (Kyber-768) key encapsulation
│   │   ├── kdf.py               # HKDF-SHA-256 key derivation
│   │   ├── aead.py              # AES-256-GCM gradient encryption
│   │   └── ratchet.py           # Static symmetric ratchet (fixed L_j)
│   ├── fl/
│   │   ├── model.py             # Logistic regression model + local SGD
│   │   ├── data.py              # Synthetic federated dataset generator
│   │   ├── client.py            # FL client (KEM + train + encrypt)
│   │   └── server.py            # FL server (FedAvg + overhead accounting)
│   └── privacy/
│       └── dp.py                # Gaussian DP + Rényi budget accounting
│
├── simulate.py                  # CLI simulation runner
├── ui_app.py                    # Streamlit dashboard
├── benchmark/                   # Auto-created output JSON directory
└── requirements.txt
```

---

## Key Design Choices (vs Adaptive PQBFL)

| Property               | Zhang et al. (this impl)         | Adaptive PQBFL (JOURNAL-3)        |
|------------------------|----------------------------------|-----------------------------------|
| KEM algorithm          | ML-KEM / Kyber-768               | ML-KEM / Kyber-512                |
| Ratchet window L_j     | **Fixed constant** (e.g. 10)     | **Adaptive** (driven by threat t) |
| Threat monitoring      | ❌ None                           | ✅ ThreatMonitor + blockchain      |
| Blockchain anchor      | ❌ None                           | ✅ Smart contract                  |
| KEM overhead           | ~40–50% of total wire bytes      | ~10–15% (76% reduction)           |
| Side-channel hardening | ❌ None                           | ✅ Constant-time, CSPRNG nonces    |
| DP                     | ✅ Gaussian mechanism             | ❌ (Separate concern)              |

---

## Quick Start

### 1. Install dependencies

```bash
cd /Users/mukeshch/PQBFL-1/zhang2025_pqfl

# Use the existing PQBFL-1 venv, or create a new one:
python -m venv .venv && source .venv/bin/activate

pip install -r requirements.txt
```

> **Note on pqcrypto**: For real ML-KEM operations, `pqcrypto` requires
> Python 3.10–3.12. If unavailable, a toy KEM fallback is used automatically
> (size/timing simulated; not cryptographically secure).

### 2. Run CLI simulation

```bash
# Default: 30 rounds, 5 clients, L_j=10
python simulate.py

# Custom: 50 rounds, 10 clients, L_j=5, with Gaussian DP
python simulate.py --rounds 50 --clients 10 --lj 5 --dp-epsilon 1.0

# Non-IID data distribution
python simulate.py --non-iid --rounds 40 --clients 8
```

### 3. Launch Streamlit dashboard

```bash
streamlit run ui_app.py
```

---

## Overhead Model

With **Kyber-768** and a fixed L_j:

| Metric                        | Value         |
|-------------------------------|---------------|
| Public key size               | 1,184 bytes   |
| Ciphertext size               | 1,088 bytes   |
| Total KEM cost per client     | 2,272 bytes   |
| Amortised cost at L_j = 10   | **227 B/round** |
| Amortised cost at L_j = 2    | **1,136 B/round** |
| Gradient payload (46 features)| ~212 bytes    |
| **Overhead fraction (L_j=10)**| **~52%**      |

Compare: Classical ECDH = 64 bytes (32 B pk + 32 B shared point) → ~23% overhead.

---

## Citation

```bibtex
@article{zhang2025,
  author  = {Zhang, Y. and others},
  title   = {Efficient Full-Stack Private Federated Deep Learning
             With Post-Quantum Security},
  journal = {IEEE Transactions on Dependable and Secure Computing},
  year    = {2025}
}
```

Related: JOURNAL-3 (`/Users/mukeshch/PQBFL-1/JOURNAL-3/main.tex`), `\cite{zhang2025}`.
