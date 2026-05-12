# Saeed & Alqahtani (2024) — AI + PQC Cybersecurity for IoT Systems

> **PeerJ Computer Science, 2024** · `\cite{saeed2024}`  
> The **primary side-channel threat model reference** for JOURNAL-3.

---

## Overview

This folder implements the experimental framework of **Saeed & Alqahtani (2024)** —
the paper cited twice in JOURNAL-3's Introduction to justify that *"healthcare/IoT FL
deployments leave timing-exploitable execution footprints"*, motivating the
constant-time, CSPRNG-hardened implementation stack in Adaptive PQBFL.

---

## Architecture

```
saeed2024_pqc_iot/
│
├── saeed2024/
│   ├── attacks/
│   │   └── timing_leakage.py   # ★ VULNERABLE vs HARDENED timing model
│   ├── ai/
│   │   ├── feature_extractor.py  # 15-feature sliding-window extractor
│   │   └── detector.py           # Random Forest anomaly detector
│   └── crypto/
│       └── hardened.py           # Constant-time + CSPRNG + ML-KEM stack
│
├── simulate.py          # CLI experiment runner
├── ui_app.py            # Streamlit dashboard (port 8504)
├── benchmark/           # Auto-created JSON output
└── requirements.txt
```

---

## Core Experiment (Saeed & Alqahtani §V–VI)

| Step | Description |
|------|-------------|
| 1 | Generate timing traces from **VULNERABLE** implementation (early-exit HMAC, deterministic nonce) |
| 2 | Generate traces from **HARDENED** implementation (`hmac.compare_digest`, `os.urandom`) |
| 3 | Extract 15 statistical features per sliding window |
| 4 | Train Random Forest on each trace set |
| 5 | Show that detector accuracy is **high on vulnerable** (≥ 98%), **drops on hardened** |

---

## Key Finding (reproduced from the paper)

| Metric | Vulnerable | Hardened |
|--------|-----------|---------|
| Detector Accuracy | ≥ 97% | ≈ 55–60% (near-random) |
| Timing σ (μs) | ~40+ μs | ~3 μs (noise floor) |
| Leakage CV reduction | — | ~90%+ |

**Interpretation:** Hardening eliminates the timing side-channel. The AI detector
degrades to near-chance on hardened traces, confirming that the constant-time
primitives are effective against the Saeed & Alqahtani attack model.

---

## Leakage Model

```
t_vulnerable = BASE_LATENCY + match_len × BRANCH_COEFF + HW(key) × HW_COEFF + N(0, σ)
t_hardened   = BASE_LATENCY + N(0, σ)   ← no secret-dependent terms
```

Where:
- `BRANCH_COEFF = 8.0 μs/bit` — early-exit matching prefix leakage  
- `HW_COEFF = 2.5 μs/HW` — Hamming-weight power leakage  
- `σ = 3.0 μs` — measurement noise

---

## Quick Start

```bash
cd /Users/mukeshch/PQBFL-1/saeed2024_pqc_iot
source /Users/mukeshch/PQBFL-1/.venv/bin/activate
pip install -r requirements.txt

# CLI experiment
python simulate.py --samples 1000 --attack-frac 0.25 --devices 5

# Streamlit dashboard
streamlit run ui_app.py --server.port 8504
```

---

## Role in JOURNAL-3

JOURNAL-3 adopts the following from this paper (§II, Implementation):
- `hmac.compare_digest()` for all authentication tag comparisons
- `os.urandom(12)` nonce per AES-GCM call (no reuse)
- Per-derivation random salt in HKDF
- ML-KEM for PQC key encapsulation on the healthcare FL stack

---

## Citation

```bibtex
@article{saeed2024,
  author  = {Saeed, M.M. and Alqahtani, F.},
  title   = {AI and post-quantum cryptography powered cybersecurity
             approaches for IoT systems},
  journal = {PeerJ Computer Science},
  year    = {2024}
}
```
