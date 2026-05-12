# Kappala et al. (2026) — Dynamic Quantum-Resistant Selective Encryption for Agricultural Sensors

> **IEEE Access, 2026** · `\cite{kappala2026}`  
> Implementation of the **closest adaptive PQC precedent** to JOURNAL-3's Threat-Adaptive PQBFL.

---

## Overview

This folder implements **Kappala et al. (2026)** — the only prior work in the JOURNAL-3
literature comparison table tagged as both *Kyber (PQC)* **and** *Adaptive*, making it the
direct conceptual predecessor to the Threat-Adaptive PQBFL ratchet mechanism.

### What makes it adaptive (and why it's still not JOURNAL-3)

| Feature | Kappala et al. (this impl) | JOURNAL-3 Adaptive PQBFL |
|---------|---------------------------|--------------------------|
| Threat signal source | **Local node sensors** (replay, tamper, jitter) | **Blockchain telemetry** (hash mismatch, sig failures) |
| Threat computation | θ = tanh(Σ wᵢ · e^{−λΔt}) | Same formula, sourced on-chain |
| Adaptive output | **Per-packet encryption mode** (KYBER/AES/PLAIN) | **Ratchet window L_j** |
| Post-Compromise Security | ❌ No ratcheting | ✅ ML-KEM ratchet |
| Blockchain anchor | ❌ None | ✅ Smart contract |
| FL gradients | ❌ Raw sensor readings | ✅ Model gradient deltas |

---

## Architecture

```
kappala2026_dqrse/
│
├── kappala2026/
│   ├── crypto/
│   │   ├── kem.py          # ML-KEM (Kyber-512) — smaller variant for MCUs
│   │   ├── aead.py         # AES-256-GCM + energy cost model
│   │   └── kdf.py          # HKDF per-packet key derivation
│   ├── adaptive/
│   │   ├── threat_engine.py  # ★ ThreatEngine — exponential-decay θ scoring
│   │   └── policy.py         # ★ SelectiveEncryptionPolicy — (tier, θ) → mode
│   └── sensors/
│       ├── data.py           # Synthetic agricultural sensor data generator
│       ├── node.py           # IoT sensor node — per-packet adaptive encryption
│       └── gateway.py        # Field gateway — decryption + round aggregation
│
├── simulate.py             # CLI simulation runner
├── ui_app.py               # Streamlit dashboard (port 8503)
├── benchmark/              # Auto-created JSON output
└── requirements.txt
```

---

## Adaptive Policy Table (Kappala et al. Table III)

| Tier | θ < θ\_lo (benign) | θ\_lo ≤ θ < θ\_hi (elevated) | θ ≥ θ\_hi (attack) |
|------|-------------------|------------------------------|---------------------|
| **CRITICAL** (actuator, GPS, dosing) | AES\_ONLY | KYBER\_AES | KYBER\_AES |
| **SENSITIVE** (soil, NPK, moisture) | PLAINTEXT | AES\_ONLY | KYBER\_AES |
| **NORMAL** (ambient weather, wind) | PLAINTEXT | PLAINTEXT | AES\_ONLY |

---

## Quick Start

```bash
cd /Users/mukeshch/PQBFL-1/kappala2026_dqrse

# Use existing PQBFL-1 venv
source /Users/mukeshch/PQBFL-1/.venv/bin/activate

pip install -r requirements.txt

# CLI simulation — attack scenario (default)
python simulate.py

# CLI — benign only (no events injected)
python simulate.py --benign --rounds 30 --sensors 8

# Streamlit dashboard
streamlit run ui_app.py --server.port 8503
```

---

## Energy Model

On ARM Cortex-M4 @ 168 MHz (Kappala et al. Table IV):

| Mode | Energy / packet | Latency |
|------|----------------|---------|
| KYBER\_AES | ~2,154 μJ (KEM encap dominant) | ~4.2 ms |
| AES\_ONLY | ~3.84 μJ (payload × 0.12 μJ/B) | ~0.38 ms |
| PLAINTEXT | ~0.05 μJ (baseline) | ~0.05 ms |

**Energy saving vs always-KYBER baseline: 60–85%** depending on θ distribution.

---

## Citation

```bibtex
@article{kappala2026,
  author  = {Kappala, A. and others},
  title   = {A Dynamic Quantum-Resistant Selective Encryption Approach
             for Agricultural Sensors},
  journal = {IEEE Access},
  year    = {2026}
}
```

Related: JOURNAL-3 (`/Users/mukeshch/PQBFL-1/JOURNAL-3/main.tex`), `\cite{kappala2026}`.
