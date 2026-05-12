"""
saeed2024_pqc_iot — Implementation of
  "AI and post-quantum cryptography powered cybersecurity approaches for IoT systems"
  Saeed M.M. & Alqahtani F., PeerJ Computer Science, 2024.  cite{saeed2024}

Core contributions implemented:
  1. Side-channel timing leakage model for IoT cryptographic primitives
     — Demonstrates how non-constant-time operations leak key material
     — Compares VULNERABLE vs HARDENED (constant-time) implementations

  2. AI-based anomaly detection on timing traces
     — Feature extraction from timing observations (mean, std, skew, entropy)
     — Random-Forest classifier trained to distinguish benign vs attack traces
     — Achieves high detection accuracy even at low SNR

  3. PQC integration for IoT (ML-KEM + AES-GCM)
     — Post-quantum key encapsulation on resource-constrained IoT nodes
     — Side-channel hardened variant with randomised nonces + masking

Role in JOURNAL-3 (cite{saeed2024}):
  Primary reference for the claim that "implemented systems of FL in
  healthcare and remote IoT sensors leave execution footprints which can
  be mathematically exploited with given hardware side-channel domains",
  motivating PQBFL's constant-time HMAC comparison, CSPRNG nonces, and
  dynamic KDF salts.
"""
__version__ = "1.0.0"
__paper__   = "Saeed & Alqahtani (2024) PeerJ CS"
__cite__    = "saeed2024"
