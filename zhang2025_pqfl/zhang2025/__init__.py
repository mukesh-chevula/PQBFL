"""
zhang2025_pqfl — Implementation of
  "Efficient Full-Stack Private Federated Deep Learning With Post-Quantum Security"
  Zhang et al., IEEE Transactions on Dependable and Secure Computing, 2025.

Architecture:
  • Static ML-KEM (Kyber-512/768) for per-session key encapsulation
  • Fixed symmetric ratchet threshold Lj (no adaptive modulation)
  • AES-256-GCM for gradient encryption
  • FedAvg aggregation with optional Gaussian differential-privacy noise
  • No blockchain component
"""
__version__ = "1.0.0"
__paper__   = "Zhang et al. IEEE TDSC 2025"
