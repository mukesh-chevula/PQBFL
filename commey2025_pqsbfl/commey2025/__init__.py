"""
commey2025_pqsbfl — Implementation of
  "PQS-BFL: A Post-Quantum Secure Blockchain-based Federated Learning Framework"
  Commey et al., arXiv:2505.01866, 2025.   cite{commey2025}

Core design:
  • ML-DSA (Dilithium-65) — post-quantum DIGITAL SIGNATURES on every
    gradient update; the aggregation server and each client holds a
    long-lived signing keypair that NEVER rotates.
  • ML-KEM — session key establishment between client and server.
  • Simulated Blockchain — gradient hashes and ML-DSA signatures are
    committed to a lightweight PoA chain before FedAvg aggregation.
  • Smart Contract — on-chain verifier that checks ML-DSA signatures
    and rejects unsigned / mis-signed gradients.
  • FedAvg — standard aggregation over MNIST-style healthcare data.

The PAPER GAP (defines JOURNAL-3 novelty):
  ✗ No ratcheting — signing key is static for the entire experiment;
    a key compromise at round R exposes ALL past and future gradients.
  ✗ No adaptive key management — no ThreatMonitor, no θ signal,
    no L_j modulation.  Re-keying requires manual intervention.
  ✗ No Post-Compromise Security — past-round signatures remain valid
    under the same long-lived key.

Compared to JOURNAL-3's Adaptive PQBFL:
  JOURNAL-3 adds ML-KEM ratcheting (PCS) + on-chain threat signal
  to close all three gaps.
"""
__version__ = "1.0.0"
__paper__   = "Commey et al. arXiv:2505.01866 (2025)"
__cite__    = "commey2025"
