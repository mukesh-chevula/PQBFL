"""
kappala2026_dqrse — Implementation of
  "A Dynamic Quantum-Resistant Selective Encryption Approach for Agricultural Sensors"
  Kappala et al., IEEE Access, 2026.   cite{kappala2026}

Core design principle:
  • IoT sensor nodes classify outgoing packets into sensitivity TIERS
    (CRITICAL / SENSITIVE / NORMAL) based on payload content.
  • A live ThreatEngine computes a normalized threat score θ ∈ [0,1].
  • A SelectiveEncryptionPolicy maps (tier, θ) → EncryptionMode:
      KYBER_AES  — full ML-KEM session + AES-256-GCM  (max security)
      AES_ONLY   — symmetric AES-256-GCM with pre-shared key (medium)
      PLAINTEXT  — no encryption (low-sensitivity / benign baseline)
  • This dynamic selection reduces energy/compute on resource-constrained
    agricultural sensor hardware while maintaining quantum resistance for
    critical readings.

Relation to PQBFL / JOURNAL-3:
  This is the closest prior work to Threat-Adaptive PQBFL but WITHOUT:
    • Blockchain anchoring / on-chain verification
    • Federated learning gradient aggregation
    • Post-Compromise Security via ratcheting
  Those three additions are JOURNAL-3's novelty claim.
"""
__version__ = "1.0.0"
__paper__   = "Kappala et al. IEEE Access 2026"
__cite__    = "kappala2026"
