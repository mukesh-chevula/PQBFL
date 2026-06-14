# PQBFL — Algorithm & Framework Usage Map
**Project:** `pqbfl_project new adaptive side channel resistant`  
All paths below are relative to that project root.

---

## Table of Contents
1. [Post-Quantum Cryptography](#1-post-quantum-cryptography)
2. [Classical Cryptography](#2-classical-cryptography)
3. [Key Derivation Functions](#3-key-derivation-functions)
4. [Side-Channel Resistance](#4-side-channel-resistance)
5. [Ratcheting — Symmetric](#5-ratcheting--symmetric-kdf_s)
6. [Ratcheting — Asymmetric (Adaptive)](#6-ratcheting--asymmetric-adaptive)
7. [Threat Monitor](#7-threat-monitor)
8. [Blockchain — Smart Contract](#8-blockchain--smart-contract-pqbflsol)
9. [Blockchain — Web3 / Contract Client](#9-blockchain--web3--contract-client)
10. [Blockchain — HD Wallet / Accounts](#10-blockchain--hd-wallet--accounts)
11. [Blockchain — Ethereum Message Signing](#11-blockchain--ethereum-message-signing)
12. [Federated Learning — Model](#12-federated-learning--model)
13. [Federated Learning — Aggregators](#13-federated-learning--aggregators)
14. [Federated Learning — Dataset](#14-federated-learning--dataset)
15. [Frameworks & Dependencies](#15-frameworks--dependencies)
16. [Infrastructure / DevOps](#16-infrastructure--devops)

---

## 1. Post-Quantum Cryptography

### 1.1 Kyber512 / ML-KEM-512 (Post-Quantum KEM)

**Definition file:** `python/pqbfl/crypto/kyber.py`

| Line(s) | What happens |
|---------|-------------|
| 14–15 | `from pqcrypto.kem import ml_kem_512` — preferred modern backend |
| 21–22 | `from pqcrypto.kem import kyber512` — older pqcrypto fallback |
| 26–31 | Toy KEM fallback warning when neither wheel is available |
| 37–41 | `KyberKeypair` frozen dataclass (`public_key`, `secret_key`) |
| 44–51 | `kyber_keygen()` — calls `_kem.generate_keypair()` or toy fallback |
| 53–57 | `KyberEncapResult` frozen dataclass (`ciphertext`, `shared_secret`) |
| 60–77 | `kyber_encap(public_key)` — SC-protected: simulate trace on pk → apply_defense → `_kem.encrypt(pk)` |
| 79–101 | `kyber_decap(ciphertext, secret_key)` — SC-protected: **mask_bytes(sk)** → simulate traces on both shares → combine → apply_defense → `_kem.decrypt(sk, ct)` |
| 104–110 | `_toy_public_from_secret()` / `_toy_shared_secret()` — toy fallback using SHA-256 |
| 112–113 | `get_kem_backend_name()` — returns which backend is active |

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/protocol.py` | 11 | Import: `KyberEncapResult, KyberKeypair, kyber_decap, kyber_encap, kyber_keygen` |
| `python/pqbfl/protocol.py` | 35 | `ServerKeys.kem: KyberKeypair` — server holds KEM keypair |
| `python/pqbfl/protocol.py` | 48 | `kyber_keygen()` inside `server_generate_keys()` |
| `python/pqbfl/protocol.py` | 70 | `kyber_encap(kpk_b)` inside `client_process_server_pubkeys()` — client encapsulates to server |
| `python/pqbfl/protocol.py` | 92 | `kyber_decap(ct, server.kem.secret_key)` inside `server_finish_session()` — server decapsulates |
| `python/pqbfl/scripts/demo_end_to_end.py` | 241 | `server_generate_keys()` — triggers `kyber_keygen()` for server |
| `python/pqbfl/scripts/demo_end_to_end.py` | 319–329 | `client_process_server_pubkeys(...)` — triggers `kyber_encap()` per client |
| `python/pqbfl/scripts/demo_end_to_end.py` | 337–343 | `server_finish_session(...)` — triggers `kyber_decap()` per client |

---

## 2. Classical Cryptography

### 2.1 X25519 (ECDH — Curve25519)

**Definition file:** `python/pqbfl/crypto/ecdh.py`

| Line(s) | What happens |
|---------|-------------|
| 6 | `from cryptography.hazmat.primitives.asymmetric import ec, x25519` |
| 20–23 | `X25519Keypair` frozen dataclass (`private_key`, `public_key_bytes`) |
| 55–63 | `ecdh_keygen_x25519()` — `X25519PrivateKey.generate()` |
| 65–82 | `ecdh_shared_secret_x25519(private_key, peer_pk)` — SC-protected: **mask_bytes(priv_bytes)** → simulate_trace on both shares → combine → apply_defense → `private_key.exchange(peer_pub)` |

> Also implemented (unused in main flow): `ecdh_keygen_secp256k1()` (L24–32) and `ecdh_shared_secret_secp256k1()` (L34–53) for secp256k1.

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/protocol.py` | 7 | Import: `X25519Keypair, ecdh_keygen_x25519, ecdh_shared_secret_x25519` |
| `python/pqbfl/protocol.py` | 36 | `ServerKeys.ecdh: X25519Keypair` |
| `python/pqbfl/protocol.py` | 41 | `ClientKeys.ecdh: X25519Keypair` |
| `python/pqbfl/protocol.py` | 50 | `ecdh_keygen_x25519()` in `server_generate_keys()` |
| `python/pqbfl/protocol.py` | 51 | `ecdh_keygen_x25519()` in `client_generate_keys()` |
| `python/pqbfl/protocol.py` | 69 | `ecdh_shared_secret_x25519(client.ecdh.private_key, epk_b)` in `client_process_server_pubkeys()` → derives `ss_e` |
| `python/pqbfl/protocol.py` | 88 | `ecdh_shared_secret_x25519(server.ecdh.private_key, epk_a)` in `server_finish_session()` → derives `ss_e` |
| `python/pqbfl/protocol.py` | 96 | `ecdh_shared_secret_x25519(client.ecdh.private_key, epk_b)` in `client_finish_session()` → derives `ss_e` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 241 | `server_generate_keys()` → triggers `ecdh_keygen_x25519()` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 268 | `client_generate_keys()` → triggers `ecdh_keygen_x25519()` per client |

---

### 2.2 Ed25519 (Digital Signatures)

**Definition file:** `python/pqbfl/crypto/eddsa.py`

| Line(s) | What happens |
|---------|-------------|
| 6 | `from cryptography.hazmat.primitives.asymmetric import ed25519` |
| 12–15 | `Ed25519Keypair` frozen dataclass (`private_key`, `public_key_bytes`) |
| 18–26 | `ed25519_keygen()` — `Ed25519PrivateKey.generate()` |
| 28–45 | `ed25519_sign(private_key, message)` — SC-protected: **mask_bytes(priv_bytes)** → simulate_trace on both shares → combine → apply_defense → `private_key.sign(message)` |
| 47–53 | `ed25519_verify(public_key_bytes, message, signature)` — `pub.verify(sig, msg)` with exception-safe bool return |

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/protocol.py` | 8 | Import: `Ed25519Keypair, ed25519_keygen, ed25519_sign, ed25519_verify` |
| `python/pqbfl/protocol.py` | 34 | `ServerKeys.sig: Ed25519Keypair` |
| `python/pqbfl/protocol.py` | 40 | `ClientKeys.sig: Ed25519Keypair` |
| `python/pqbfl/protocol.py` | 47 | `ed25519_keygen()` in `server_generate_keys()` (sig keypair) |
| `python/pqbfl/protocol.py` | 52 | `ed25519_keygen()` in `client_generate_keys()` (sig keypair) |
| `python/pqbfl/protocol.py` | 57 | `ed25519_sign(server.sig.private_key, msg_bytes)` in `server_send_pubkeys()` — signs {kpk_b, epk_b, tx_r} |
| `python/pqbfl/protocol.py` | 62 | `ed25519_verify(server_sig_pk, msg_bytes, signed.signature)` in `client_process_server_pubkeys()` |
| `python/pqbfl/protocol.py` | 78 | `ed25519_sign(client.sig.private_key, msg_bytes)` in `client_send_epk_and_ct()` — signs {epk_a, ct, tx_r} |
| `python/pqbfl/protocol.py` | 80 | `ed25519_verify(client_sig_pk, msg_bytes, signed.signature)` in `server_finish_session()` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 28 | Import: `ed25519_verify` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 413 | `sig = server_keys.sig.private_key.sign(ct)` — direct Ed25519 sign on round ciphertext |
| `python/pqbfl/scripts/demo_end_to_end.py` | 414 | `ed25519_verify(server_keys.sig.public_key_bytes, ct, sig)` — verify server's round signature |
| `python/pqbfl/scripts/demo_end_to_end.py` | 447 | `sig_u = client_keys.sig.private_key.sign(ct_u)` — client signs update ciphertext |
| `python/pqbfl/scripts/demo_end_to_end.py` | 448 | `ed25519_verify(client_keys.sig.public_key_bytes, ct_u, sig_u)` — server verifies client sig |

---

### 2.3 ChaCha20-Poly1305 (AEAD Encryption)

**Definition file:** `python/pqbfl/crypto/aead.py`

| Line(s) | What happens |
|---------|-------------|
| 3 | `from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305` |
| 8–15 | `nonce_for_round(round_num, label)` — deterministic 12-byte nonce: `hash32("pqbfl:{label}:{round}")[:12]` |
| 17–34 | `aead_encrypt(key32, plaintext, aad, nonce)` — SC-protected: **mask_bytes(key32)** → simulate_trace on shares → apply_defense → `ChaCha20Poly1305(key).encrypt(nonce, pt, aad)` |
| 36–52 | `aead_decrypt(key32, ciphertext, aad, nonce)` — SC-protected: same masking pattern → `ChaCha20Poly1305(key).decrypt(nonce, ct, aad)` |

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/protocol.py` | 3 | Import: `aead_decrypt, aead_encrypt, nonce_for_round` |
| `python/pqbfl/protocol.py` | 145–150 | `encrypt_round_message(model_key, round_num, direction, payload)` — AAD = `"pqbfl:{direction}:{round_num}"`, calls `aead_encrypt` |
| `python/pqbfl/protocol.py` | 152–159 | `decrypt_round_message(model_key, round_num, direction, ciphertext)` — calls `aead_decrypt` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 395 | `ct = encrypt_round_message(model_key, round_num=r, direction="S->C", payload=...)` — server encrypts model |
| `python/pqbfl/scripts/demo_end_to_end.py` | 418 | `msg = decrypt_round_message(client_model_key, round_num=r, direction="S->C", ...)` — client decrypts model |
| `python/pqbfl/scripts/demo_end_to_end.py` | 440 | `ct_u = encrypt_round_message(client_model_key, round_num=r, direction="C->S", payload=...)` — client encrypts update |
| `python/pqbfl/scripts/demo_end_to_end.py` | 455 | `decrypt_round_message(model_key, round_num=r, direction="C->S", ciphertext=ct_u)` — server decrypts update |

---

## 3. Key Derivation Functions

### 3.1 HKDF (HMAC-based Extract-and-Expand)

**Definition file:** `python/pqbfl/crypto/kdf.py`

| Line(s) | What happens |
|---------|-------------|
| 6–48 | `_kdf_hashmod()` — returns BLAKE3 hash class (preferred) or `hashlib.sha256` fallback |
| 53–55 | `hkdf_extract(salt, ikm)` — `HMAC(salt, ikm)` using chosen hash |
| 57–75 | `hkdf_expand(prk, info, length)` — HMAC-based T(1)‖T(2)‖… expansion |
| 77–87 | `kdf_a_root_key(ss_k, ss_e)` — **Asymmetric ratchet KDF_A**: `HKDF(ss_k) → HKDF(ss_e) → expand("pqbfl:RK")` → 32-byte root key RK_j |

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/protocol.py` | 11 | Import: `kdf_a_root_key` |
| `python/pqbfl/protocol.py` | 70 | `kdf_a_root_key(encap.shared_secret, ss_e)` in `client_process_server_pubkeys()` — pre-compute to verify |
| `python/pqbfl/protocol.py` | 90–91 | `kdf_a_root_key(ss_k, ss_e)` in `server_finish_session()` — derives RK on server side |
| `python/pqbfl/protocol.py` | 97 | `kdf_a_root_key(encap.shared_secret, ss_e)` in `client_finish_session()` — derives RK on client side |

---

### 3.2 BLAKE3-256 / SHA-256 (Protocol Hashing)

**Definition file:** `python/pqbfl/utils.py`

| Line(s) | What happens |
|---------|-------------|
| 3 | `import hashlib` |
| 10–16 | `blake3_256(data)` — tries `from blake3 import blake3`, falls back to `hashlib.sha256` |
| 19–21 | `hash32(data)` — protocol-wide 32-byte hash used everywhere |
| 24–26 | `sha256(data)` — direct SHA-256 |
| 28–33 | `sha256_hex()`, `sha256_bytes32()`, `to_bytes32_hex()` — Ethereum bytes32 helpers |

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/crypto/aead.py` | 7 | Import `hash32` — used in `nonce_for_round()` |
| `python/pqbfl/protocol.py` | 12 | Import `hash32` |
| `python/pqbfl/protocol.py` | 47 | `hash32(kpk_b + epk_b)` — `h_server_pubkeys()` |
| `python/pqbfl/protocol.py` | 65 | `hash32(kpk_b + epk_b)` — verify h_pks in `client_process_server_pubkeys()` |
| `python/pqbfl/protocol.py` | 85 | `hash32(epk_a)` — verify h_epk_a in `server_finish_session()` |
| `python/pqbfl/crypto/kyber.py` | 104–110 | `sha256(...)` — toy KEM fallback pseudo-random derivation |
| `python/pqbfl/scripts/demo_end_to_end.py` | 40 | Import `hash32` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 247 | `h_pks = hash32(server_keys.kem.public_key + server_keys.ecdh.public_key_bytes)` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 248 | `h_m0 = hash32(global_model.to_bytes())` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 367 | `h_inf_b = hash32(json_dumps_canonical(inf_b).encode())` — task hash |
| `python/pqbfl/scripts/demo_end_to_end.py` | 431 | `h_inf_a = hash32(json_dumps_canonical(inf_a).encode())` — update hash |

---

## 4. Side-Channel Resistance

### 4.1 Boolean Masking (`mask_bytes`)

**Definition file:** `python/pqbfl/crypto/leakage.py`

| Line(s) | What happens |
|---------|-------------|
| 3–5 | `_hw(x)` — Hamming weight of an integer (`bin(x).count("1")`) |
| 7–14 | `simulate_trace(data, noise_std, jitter)` — HW-based leakage model: `trace[i] = HW(byte[i]) + N(0, σ²)`, then `np.roll(trace, rand_shift)` if jitter=True |
| 17–22 | `mask_bytes(data)` — **Boolean masking**: generates random mask `m ~ U[0,255]ⁿ`, `share1 = data ⊕ m`, `share2 = m` → no individual share leaks the secret |
| 24–26 | `combine_shares(s1, s2)` — reconstructs secret: `s1 ⊕ s2` |
| 28–37 | `apply_defense(trace, mode)` — `"masking"`: +N(0,0.5²); `"noise"`: +N(0,2.0²); `"adaptive"`: +N(0,2.5²) + np.roll jitter |

**Applied in (every crypto primitive):**

| File | Line(s) | Secret protected | Defense applied |
|------|---------|-----------------|-----------------|
| `python/pqbfl/crypto/kyber.py` | 8 | imports all three |  |
| `python/pqbfl/crypto/kyber.py` | 62–66 | `public_key` during encap | simulate_trace + apply_defense |
| `python/pqbfl/crypto/kyber.py` | 81–91 | `secret_key` during decap | mask_bytes → simulate both shares → apply_defense |
| `python/pqbfl/crypto/ecdh.py` | 9 | imports all three |  |
| `python/pqbfl/crypto/ecdh.py` | 40–45 | SECP256K1 `priv_bytes` | mask_bytes → simulate → apply_defense |
| `python/pqbfl/crypto/ecdh.py` | 70–77 | X25519 `priv_bytes` | mask_bytes → simulate → apply_defense |
| `python/pqbfl/crypto/eddsa.py` | 10 | imports all three |  |
| `python/pqbfl/crypto/eddsa.py` | 33–40 | Ed25519 `priv_bytes` during sign | mask_bytes → simulate → apply_defense |
| `python/pqbfl/crypto/aead.py` | 5 | imports all three |  |
| `python/pqbfl/crypto/aead.py` | 21–26 | AEAD `key32` during encrypt | mask_bytes → simulate → apply_defense |
| `python/pqbfl/crypto/aead.py` | 39–44 | AEAD `key32` during decrypt | mask_bytes → simulate → apply_defense |

---

## 5. Ratcheting — Symmetric (KDF_S)

**Definition file:** `python/pqbfl/crypto/kdf.py`

| Line(s) | What happens |
|---------|-------------|
| 89–92 | `SymmetricRatchetState` dataclass (`chain_key: bytes`, `index: int`) |
| 94–112 | `kdf_s_next(state)` — derives next CK and model key: `CK_{i+1} = HMAC(CK_i, "pqbfl:CK")`, `MK_i = HMAC(CK_i, "pqbfl:MK")` |
| 114–116 | `chain_key_from_root(root_key)` — seeds first chain key: `CK_0 = HMAC(RK, "pqbfl:CK0")` |

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/protocol.py` | 11 | Import: `SymmetricRatchetState, chain_key_from_root, kdf_s_next` |
| `python/pqbfl/protocol.py` | 43–54 | `SessionState` holds `ratchet: SymmetricRatchetState`, `j` (epoch), `i` (step), `L_j`, `adaptive_L_j` |
| `python/pqbfl/protocol.py` | 100–105 | `session_from_root(root_key, L_j)` — calls `chain_key_from_root(root_key)` |
| `python/pqbfl/protocol.py` | 120–124 | `next_model_key(state)` — calls `kdf_s_next(state.ratchet)`, increments `state.i` |
| `python/pqbfl/protocol.py` | 126–131 | `should_asymmetric_ratchet(state)` — returns `state.i >= get_effective_L_j(state)` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 350–355 | `session_from_root(rk_server, L_j=initial_L_j)` per client after key exchange |
| `python/pqbfl/scripts/demo_end_to_end.py` | 388–391 | `server_state, model_key = next_model_key(server_state)` — per round per client |
| `python/pqbfl/scripts/demo_end_to_end.py` | 404–407 | `client_state, client_model_key = next_model_key(client_state)` — then asserts equality |

---

## 6. Ratcheting — Asymmetric (Adaptive)

**Definition file:** `python/pqbfl/adaptive/adaptive_ratchet.py`

| Line(s) | What happens |
|---------|-------------|
| 30–36 | `RatchetAdjustment` frozen dataclass — audit log entry (`timestamp, round_num, old_L_j, new_L_j, threat_level, reason`) |
| 38–65 | `AdaptiveRatchetPolicy` dataclass — parameters: `L_min`, `L_max`, `L_default`, `cooldown_rounds`, `alpha`, `beta`, `gamma`, `N`, `C_kem`, `E_kem` |
| 75–89 | `compute_L_j(threat_level)` — **joint optimization**: `L_j* = sqrt( N*(beta*C_kem + gamma*E_kem) / (alpha * Theta_epsilon(t)) )` bounded to `[L_min, L_max]` |
| 91–129 | `evaluate(threat_level, round_num)` — cooldown-gated: only updates `_current_L_j` if `|round - last_change| ≥ cooldown_rounds`; appends to `_adjustments` log |
| 131–160 | `should_ratchet(i, L_j, threat_level)` — uses `min(current_L_j, compute_L_j(threat))` for conservative threshold |

**Protocol glue in:** `python/pqbfl/protocol.py`

| Line(s) | What happens |
|---------|-------------|
| 43–54 | `SessionState.adaptive_L_j: Optional[int]` — hot-override field |
| 107–113 | `update_L_j(state, new_L_j)` — sets `state.adaptive_L_j = max(1, new_L_j)` without re-keying |
| 115–118 | `get_effective_L_j(state)` — returns `adaptive_L_j` if set, else `L_j` |
| 126–131 | `should_asymmetric_ratchet(state)` — `state.i >= get_effective_L_j(state)` |

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/scripts/demo_end_to_end.py` | 19 | Import: `AdaptiveRatchetPolicy` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 67–73 | `DemoConfig` fields: `adaptive_enabled, L_min, L_max, L_default, sensitivity` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 191–196 | `policy = AdaptiveRatchetPolicy(L_min=..., L_max=..., L_default=..., sensitivity=...)` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 348 | `_inject_simulated_threats(monitor, r, rounds)` — injects synthetic events at rounds 3, 4, mid |
| `python/pqbfl/scripts/demo_end_to_end.py` | 352 | `current_L_j = policy.evaluate(threat_level, round_num=r, reason=...)` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 354–356 | `update_L_j(server_sessions[addr]["state"], current_L_j)` & same for client sessions |
| `python/pqbfl/scripts/demo_end_to_end.py` | 360–362 | `get_effective_L_j(state)` — stale-ratchet detection before publish_task |

---

## 7. Threat Monitor

**Definition file:** `python/pqbfl/adaptive/threat_monitor.py`

| Line(s) | What happens |
|---------|-------------|
| 27–34 | `ThreatEventType` str-Enum: `SIG_VERIFICATION_FAILED`, `HASH_MISMATCH`, `REPUTATION_DROP`, `TIMING_ANOMALY`, `STALE_RATCHET` |
| 36–41 | `_DEFAULT_WEIGHTS` — per-type multipliers: SIG_FAIL=1.0, HASH=0.9, REPUTATION=0.6, TIMING=0.4, STALE=0.3 |
| 43–52 | `ThreatEvent` frozen dataclass (`event_type, severity, timestamp, round_num, detail`) |
| 54–80 | `ThreatMonitor` dataclass — `window_seconds=300`, `decay_half_life=120`, per-type weights |
| 84–125 | `record_event(type, severity, round_num, detail)` — appends `ThreatEvent` to `_events` |
| 128–160 | `get_threat_level()` — **exponential decay weighted average**: `threat = Σ(decay × w × severity) / Σ(decay × w)` where `decay = 2^(-age/half_life)` |
| 162–170 | `get_recent_events(limit)` — sliding-window event list |
| 172–185 | `get_event_log()` — serialisable dict list for UI/JSON |

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/scripts/demo_end_to_end.py` | 20 | Import: `ThreatEventType, ThreatMonitor` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 135–148 | `_inject_simulated_threats()` — round 3: `SIG_FAIL` sev=0.95; round 4: `TIMING_ANOMALY` sev=0.7; round mid: `REPUTATION_DROP` sev=0.5 |
| `python/pqbfl/scripts/demo_end_to_end.py` | 191 | `monitor = ThreatMonitor()` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 350 | `threat_level = monitor.get_threat_level()` — queried each round |
| `python/pqbfl/scripts/demo_end_to_end.py` | 362 | `monitor.record_event(ThreatEventType.STALE_RATCHET, severity=0.3, ...)` — when `i >= effective_L_j` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 415 | `monitor.record_event(ThreatEventType.SIG_VERIFICATION_FAILED, severity=1.0, ...)` — server sig failure |
| `python/pqbfl/scripts/demo_end_to_end.py` | 448 | `monitor.record_event(ThreatEventType.SIG_VERIFICATION_FAILED, severity=1.0, ...)` — client sig failure |

---

## 8. Blockchain — Smart Contract (PQBFL.sol)

**Definition file:** `chain/contracts/PQBFL.sol`

| Line(s) | What / Algorithm |
|---------|-----------------|
| 1 | `pragma solidity ^0.8.20` |
| 5 | `MIN_DEPOSIT_WEI = 0.01 ether` — economic security parameter |
| 7–18 | `Project` struct: `id, server, nClients, clientCount, hInitialModel (bytes32), hServerKeys (bytes32), done, createdAt` |
| 20–29 | `Client` struct: `addr, projectId, hEpk (bytes32), score, registeredAt` |
| 31–43 | `Task` struct: `round, taskId, projectId, server, hInf (bytes32), hPks (bytes32), deadline` |
| 45–55 | `Update` struct: `round, taskId, projectId, client, hInf (bytes32), hCtEpk (bytes32), submittedAt` |
| 57–69 | `Feedback` struct: `round, taskId, projectId, client, hUpdateInf, hPks, scoreDelta (int256), terminate, time` |
| 71–77 | Events: `RegClient, RegProject, TaskEvent, UpdateEvent, FeedbackEvent, ProjectTerminate` |
| 78–82 | `onlyServer(projectId)` modifier — access control |
| 84–101 | `registerProject(id_p, nClients, h_M0, h_pks)` payable — requires ≥ MIN_DEPOSIT |
| 103–122 | `registerClient(h_epk, id_p)` — stores `h_epk` on-chain for session binding |
| 124–143 | `publishTask(r, h_Inf_b, h_pks_r, id_t, id_p, D_t)` — commits task hash + server key hash |
| 145–165 | `updateModel(r, h_Inf_a, h_ct_epk, id_t, id_p)` — commits model update hash |
| 167–200+ | `feedbackModel(r, id_t, id_p, cAddr, h_Inf_a, h_pks_r, sc, T)` — updates client score, emits feedback/terminate |

**Compiled and deployed by:**

| File | Line(s) | What |
|------|---------|------|
| `chain/hardhat.config.js` | 1–14 | Hardhat config: Solidity 0.8.20, optimizer runs=200, localhost:8545 |
| `chain/scripts/deploy.js` | 1–11 | `ethers.getContractFactory("PQBFL")` → deploy → log address |

---

## 9. Blockchain — Web3 / Contract Client

**Definition file:** `python/pqbfl/chain/contract_client.py`

| Line(s) | What happens |
|---------|-------------|
| 8 | `from web3 import Web3` |
| 11–13 | `PQBFLArtifact` dataclass (`abi`, `bytecode`) |
| 15–26 | `load_hardhat_artifact(chain_dir)` — reads `artifacts/contracts/PQBFL.sol/PQBFL.json` |
| 29–44 | `PQBFLContractClient` class — wraps `w3.eth.contract` |
| 36–42 | `deploy_from_artifact(w3, artifact, deployer)` — `constructor().transact()` → `wait_for_transaction_receipt` |
| 44–49 | `register_project(...)` — calls `registerProject()` with ETH deposit |
| 51–53 | `register_client(...)` — calls `registerClient()` |
| 55–60 | `publish_task(...)` — calls `publishTask()` |
| 62–66 | `update_model(...)` — calls `updateModel()` |
| 68–82 | `feedback_model(...)` — calls `feedbackModel()` |

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/scripts/demo_end_to_end.py` | 23 | Import: `PQBFLContractClient, load_hardhat_artifact` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 154 | `w3 = Web3(Web3.HTTPProvider(cfg.chain_url))` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 155 | `w3.is_connected()` check |
| `python/pqbfl/scripts/demo_end_to_end.py` | 219 | `artifact = load_hardhat_artifact(chain_dir)` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 222 | `contract = PQBFLContractClient.deploy_from_artifact(w3, artifact, ...)` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 254 | `contract.register_project(id_p, n_clients, h_m0, h_pks, deposit_wei)` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 267 | `contract.register_client(h_epk=h_epk_a, id_p=id_p)` per client |
| `python/pqbfl/scripts/demo_end_to_end.py` | 371 | `contract.publish_task(r, h_inf_b, h_pks_r, id_t, id_p, deadline)` per round |
| `python/pqbfl/scripts/demo_end_to_end.py` | 431 | `contract.update_model(r, h_inf_a, h_ct_epk=0x00*32, id_t, id_p)` per client |
| `python/pqbfl/scripts/demo_end_to_end.py` | 457 | `contract.feedback_model(r, id_t, id_p, client_addr, h_inf_a, h_pks_r, score_delta, terminate)` |

---

## 10. Blockchain — HD Wallet / Accounts

**Definition file:** `python/pqbfl/chain/hardhat_accounts.py`

| Line(s) | What / Algorithm |
|---------|-----------------|
| 5 | `from eth_account import Account` |
| 8 | `HARDHAT_DEFAULT_MNEMONIC = "test test test … junk"` — BIP-39 mnemonic |
| 12–15 | `HardhatAccount` frozen dataclass (`index, address, private_key_hex`) |
| 17–23 | `derive_hardhat_account(index)` — **BIP-44 HD derivation**: `m/44'/60'/0'/0/{index}` via `Account.from_mnemonic()` |

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/scripts/demo_end_to_end.py` | 24 | Import: `derive_hardhat_account` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 157 | `server_acct = derive_hardhat_account(0)` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 159 | `client_accts = [derive_hardhat_account(i) for i in range(1, 1 + n_clients)]` |

---

## 11. Blockchain — Ethereum Message Signing

**Definition file:** `python/pqbfl/crypto/ethsig.py`

| Line(s) | What / Algorithm |
|---------|-----------------|
| 4 | `from eth_account import Account` |
| 5 | `from eth_account.messages import encode_defunct` |
| 8–11 | `EthIdentity` frozen dataclass (`address, private_key_hex`) |
| 13–15 | `sign_bytes(private_key_hex, message)` — `Account.sign_message(encode_defunct(msg))` |
| 18–19 | `recover_signer(message, signature)` — `Account.recover_message(...)` |

> Note: `ethsig.py` is defined but not called in the main demo flow (off-chain Ed25519 is used instead). It is available for direct on-chain Ethereum identity binding.

---

## 12. Federated Learning — Model

**Definition file:** `python/pqbfl/fl/model.py`

| Line(s) | What / Algorithm |
|---------|-----------------|
| 8–11 | `LogisticModel` dataclass (`w: ndarray`, `b: float`) |
| 13–18 | `LogisticModel.init(d, seed)` — `rng.normal(scale=0.01)` weight init |
| 20–21 | `copy()` — deep copy |
| 24–31 | `predict_proba(x)` — **sigmoid**: `σ(x @ w + b)`, clipped to ±50 |
| 33–34 | `predict(x)` — binary threshold at 0.5 |
| 36–64 | `train_sgd(x, y, lr, epochs, batch_size, l2, seed)` — **mini-batch SGD** with optional **L2 regularization**: `grad_w += l2 × w` |
| 66–72 | `to_bytes()` / `from_bytes()` — `numpy.savez` / `numpy.load` serialization for encrypted transport |
| 74–76 | `accuracy(model, x, y)` — `mean(predict(x) == y)` |

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/fl/aggregator.py` | 4 | Import: `LogisticModel` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 30 | Import: `LogisticModel, accuracy` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 248 | `global_model = LogisticModel.init(d, seed=cfg.model_seed)` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 418 | `received_model = LogisticModel.from_bytes(msg["M"])` — client deserializes decrypted model |
| `python/pqbfl/scripts/demo_end_to_end.py` | 419 | `local_model = received_model.copy()` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 422–432 | `local_model.train_sgd(ds.x, y_train, lr, epochs, batch_size, l2, seed)` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 466–469 | `accuracy(global_model, dataset.x_test, dataset.y_test)` appended per round |

---

## 13. Federated Learning — Aggregators

**Definition file:** `python/pqbfl/fl/aggregator.py`

### FedAvg

| Line(s) | What happens |
|---------|-------------|
| 7–30 | `fedavg(models: list[(LogisticModel, int)])` — **weighted average**: `w_new = Σ (n_i/N) × w_i`, `b_new = Σ (n_i/N) × b_i` |

### Coordinate Median

| Line(s) | What happens |
|---------|-------------|
| 32–54 | `coord_median(models)` — **unweighted coordinate-wise median**: `np.median(w_stack, axis=0)` — robust against Byzantine clients |

### Trimmed Mean

| Line(s) | What happens |
|---------|-------------|
| 56–95 | `trimmed_mean(models, trim_ratio=0.1)` — sorts per-coordinate, trims `k=floor(ratio×n)` from top and bottom, then mean — **Byzantine-robust** |

**Used in:**

| File | Line(s) | Usage |
|------|---------|-------|
| `python/pqbfl/scripts/demo_end_to_end.py` | 29 | Import: `coord_median, fedavg, trimmed_mean` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 464 | `global_model = coord_median(local_updates)` if `cfg.aggregator == "median"` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 466 | `global_model = trimmed_mean(local_updates, trim_ratio=cfg.trim_ratio)` if `"trimmed_mean"` |
| `python/pqbfl/scripts/demo_end_to_end.py` | 468 | `global_model = fedavg(local_updates)` default |

---

## 14. Federated Learning — Dataset

**Definition file:** `python/pqbfl/fl/data.py`

| Line(s) | What / Algorithm |
|---------|-----------------|
| 8–10 | `ClientDataset` frozen dataclass (`x, y`) |
| 12–14 | `FederatedDataset` frozen dataclass (`clients: list[ClientDataset], x_test, y_test`) |
| 18–50 | `dict_2classes` — 34-class → binary label map (CIC-IoT-2023 dataset) |
| 52–57 | `X_columns` — 46 numeric network flow features |
| 59–120 | `load_and_preprocess_dataset(csv_path, n_clients, seed)`: `pd.read_csv` → binary label map → `StandardScaler.fit_transform` → `train_test_split(stratify=y, test_size=0.2)` → equal random partition among clients |

**Also (synthetic path) in `demo_end_to_end.py`:**

| Line(s) | What |
|---------|------|
| 261–280 | `make_classification(n_samples=1000, n_features=20, n_informative=15)` → manual 80/20 split → equal client partition (no scaler for synthetic path) |

---

## 15. Frameworks & Dependencies

**Definition file:** `python/requirements.txt`

| Library | Version pin | Where used | Key purpose |
|---------|-------------|------------|-------------|
| `cryptography` | none | `ecdh.py`, `eddsa.py`, `aead.py` | X25519, Ed25519, ChaCha20-Poly1305, SECP256K1 |
| `numpy` | none | `leakage.py`, `ecdh.py`, `eddsa.py`, `kyber.py`, `aead.py`, `model.py`, `aggregator.py`, `data.py` | trace arrays, model weights, data arrays |
| `pqcrypto` | none | `kyber.py` L14–22 | ML-KEM-512 / Kyber512 (PQ KEM) |
| `web3` | none | `contract_client.py`, `demo_end_to_end.py` | Ethereum RPC, contract deploy & calls |
| `eth-account` | none | `hardhat_accounts.py`, `ethsig.py` | BIP-44 HD wallet, Eth signing/recovery |
| `streamlit` | none | `ui_app.py` | Web UI (sliders, charts) |
| `pandas` | none | `fl/data.py` L2 | CSV loading, DataFrame ops |
| `altair` | none | `ui_app.py` | Vega-Altair charts in Streamlit |
| `blake3` | none | `utils.py` L11, `kdf.py` L8 | BLAKE3-256 hashing (KDF + hash32) |
| `sklearn` (scikit-learn) | none | `fl/data.py` L4–5, `demo_end_to_end.py` L261 | StandardScaler, train_test_split, make_classification |

---

## 16. Infrastructure / DevOps

### Hardhat (Local Ethereum Node)

| File | Line(s) | What |
|------|---------|------|
| `chain/hardhat.config.js` | 1 | `require("@nomicfoundation/hardhat-ethers")` |
| `chain/hardhat.config.js` | 4–6 | Solidity 0.8.20, optimizer enabled, runs=200 |
| `chain/hardhat.config.js` | 10–12 | `localhost` network: `http://127.0.0.1:8545` (env override via `HARDHAT_LOCALHOST_URL`) |
| `chain/package.json` | — | `@nomicfoundation/hardhat-ethers`, `hardhat`, `ethers` devDependencies |
| `chain/scripts/deploy.js` | 1–11 | `ethers.getContractFactory("PQBFL")` → `.deploy()` → log deployed address |

### Docker

| File | What |
|------|------|
| `docker/Dockerfile.chain` | Node.js image: installs Hardhat deps, runs `npx hardhat node` |
| `docker/Dockerfile.python` | Python image: installs `requirements.txt`, runs Streamlit UI |
| `docker/docker-compose.yml` | Starts `chain` (port 9545) + `python` (port 9501) services |
| `docker/docker-up.sh` | `docker compose up --build -d` |
| `docker/docker-down.sh` | `docker compose down -v` |

---

*Generated from source inspection of `pqbfl_project new adaptive side channel resistant` — May 2026*
