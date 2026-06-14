# Side-Channel Masking Pipeline — PQBFL Adaptive SC-Resistant Variant

```mermaid
flowchart TD
    %% ── LAYER 1 · Boolean Masking ────────────────────────────────────────
    subgraph L1["① BOOLEAN MASKING  ·  leakage.py :: mask_bytes()"]
        direction LR
        SK["🔑 Secret Key k\n─────────────────\n32 bytes\nKEM sk / ECDH priv / AEAD key"]
        MB["mask_bytes(k)\n─────────────────\nmask ← U(0,255)ⁿ\nshare₁ = k ⊕ mask\nshare₂ = mask"]
        S1["Share₁\n= k ⊕ mask\n(random-looking)"]
        S2["Share₂\n= mask\n(uniform random)"]
        REC["✔ Recovery\n─────────────\nS₁ ⊕ S₂ = k\nNo share alone leaks k"]

        SK -->|"secret never\nused whole"| MB
        MB --> S1
        MB --> S2
        S1 & S2 -.->|"combine_shares()"| REC
    end

    %% ── LAYER 2 · Leakage Simulation ─────────────────────────────────────
    subgraph L2["② LEAKAGE SIMULATION  ·  leakage.py :: simulate_trace()"]
        direction LR
        T1["trace(S₁)\n─────────────────\nHW(byte[i]) + N(0, σ²)\njitter: roll(t, Δ), Δ∈{0,1,2}"]
        T2["trace(S₂)\n─────────────────\nHW(byte[i]) + N(0, σ²)\njitter: roll(t, Δ), Δ∈{0,1,2}"]
        TC["Combined Trace\n─────────────────\ntrace(S₁) + trace(S₂)\n← attacker observes THIS\n(not k directly)"]

        T1 -->|"+"| TC
        T2 -->|"+"| TC
    end

    %% ── LAYER 3 · Adaptive Defence ────────────────────────────────────────
    subgraph L3["③ ADAPTIVE DEFENCE  ·  leakage.py :: apply_defense()"]
        direction LR
        M_NONE["mode = none\n─────────\nσ = 0,  Δ = 0\nbaseline / no defence"]
        M_MASK["mode = masking\n─────────\nσ = 0.5,  Δ = 0\nlow noise injection"]
        M_NOISE["mode = noise\n─────────\nσ = 2.0,  Δ = 0\nmedium noise injection"]
        M_ADAPT["mode = adaptive\n─────────\nσ = 2.5  + roll(Δ)\nΔ ~ U(1,4)\n★ defeats DPA / CPA"]
        DT["Defended Trace\n─────────────────\nhigh-entropy output\nattacker cannot recover k"]

        M_ADAPT -->|"applied to\ncombined trace"| DT
    end

    %% ── LAYER 4 · Protected Primitives ───────────────────────────────────
    subgraph L4["④ PROTECTED CRYPTOGRAPHIC PRIMITIVES"]
        direction LR
        P1["kyber_decap()\n─────\nkyber.py\nMasks secret key\nbefore KEM decrypt"]
        P2["kyber_encap()\n─────\nkyber.py\nSimulates leakage\nfrom public key ops"]
        P3["ecdh_shared_secret\n_secp256k1()\n─────\necdh.py"]
        P4["ecdh_shared_secret\n_x25519()\n─────\necdh.py"]
        P5["aead_encrypt()\nChaCha20-Poly1305\n─────\naead.py\nMasks AEAD key"]
        P6["aead_decrypt()\nChaCha20-Poly1305\n─────\naead.py\nMasks AEAD key"]
    end

    %% ── Flow connections between layers ──────────────────────────────────
    L4 -->|"all primitives call\nmask_bytes(secret)"| L1
    L1 -->|"simulate_trace(shareₙ)"| L2
    L2 -->|"apply_defense(combined_trace,\nmode='adaptive')"| L3

    %% ── Styling ──────────────────────────────────────────────────────────
    classDef secret   fill:#5c1a1a,stroke:#E05252,color:#fdd,font-weight:bold
    classDef share    fill:#1a2e4a,stroke:#4A9EEB,color:#cdf
    classDef mask2    fill:#0d2e1e,stroke:#3EC98A,color:#cfd
    classDef recovery fill:#1a2030,stroke:#5A6490,color:#bcc
    classDef trace    fill:#2e2000,stroke:#F0A500,color:#ffe
    classDef defended fill:#1e0e36,stroke:#B06EF5,color:#e8d
    classDef mode     fill:#111827,stroke:#5A6490,color:#aaa
    classDef prim     fill:#0d1f2e,stroke:#5BC8F5,color:#cef

    class SK secret
    class MB,REC recovery
    class S1 share
    class S2 mask2
    class T1,T2,TC trace
    class M_NONE,M_MASK,M_NOISE mode
    class M_ADAPT,DT defended
    class P1,P2,P3,P4,P5,P6 prim
```

## How the pipeline works

| Layer | Function | What it does |
|---|---|---|
| ① Boolean Masking | `mask_bytes(k)` | Splits secret `k` into `S₁ = k ⊕ mask` and `S₂ = mask`; no single share reveals `k` |
| ② Leakage Simulation | `simulate_trace(share)` | Models Hamming-weight power leakage + Gaussian noise + random temporal jitter per share |
| ③ Adaptive Defence | `apply_defense(trace, mode)` | Adds σ=2.5 noise and random roll shift in `adaptive` mode to defeat DPA/CPA correlation attacks |
| ④ Primitives | `kyber_decap`, `ecdh_*`, `aead_*` | Every secret-touching operation passes through layers ①→②→③ before and after use |

### Defence modes

| Mode | Noise σ | Jitter Δ | Use case |
|---|---|---|---|
| `none` | 0 | 0 | Baseline / testing |
| `masking` | 0.5 | 0 | Light protection |
| `noise` | 2.0 | 0 | Medium protection |
| `adaptive` | **2.5** | **U(1,4)** | **Full DPA/CPA resistance** |
