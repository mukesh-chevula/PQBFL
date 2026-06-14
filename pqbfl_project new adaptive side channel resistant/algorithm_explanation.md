# Algorithm Explanations

Project scope: PQBFL adaptive side-channel resistant variant.

This document explains the algorithms used in the system with:
- formal model,
- proof-style security/correctness arguments,
- implementation-oriented pseudocode.

## Full algorithm index

### Cryptographic core (§1–§10)
1. ML-KEM-512 / Kyber512 (post-quantum KEM)
2. X25519 ECDH (Curve25519 key agreement)
3. Ed25519 signatures
4. ChaCha20-Poly1305 AEAD
5. HKDF (extract-and-expand KDF)
6. HMAC-based symmetric ratchet KDF
7. BLAKE3-256 hashing
8. SHA-256 hashing
9. Boolean masking for side-channel resistance
10. Hamming-weight leakage simulation model

### Side-channel defenses & adaptive control (§11–§14)
11. Additive Gaussian noise defense (multiple sigma levels)
12. Jitter / trace-shift defense (`np.roll`-based)
13. Adaptive ratchet threshold mapping (power-curve policy for $L_j$)
14. Exponential-decay weighted threat scoring

### Federated learning model & training (§15–§17)
15. Logistic regression
16. Mini-batch stochastic gradient descent
17. L2 regularization

### Federated aggregation (§18–§20)
18. FedAvg aggregation
19. Coordinate-wise median aggregation
20. Trimmed-mean aggregation

### Data pipeline (§21–§23)
21. Stratified train/test split
22. Feature standardization (`StandardScaler`)
23. Synthetic data generation (`make_classification`)

---

## 1) ML-KEM-512 / Kyber512 (Post-Quantum KEM)

### 1.1 Mathematical model
A Key Encapsulation Mechanism (KEM) is a triple of PPT algorithms:
- $\mathsf{KeyGen}(1^\lambda) \to (pk, sk)$
- $\mathsf{Encaps}(pk) \to (ct, ss)$
- $\mathsf{Decaps}(sk, ct) \to ss'$

Correctness requires:
$$
\Pr[ss' = ss] \ge 1 - \epsilon(\lambda)
$$
where $\epsilon$ is negligible.

Kyber/ML-KEM is lattice-based (module-LWE family). Security is based on hardness of structured LWE variants against quantum adversaries.

### 1.2 Security notion (IND-CCA for KEM)
Let adversary $\mathcal{A}$ choose adaptively decryption queries except the challenge ciphertext $ct^*$. In the challenge game, challenger samples $b \in \{0,1\}$ and returns:
- if $b=0$: real shared secret from encapsulation,
- if $b=1$: uniformly random secret.

Advantage:
$$
\mathsf{Adv}^{\mathsf{IND-CCA}}_{\mathcal{A}} = \left|\Pr[b'=b] - \frac{1}{2}\right|
$$
A KEM is IND-CCA secure if this is negligible.

### 1.3 Why correctness holds in this project flow
In protocol session setup:
- Client runs encapsulation using server public key, obtaining $(ct, ss_k)$.
- Server runs decapsulation on the same $ct$ and secret key, deriving $ss_k'$.

By KEM correctness:
$$
ss_k' = ss_k \quad \text{except negligible failure probability}
$$
The root key is then derived from $ss_k$ and ECDH secret, so both parties match unless either component mismatches.

### 1.4 Step-by-step process (Kyber512 / ML-KEM-512 internals)

Let $R_q = \mathbb{Z}_q[X] / (X^n + 1)$ with $n = 256$, $q = 3329$. Kyber512 uses module rank $k = 2$, error distribution $\chi$ (centered binomial $\mathrm{CBD}_{\eta_1}, \mathrm{CBD}_{\eta_2}$ with $\eta_1=3, \eta_2=2$).

**Step 1 — KeyGen$(1^\lambda) \to (pk, sk)$**
1. Sample seed $\rho, \sigma \leftarrow \{0,1\}^{256}$.
2. Expand public matrix from $\rho$:
   $$\mathbf{A} \in R_q^{k \times k}, \qquad \mathbf{A}_{ij} = \mathsf{XOF}(\rho, i, j)$$
3. Sample secret/error:
   $$\mathbf{s}, \mathbf{e} \leftarrow \chi^{k}$$
4. Compute public vector:
   $$\mathbf{t} = \mathbf{A}\mathbf{s} + \mathbf{e} \bmod q$$
5. Output $pk = (\mathbf{t}, \rho)$, $sk = \mathbf{s}$ (plus extra material for FO transform in CCA version).

**Step 2 — Encaps$(pk) \to (ct, ss)$ (CPA core)**
1. Sample message $m \leftarrow \{0,1\}^{256}$.
2. Derive randomness $r = G(m \| H(pk))$.
3. Sample $\mathbf{r}', \mathbf{e}_1 \leftarrow \chi^k$, $e_2 \leftarrow \chi$.
4. Compute ciphertext:
   $$\mathbf{u} = \mathbf{A}^\top \mathbf{r}' + \mathbf{e}_1$$
   $$v = \mathbf{t}^\top \mathbf{r}' + e_2 + \mathrm{Decompress}_q(m,1) \bmod q$$
5. Compress: $ct = (\mathrm{Compress}(\mathbf{u}, d_u), \mathrm{Compress}(v, d_v))$.
6. Shared secret $ss = \mathsf{KDF}(m \| H(ct))$.

**Step 3 — Decaps$(sk, ct) \to ss'$**
1. Decompress $(\mathbf{u}, v)$.
2. Compute:
   $$m' = \mathrm{Compress}\bigl(v - \mathbf{s}^\top \mathbf{u},\; 1\bigr)$$
3. Re-encrypt $m'$ using deterministic $r' = G(m' \| H(pk))$ to get $ct'$.
4. If $ct' = ct$: output $ss = \mathsf{KDF}(m' \| H(ct))$; else: output pseudorandom $\mathsf{KDF}(z \| H(ct))$ (implicit rejection in FO transform).

**Step 4 — Correctness algebra.** Plug $\mathbf{t} = \mathbf{A}\mathbf{s} + \mathbf{e}$ into $v$:
$$
v - \mathbf{s}^\top \mathbf{u} = (\mathbf{A}\mathbf{s} + \mathbf{e})^\top \mathbf{r}' + e_2 + \mu - \mathbf{s}^\top(\mathbf{A}^\top \mathbf{r}' + \mathbf{e}_1)
$$
where $\mu = \mathrm{Decompress}_q(m,1)$. Expanding:
$$
= \mathbf{s}^\top \mathbf{A}^\top \mathbf{r}' + \mathbf{e}^\top \mathbf{r}' + e_2 + \mu - \mathbf{s}^\top \mathbf{A}^\top \mathbf{r}' - \mathbf{s}^\top \mathbf{e}_1
$$
$$
= \mu + \underbrace{\mathbf{e}^\top \mathbf{r}' - \mathbf{s}^\top \mathbf{e}_1 + e_2}_{\text{small error term } \Delta}
$$
Decoding recovers $m$ iff $\|\Delta\|_\infty < q/4$. Kyber parameters are chosen so $\Pr[\|\Delta\|_\infty \geq q/4] = \delta < 2^{-139}$, which is the formal correctness bound:
$$
\Pr[\mathsf{Decaps}(sk, \mathsf{Encaps}(pk)) = ss] \geq 1 - \delta
$$

**Step 5 — IND-CCA reduction (FO transform sketch).** Let $\mathcal{A}$ break IND-CCA with advantage $\epsilon$. The Fujisaki–Okamoto transform reduces to IND-CPA security of the inner PKE plus collision resistance of $H$:
$$
\mathsf{Adv}^{\mathsf{CCA}}_{\mathsf{KEM}}(\mathcal{A}) \leq q_D \cdot \delta + 2 q_G \cdot \mathsf{Adv}^{\mathsf{CPA}}_{\mathsf{PKE}}(\mathcal{B}) + \mathsf{negl}(\lambda)
$$
Under Module-LWE hardness $\mathsf{Adv}^{\mathsf{CPA}}_{\mathsf{PKE}}$ is negligible, giving IND-CCA security.

### 1.5 Pseudocode
```text
Algorithm KEM-Session-Component
Input: server public key pk_B, server secret key sk_B
Output: shared secret ss_k at client/server

Client side:
1: m       <- UniformRandom(256 bits)
2: r       <- G(m || H(pk_B))
3: (u, v)  <- CPA_Encrypt(pk_B, m; r)
4: ct      <- Compress(u, v)
5: ss_k_c  <- KDF(m || H(ct))
6: send ct to server

Server side:
7: (u, v)  <- Decompress(ct)
8: m'      <- Decode(v - s^T u)
9: r'      <- G(m' || H(pk_B))
10: ct''   <- Compress(CPA_Encrypt(pk_B, m'; r'))
11: if ct'' == ct: ss_k_s <- KDF(m'  || H(ct))
12: else:           ss_k_s <- KDF(z   || H(ct))   // implicit reject
13: return ss_k_s

Property (correctness theorem):
14: ss_k_s == ss_k_c except with prob <= delta ~ 2^-139
```

---

## 2) X25519 ECDH (Curve25519 key agreement)

### 2.1 Group-theoretic definition
Let $G$ be the prime-order subgroup generated by base point $P$ on Curve25519. Parties sample private scalars:
$$
a, b \in_R \mathbb{Z}_q
$$
Public keys:
$$
A = aP, \quad B = bP
$$
Shared secret computation:
$$
S_A = aB = a(bP) = (ab)P
$$
$$
S_B = bA = b(aP) = (ab)P
$$
Hence $S_A = S_B$ (commutativity in scalar multiplication).

### 2.2 Correctness proof sketch
Given valid group operations:
$$
a(bP) = (ab)P = (ba)P = b(aP)
$$
So both parties derive same point (or x-coordinate in X25519 representation). This is exactly what protocol code uses for $ss_e$.

### 2.3 Security argument
If Computational Diffie-Hellman (CDH) is hard in Curve25519 subgroup, then from $(P, aP, bP)$ attacker cannot compute $(ab)P$ efficiently. Practical X25519 also includes scalar clamping and constant-time operations in hardened libs.

### 2.4 Step-by-step process

Curve25519 is the Montgomery curve
$$E: y^2 = x^3 + 486662 x^2 + x \pmod{p},\qquad p = 2^{255} - 19$$
over prime field $\mathbb{F}_p$, with cofactor $h = 8$ and prime-order subgroup of order $\ell = 2^{252} + 27742\ldots$.

**Step 1 — Key generation.**
1. Sample $k \leftarrow \{0,1\}^{256}$ uniformly.
2. Apply scalar clamping:
   $$a = k \text{ with bits set: } a_0\!\to\!0, a_1\!\to\!0, a_2\!\to\!0, a_{255}\!\to\!0, a_{254}\!\to\!1$$
   This forces $a \in \{2^{254}, 2^{254}+8, \ldots, 2^{255}-8\}$, eliminating cofactor and small-subgroup attacks.
3. Public key $A = a \cdot P$ where $P = (9, \ldots)$ is the standard base point. X25519 transmits only the $u$-coordinate.

**Step 2 — Shared secret computation.** Given peer public $u_B$, compute
$$ss = X25519(a, u_B) = u\text{-coord of }(a \cdot B)$$
using the Montgomery ladder (constant-time):
```
(R0, R1) <- (P_inf, B)
for i = 254 down to 0:
    bit <- a_i
    cswap(R0, R1, bit)
    (R0, R1) <- (2*R0, R0 + R1)   // formula avoids y-coord
    cswap(R0, R1, bit)
return u(R0)
```

**Step 3 — Correctness theorem.**
*Claim.* For any scalars $a, b$ with $a, b < \ell$ and base $P$:
$$X25519(a, X25519(b, P)) = X25519(b, X25519(a, P))$$

*Proof.* In the prime-order subgroup, scalar multiplication is a group homomorphism. Therefore
$$a \cdot (b \cdot P) = (ab) \cdot P = (ba) \cdot P = b \cdot (a \cdot P).$$
Montgomery $u$-coordinate is invariant under the sign of $y$, so
$$u(a \cdot (b P)) = u((ab) P) = u(b \cdot (a P)). \qquad\square$$

**Step 4 — Security reduction.** Computational Diffie–Hellman (CDH) for X25519:
Given $(P, aP, bP)$, output $u(abP)$. The best classical algorithm is Pollard rho on the prime-order subgroup with cost
$$O\!\left(\sqrt{\ell}\right) \approx 2^{126}$$
operations, providing $\approx 128$-bit classical security. Under the **Gap-DH** assumption (CDH hard even given DDH oracle), X25519 keys are pseudorandom after a hash extractor — which is exactly how this project uses $ss_e$: it is fed into HKDF, not used directly.

**Step 5 — Why clamping prevents small-subgroup attack.** If $u_B$ is a point of order $d \in \{1, 2, 4, 8\}$ (small subgroup of cofactor), then $a \cdot B \in \langle B \rangle$ which has at most $d$ elements, leaking $a \bmod d$. Clamping forces $a \equiv 0 \pmod{8}$, so
$$a \cdot B = (8 \cdot (a/8)) \cdot B = (a/8) \cdot (8B) = (a/8) \cdot \mathcal{O} = \mathcal{O}$$
for any point of order dividing 8. Thus output is independent of $a \bmod 8$, killing the leak.

### 2.5 Pseudocode
```text
Algorithm X25519-ECDH
Input: 32-byte random k, peer public u_B
Output: shared secret ss_e (32 bytes)

1: a     <- Clamp(k)              // forces a in 2^254..2^255-8, a mod 8 = 0
2: u_A   <- MontgomeryLadder(a, BasePoint)
3: ss_e  <- MontgomeryLadder(a, u_B)
4: return ss_e

Agreement theorem:
ss_e_A = X25519(a, u_B) = u((ab)P) = X25519(b, u_A) = ss_e_B
```

---

## 3) Ed25519 Signatures

### 3.1 Signature API
- Key generation: $(pk, sk)$
- Sign: $\sigma \leftarrow \mathsf{Sign}(sk, m)$
- Verify: $\mathsf{Verify}(pk, m, \sigma) \in \{0,1\}$

### 3.2 Correctness theorem
For all messages $m$ and honestly generated keys:
$$
\Pr[\mathsf{Verify}(pk,m,\mathsf{Sign}(sk,m)) = 1] = 1
$$
(up to implementation-level exceptional failure treated as negligible).

### 3.3 EUF-CMA security game
Attacker obtains signatures on chosen messages and outputs forgery $(m^*,\sigma^*)$ where $m^*$ was not previously queried. Advantage is probability that verify accepts. Ed25519 aims negligible advantage under elliptic-curve discrete-log assumptions + hash model assumptions.

### 3.4 Role in protocol
The project signs:
- server off-chain pubkey package,
- client off-chain encapsulation message,
- per-round encrypted payloads.

This gives origin authentication and tamper detection before decrypting or accepting updates.

### 3.5 Step-by-step process

Ed25519 uses the twisted Edwards curve
$$E: -x^2 + y^2 = 1 + d\, x^2 y^2 \pmod{p}, \qquad d = -121665/121666,\ p = 2^{255}-19$$
birationally equivalent to Curve25519. Base point $B$ has prime order $\ell$.

**Step 1 — Key generation.**
1. Sample seed $sk \leftarrow \{0,1\}^{256}$.
2. Compute $h = \mathrm{SHA\text{-}512}(sk) = (h_0, h_1)$, each 32 bytes.
3. Clamp $h_0$ as in X25519 to scalar $a$.
4. Public key $A = a \cdot B$ (encoded as 32-byte compressed Edwards point).

**Step 2 — Signing $\mathsf{Sign}(sk, m) \to \sigma$.**
1. Derive nonce **deterministically**:
   $$r = \mathrm{SHA\text{-}512}(h_1 \| m) \bmod \ell$$
2. Compute commitment $R = r \cdot B$.
3. Compute challenge
   $$c = \mathrm{SHA\text{-}512}(R \| A \| m) \bmod \ell$$
4. Compute response
   $$s = r + c \cdot a \bmod \ell$$
5. Output $\sigma = (R, s)$.

**Step 3 — Verification $\mathsf{Verify}(A, m, \sigma) \to \{0,1\}$.**
1. Parse $\sigma = (R, s)$; reject if $s \geq \ell$.
2. Recompute $c = \mathrm{SHA\text{-}512}(R \| A \| m) \bmod \ell$.
3. Check the Schnorr equation:
   $$[8 s] B \stackrel{?}{=} [8] R + [8 c] A$$
   (multiplication by cofactor 8 makes the check cofactor-clearing.)

**Step 4 — Correctness proof.** Starting from honest signing:
$$s B = (r + ca) B = rB + c(aB) = R + cA$$
Multiplying both sides by $8$:
$$8 s B = 8 R + 8 c A$$
which is exactly the verifier's check. Hence honest signatures always verify. $\square$

**Step 5 — EUF-CMA security reduction (Schnorr → DLog).** Assume $\mathcal{F}$ forges with probability $\epsilon$ after $q_H$ random-oracle queries to $H = \mathrm{SHA\text{-}512}$.

The **Forking Lemma** (Pointcheval–Stern, Bellare–Neven) says: running $\mathcal{F}$ twice with the same random tape but different oracle answers from the point of the challenge query produces two valid forgeries $(R, s)$ and $(R, s')$ with same $R$ but different $c \ne c'$, with probability
$$
\epsilon' \geq \frac{\epsilon^2}{q_H} - \frac{1}{2^{|c|}}
$$
From the two equations:
$$sB = R + cA, \qquad s'B = R + c'A$$
Subtract:
$$(s - s') B = (c - c') A \;\Longrightarrow\; a = (s - s')(c - c')^{-1} \bmod \ell$$
This solves discrete log in the prime-order subgroup. Hence:
$$
\mathsf{Adv}^{\mathsf{EUF\text{-}CMA}}_{\mathsf{Ed25519}}(\mathcal{F}) \leq \sqrt{q_H \cdot \mathsf{Adv}^{\mathsf{DLog}}(\mathcal{B})} + \mathsf{negl}(\lambda)
$$
Under ECDLP hardness on Curve25519 ($\approx 2^{126}$ ops), forgery probability is negligible.

**Step 6 — Determinism prevents catastrophic nonce reuse.** Step 2's $r$ depends on $(h_1, m)$, so two signatures on the same $m$ produce same $\sigma$. If $r$ were reused across $m \ne m'$:
$$s - s' = (c - c') a \Rightarrow a = (s-s')/(c-c')$$
(the same algebra used in the security reduction). Determinism eliminates this whole class of bug.

### 3.6 Pseudocode
```text
Algorithm Ed25519-Sign
Input: secret seed sk (32 bytes), message m
Output: signature sigma = (R, s)

1: (h0, h1) <- SHA-512(sk)
2: a        <- Clamp(h0) mod ell
3: A        <- a * B
4: r        <- SHA-512(h1 || m) mod ell
5: R        <- r * B
6: c        <- SHA-512(R || A || m) mod ell
7: s        <- (r + c * a) mod ell
8: return (R, s)

Algorithm Ed25519-Verify
Input: public key A, message m, signature (R, s)
Output: accept/reject

1: if s >= ell: reject
2: c <- SHA-512(R || A || m) mod ell
3: if [8s]B == [8]R + [8c]A: accept
4: else: reject
```

---

## 4) ChaCha20-Poly1305 AEAD

### 4.1 AEAD definition
Authenticated encryption with associated data has:
- $c \leftarrow \mathsf{Enc}(k, n, m, aad)$
- $m \leftarrow \mathsf{Dec}(k, n, c, aad)$ or $\bot$

Security goals:
- IND-CPA/IND-CCA-style confidentiality for $m$.
- Integrity: cannot forge valid ciphertext/tag for unseen tuple.

### 4.2 Construction insight
ChaCha20 generates keystream; Poly1305 provides one-time MAC over ciphertext and AAD. Nonce uniqueness under a fixed key is critical.

### 4.3 Correctness argument
For valid input and same $(k,n,aad)$:
$$
\mathsf{Dec}(k,n,\mathsf{Enc}(k,n,m,aad),aad)=m
$$
If any bit of ciphertext/tag/AAD changes, verification fails with probability close to $1$ (except tiny forgery bound).

### 4.4 Nonce derivation in project
Nonce is deterministic from round and direction:
$$
n = \mathsf{Hash32}(\text{"pqbfl:"} || \text{label} || \text{":"} || r)[0:12]
$$
Distinct direction+round labels reduce accidental nonce reuse per key schedule.

### 4.5 Step-by-step process

**Step 1 — ChaCha20 quarter-round.** ChaCha20 keeps a 16-word state $S = (s_0, \ldots, s_{15})$, each $s_i \in \mathbb{Z}_{2^{32}}$. The atomic operation is the quarter-round on four words $(a,b,c,d)$:
$$
\begin{aligned}
a &\mathrel{+}= b; \quad d \mathrel{\oplus}= a; \quad d \lll 16 \\
c &\mathrel{+}= d; \quad b \mathrel{\oplus}= c; \quad b \lll 12 \\
a &\mathrel{+}= b; \quad d \mathrel{\oplus}= a; \quad d \lll 8 \\
c &\mathrel{+}= d; \quad b \mathrel{\oplus}= c; \quad b \lll 7
\end{aligned}
$$
The full block applies 8 quarter-rounds × 10 = 80 quarter-rounds (i.e. 20 rounds, alternating column and diagonal). After rounds, the working state is added word-wise to the original $S$, giving a 512-bit keystream block.

**Step 2 — Initial state.**
$$S = (\underbrace{c_0, c_1, c_2, c_3}_{\text{constants}}, \underbrace{k_0, \ldots, k_7}_{256\text{-bit key}}, \underbrace{\text{ctr}}_{32}, \underbrace{n_0, n_1, n_2}_{96\text{-bit nonce}})$$
The four constants are ASCII "expand 32-byte k".

**Step 3 — Encryption.** For plaintext $m$ of length $L$:
1. Generate keystream $Z = Z_0 \| Z_1 \| \cdots$ by incrementing ctr from 1.
2. Output ciphertext
$$c = m \oplus Z[0\!:\!L]$$
3. Block at counter $0$ is reserved for Poly1305 one-time key derivation.

**Step 4 — Poly1305 MAC.** Let $r, s \in \mathbb{F}_{2^{130}-5}$ be derived from keystream block 0:
$$(r, s) = Z_0[0\!:\!16],\ Z_0[16\!:\!32]$$
with $r$ clamped (10 bits cleared). For input $M = aad \| \mathrm{pad}_{16} \| c \| \mathrm{pad}_{16} \| |aad|_8 \| |c|_8$, split into 16-byte blocks $M_1, \ldots, M_q$ (each padded with a leading $0x01$ byte). Tag is
$$T = \left(\sum_{i=1}^{q} M_i \cdot r^{q-i+1} \bmod (2^{130}-5)\right) + s \bmod 2^{128}$$
This is a polynomial evaluation MAC in the prime field $\mathbb{F}_{2^{130}-5}$.

**Step 5 — Output and decryption.** AEAD ciphertext is $(c, T)$. Decryption recomputes $T'$ and compares in constant time; on mismatch returns $\bot$, otherwise outputs $m = c \oplus Z[0\!:\!L]$.

**Step 6 — Security bound (AEAD).** Let $\mathcal{A}$ make $q$ encryption queries totaling $\sigma$ blocks and $q_v$ forgery attempts.
- **Confidentiality (IND-CPA):** ChaCha20 is PRF-secure; advantage bounded by
  $$\mathsf{Adv}^{\mathsf{prf}}_{\mathsf{ChaCha20}} + \frac{\sigma^2}{2^{128}}$$
- **Integrity (INT-CTXT):** Poly1305 is $\epsilon$-AXU with $\epsilon \leq \lceil L/16 \rceil / 2^{102}$. Total forgery probability bound:
  $$\mathsf{Adv}^{\mathsf{int\text{-}ctxt}} \leq \frac{q_v \cdot \lceil L_{\max}/16 \rceil}{2^{102}}$$
- **Nonce reuse caveat:** if $(k, n)$ pair repeats, attacker recovers $m \oplus m'$ from XOR of ciphertexts, AND recovers $r$ from MAC algebra, breaking integrity entirely. Hence the project's deterministic nonce $n = \mathrm{Hash32}(\text{"pqbfl:"} \| \text{dir} \| \text{":"} \| r)[0\!:\!12]$ relies on distinct (direction, round) pairs per ratchet key.

**Step 7 — Why per-round key + per-round nonce is safe in PQBFL.** The model key $MK_r$ changes every round (Section 6), AND the nonce is bound to direction+round, so even if the hash collided on nonce, the underlying key would differ. The composition gives $(k, n)$ uniqueness with overwhelming probability.

### 4.6 Pseudocode
```text
Algorithm Round-AEAD
Input: model key MK_r (32B), round r, direction dir, payload P
Output: ciphertext C, tag T

1: aad   <- Encode("pqbfl:" || dir || ":" || r)
2: nonce <- Hash32(aad)[0:12]
3: Z_0   <- ChaCha20Block(MK_r, nonce, counter=0)
4: (r_p, s_p) <- (Clamp(Z_0[0:16]), Z_0[16:32])
5: Z     <- ChaCha20Stream(MK_r, nonce, counter>=1, len(P))
6: C     <- Serialize(P) XOR Z
7: T     <- Poly1305(r_p, s_p, aad || pad || C || pad || len(aad) || len(C))
8: return (C, T)

Decryption (verify-then-decrypt):
9:  recompute T'
10: if T' != T (constant-time): reject
11: P <- C XOR Z
```

---

## 5) HKDF (Extract-and-Expand)

### 5.1 Formal equations
Given input keying material $IKM$, salt $s$, info string $info$:

Extract:
$$
PRK = \mathsf{HMAC}(s, IKM)
$$

Expand blocks:
$$
T_0 = \epsilon,
\quad
T_i = \mathsf{HMAC}(PRK, T_{i-1} || info || i)
$$
Output keying material:
$$
OKM = T_1 || T_2 || \cdots
$$
(truncated to requested length).

### 5.2 Why extract+expand is robust
- Extract compresses possibly biased/non-uniform input into pseudorandom key under HMAC assumptions.
- Expand provides domain-separated, length-flexible subkeys.

### 5.3 Project-specific root-key derivation
Project combines two shared secrets ($ss_k$ from KEM and $ss_e$ from ECDH):
$$
PRK_1 = \mathsf{HMAC}(0^*, ss_k)
$$
$$
PRK_2 = \mathsf{HMAC}(PRK_1, ss_e)
$$
$$
RK = \mathsf{HKDFExpand}(PRK_2, \text{"pqbfl:RK"}, 32)
$$
This composition means attacker must break at least one secret component to recover full root key (assuming independent hardness).

### 5.4 Step-by-step process

**Step 1 — HMAC primitive.** For hash $H$ with block size $B$ and digest size $L$, key $K$ (padded/truncated to $B$ bytes):
$$\mathrm{HMAC}_K(x) = H\bigl((K \oplus \mathrm{opad}) \;\|\; H((K \oplus \mathrm{ipad}) \| x)\bigr)$$
with $\mathrm{ipad} = 0x36^B$, $\mathrm{opad} = 0x5c^B$. HMAC is a PRF if the compression function of $H$ is a dual PRF (Bellare 2006).

**Step 2 — Extract.** Given input keying material $IKM$ (possibly biased) and salt $s$:
$$PRK = \mathrm{HMAC}(s, IKM) \in \{0,1\}^L$$
*Property (Leftover-Hash-style).* If $IKM$ has min-entropy $\geq k$ and HMAC is a randomness extractor with parameter $\delta$, then $PRK$ is statistically $\delta$-close to uniform $\{0,1\}^L$ given the salt.

**Step 3 — Expand.** Iterative HMAC chain with counter:
$$T_0 = \varepsilon$$
$$T_i = \mathrm{HMAC}(PRK,\; T_{i-1} \| info \| \langle i \rangle_1) \qquad i = 1, 2, \ldots, \lceil L_{\text{out}}/L \rceil$$
$$OKM = T_1 \| T_2 \| \cdots \text{ truncated to } L_{\text{out}}$$

**Step 4 — Correctness of length.** Constraint $L_{\text{out}} \leq 255 L$ because the counter is 1 byte. For Kyber/PQBFL with $L = 32$ and $L_{\text{out}} = 32$, only one block is needed: $RK = T_1$.

**Step 5 — PRF/extractor security composition.** Krawczyk's HKDF theorem (CRYPTO 2010): for any PPT distinguisher $\mathcal{D}$,
$$
\bigl|\Pr[\mathcal{D}(OKM) = 1] - \Pr[\mathcal{D}(U_{L_{\text{out}}}) = 1]\bigr| \leq \mathsf{Adv}^{\mathsf{ext}}_{\mathrm{HMAC}}(\mathcal{B}_1) + \mathsf{Adv}^{\mathsf{prf}}_{\mathrm{HMAC}}(\mathcal{B}_2)
$$
Both terms are negligible if $H$ is a dual PRF / random oracle, so $OKM$ is computationally indistinguishable from uniform.

**Step 6 — Hybrid combining (project specific).** The project chains two extractions:
$$PRK_1 = \mathrm{HMAC}(0^L,\; ss_k)$$
$$PRK_2 = \mathrm{HMAC}(PRK_1,\; ss_e)$$
$$RK = T_1 = \mathrm{HMAC}(PRK_2,\; \text{"pqbfl:RK"} \| 0x01)$$

*Hybrid security claim.* If **either** $ss_k$ (Kyber) **or** $ss_e$ (X25519) is pseudorandom to the adversary, then $RK$ is pseudorandom. Formally let $H_0$ be the real game, $H_1$ replace $PRK_1$ with uniform, $H_2$ replace $PRK_2$ with uniform.
- $|H_0 - H_1| \leq \mathsf{Adv}^{\mathsf{kem\text{-}ind}}(\mathcal{A})$
- $|H_1 - H_2| \leq \mathsf{Adv}^{\mathsf{ddh}}(\mathcal{A})$
- $|H_2 - \text{uniform}| \leq \mathsf{Adv}^{\mathsf{prf}}_{\mathrm{HMAC}}(\mathcal{A})$

By triangle inequality the adversary must break **all three** to distinguish $RK$ from random. This is the **hybrid post-quantum + classical** rationale: even if a quantum attacker breaks X25519, $ss_k$ from Kyber preserves $RK$ pseudorandomness.

### 5.5 Pseudocode
```text
Algorithm HKDF-Extract
Input: salt s, input keying material IKM
Output: PRK (L bytes)
1: return HMAC(s, IKM)

Algorithm HKDF-Expand
Input: PRK, info, output length L_out
Output: OKM
1: n <- ceil(L_out / L)
2: T_prev <- empty
3: OKM <- empty
4: for i = 1..n:
5:     T_prev <- HMAC(PRK, T_prev || info || byte(i))
6:     OKM    <- OKM || T_prev
7: return OKM[0:L_out]

Algorithm RootKey-Derivation (PQBFL)
Input: ss_k (KEM), ss_e (ECDH)
Output: RK (32 bytes)
1: prk1 <- HKDF-Extract(salt = 0x00...0, IKM = ss_k)
2: prk2 <- HKDF-Extract(salt = prk1,    IKM = ss_e)
3: RK   <- HKDF-Expand(prk2, info = "pqbfl:RK", L_out = 32)
4: return RK
```

---

## 6) HMAC-Based Symmetric Ratchet KDF

### 6.1 State transition model
Ratchet state at step $i$ has chain key $CK_i$. Derive:
$$
CK_{i+1} = \mathsf{HMAC}(CK_i, \text{"pqbfl:CK"})
$$
$$
MK_i = \mathsf{HMAC}(CK_i, \text{"pqbfl:MK"})
$$
where $MK_i$ is encryption key for round payload.

### 6.2 Correctness
If both peers start with same $CK_0$ and apply identical transition count/order, then by determinism:
$$
CK_i^A = CK_i^B, \quad MK_i^A = MK_i^B\; \forall i
$$
This is exactly enforced in code via key-match checks.

### 6.3 Forward-secrecy style argument (within epoch)
If attacker learns $CK_t$, they can compute future keys, but cannot efficiently recover prior chain keys under one-wayness of HMAC compression relation. So compromise at time $t$ does not reveal earlier $MK_{<t}$.

### 6.4 Step-by-step process

**Step 1 — Initialization.** From root key $RK$ derived in §5:
$$CK_0 = \mathrm{HMAC}(RK,\;\text{"pqbfl:CK0"})$$
Note $RK$ is used **as the HMAC key**, not as data — this binds the entire chain to the session root.

**Step 2 — Ratchet step $i \to i+1$.**
$$CK_{i+1} = \mathrm{HMAC}(CK_i,\;\text{"pqbfl:CK"})$$
$$MK_i = \mathrm{HMAC}(CK_i,\;\text{"pqbfl:MK"})$$
Domain-separation tags "pqbfl:CK" and "pqbfl:MK" are distinct, so $CK_{i+1}$ and $MK_i$ are independent PRF outputs of $CK_i$.

**Step 3 — One-way recurrence theorem.**
*Claim.* If HMAC is a one-way PRF (under hash compression assumption), given $CK_t$ no PPT adversary recovers $CK_{t-1}$ with non-negligible probability.

*Proof.* By contradiction: suppose $\mathcal{A}$ recovers $CK_{t-1}$ from $CK_t$. Then $\mathcal{A}$ is computing a preimage of $\mathrm{HMAC}(\cdot, \text{"pqbfl:CK"})$, which contradicts one-wayness. $\square$

Applying induction:
$$\forall\, j < t:\quad CK_j \text{ is unrecoverable from } CK_t \text{ (and a fortiori } MK_j \text{ unrecoverable)}.$$
This is **forward secrecy within an epoch.**

**Step 4 — Key independence.**
*Claim.* $MK_i$ is computationally independent of $CK_{i+1}$ given the adversary view.

*Proof sketch.* In the PRF game with key $CK_i$, the outputs $\mathrm{HMAC}(CK_i, x_1)$ and $\mathrm{HMAC}(CK_i, x_2)$ for $x_1 \ne x_2$ are jointly indistinguishable from two independent uniform strings. Hence revealing $MK_i$ (used for AEAD) does not help compute $CK_{i+1}$, except by breaking HMAC. $\square$

**Step 5 — Synchronization invariant.** Define synchronization predicate
$$\mathrm{Sync}(i) \equiv (CK_i^{\text{server}} = CK_i^{\text{client}})$$
Induction:
- *Base:* $\mathrm{Sync}(0)$ from shared $RK$ (proved in §5).
- *Step:* If $\mathrm{Sync}(i)$ holds, then by determinism of HMAC,
  $$CK_{i+1}^S = \mathrm{HMAC}(CK_i^S, \text{"pqbfl:CK"}) = \mathrm{HMAC}(CK_i^C, \text{"pqbfl:CK"}) = CK_{i+1}^C$$
  hence $\mathrm{Sync}(i+1)$.

Therefore $MK_i^S = MK_i^C$ for all $i$, which is the explicit `assert client_model_key == model_key` check in the demo code.

**Step 6 — Bridging to asymmetric ratchet.** When the symmetric step counter reaches threshold $L_j$ (possibly adapted by the threat monitor), an **asymmetric ratchet** runs a fresh Kyber + X25519 exchange, producing $RK_{j+1}$ and reseeding $CK_0^{(j+1)}$. This bounds the damage window of any state compromise to one epoch: after the next asymmetric ratchet, future keys are independent of the compromised state. This is **post-compromise security (PCS)**.

### 6.5 Pseudocode
```text
Algorithm Init-Symmetric-Ratchet
Input: root key RK
Output: initial state (CK_0, i=0)
1: CK_0 <- HMAC(RK, "pqbfl:CK0")
2: return (CK_0, 0)

Algorithm Symmetric-Ratchet-Next
Input: state (CK_i, i)
Output: state (CK_{i+1}, i+1), model key MK_i
1: MK_i    <- HMAC(CK_i, "pqbfl:MK")
2: CK_next <- HMAC(CK_i, "pqbfl:CK")
3: return ((CK_next, i+1), MK_i)

Algorithm Trigger-Asymmetric-Ratchet (when i >= L_j)
Input: current session, threat-adapted L_j
Output: fresh RK_{j+1}, reseeded CK_0^{(j+1)}
1: (ct, ss_k) <- Kyber-Encaps(pk_new)
2: ss_e       <- X25519(a_new, B_new)
3: RK_new     <- HKDF(ss_k, ss_e)
4: CK_0_new   <- HMAC(RK_new, "pqbfl:CK0")
5: replace session.RK, session.CK; reset i to 0; j <- j+1
```

---

## 7) BLAKE3-256 Hashing

### 7.1 Hash definition
A hash function $H: \{0,1\}^* \to \{0,1\}^{256}$ should satisfy:
- preimage resistance,
- second-preimage resistance,
- collision resistance.

BLAKE3 is a tree-hash based on a compression function inherited from BLAKE2 design principles, enabling parallelism and high speed.

### 7.2 Security usage in this project
Used for protocol commitments such as:
- server key bundle hash $h_{pks}$,
- model hash $h_{m0}$,
- task and update metadata hashes,
- nonce seed material (truncated).

### 7.3 Integrity argument
If hashes are collision resistant, then replacing committed content with different content while preserving hash requires finding collision:
$$
H(x) = H(x') \land x \ne x'
$$
which is assumed computationally infeasible.

### 7.4 Step-by-step process

**Step 1 — Compression function.** BLAKE3 uses a compression $f: \{0,1\}^{256} \times \{0,1\}^{512} \times \mathrm{params} \to \{0,1\}^{512}$ derived from BLAKE2's ChaCha-like permutation, with 7 rounds and 4-word quarter-round mixing functions $G$:
$$G(a,b,c,d, m_x, m_y): \quad a \mathrel{+}= b + m_x,\ d \mathrel{\oplus}= a,\ d \lll 16,\ \ldots$$

**Step 2 — Chunking.** Input of length $\ell$ is split into $\lceil \ell / 1024 \rceil$ chunks of 1024 bytes (last chunk may be shorter). Each chunk is processed as a chain of 16 BLAKE3 compression calls on 64-byte blocks.

**Step 3 — Binary tree.** Chunk chaining values form leaves of a binary Merkle tree. Internal nodes are computed via
$$\mathrm{parent}(L, R) = f(\mathrm{IV},\; L \| R,\; \text{PARENT flag})$$
The root chaining value is the final hash, with output extension by XOFing.

**Step 4 — Output of arbitrary length.**
$$\mathrm{BLAKE3}(x, L) = f(\mathrm{root\_cv},\; \langle 0,1,2,\ldots\rangle,\; \text{ROOT}\,\|\,\text{XOF})[0\!:\!L]$$
For $L = 32$ we get the 256-bit digest used throughout PQBFL as `hash32`.

**Step 5 — Collision-resistance argument.** A collision $H(x) = H(x')$, $x \ne x'$, implies either:
1. a collision in the compression $f$, or
2. a Merkle-tree structural collision at some internal node.

Under the assumption that $f$ behaves like a random function (idealized model), the birthday bound gives
$$\Pr[\text{collision in } q \text{ queries}] \leq \frac{q^2}{2 \cdot 2^{256}}$$
so $q \approx 2^{128}$ work is required.

**Step 6 — Commitment binding (project relevance).** A commitment $h = H(x)$ binds $x$ iff $H$ is collision-resistant. Used in PQBFL:
- $h_{pks} = H(\text{kpk}_B \| \text{epk}_B)$ — server public key bundle
- $h_{m0} = H(M_0.\text{to\_bytes}())$ — initial model
- $h_{\text{inf}_b}, h_{\text{inf}_a}$ — round task/update metadata
- nonce seed via truncation: $n = H(\text{aad})[0\!:\!12]$

*Binding theorem.* If adversary opens commitment $h$ to two different preimages $(x, x')$, then $\mathcal{A}$ has found a collision in $H$, contradicting the birthday bound. Hence on-chain $h$ values uniquely fix off-chain content.

### 7.5 Pseudocode
```text
Algorithm BLAKE3-256
Input: byte string X
Output: 32-byte digest h

1: chunks <- Split(X, chunk_size=1024)
2: leaves <- []
3: for chunk in chunks:
4:     cv <- IV
5:     for block in Split(chunk, block_size=64):
6:         cv <- Compress(cv, block, flag=CHUNK)
7:     leaves.append(cv)
8: root <- MerkleTreeReduce(leaves, parent_fn=Compress(., ., flag=PARENT))
9: h    <- Compress(root, IV, flag=ROOT | XOF)[0:32]
10: return h

Algorithm Commit-By-Hash (PQBFL hash32)
Input: byte string X
Output: digest h
1: if HAS_BLAKE3: h <- BLAKE3-256(X)
2: else:          h <- SHA-256(X)        // fallback (§8)
3: return h
```

---

## 8) SHA-256 Hashing

### 8.1 Role in project
SHA-256 is used as fallback when BLAKE3 is unavailable and in toy KEM helper routines.

### 8.2 Merkle-Damgard style overview
SHA-256 processes padded message blocks through iterative compression:
$$
H_i = f(H_{i-1}, M_i)
$$
with final digest $H_t$.

### 8.3 Security claim context
For cryptographic usage, practical attacks do not break full SHA-256 collision/preimage security at relevant security levels. Thus fallback still provides strong commitments.

### 8.4 Step-by-step process

**Step 1 — Padding.** For message $M$ of bit-length $\ell$:
1. Append `1` bit.
2. Append $k$ zero bits where $k$ is smallest non-negative integer with $\ell + 1 + k \equiv 448 \pmod{512}$.
3. Append 64-bit big-endian encoding of $\ell$.
Result length is a multiple of 512.

**Step 2 — Initial hash value.** Eight 32-bit words from fractional parts of square roots of first 8 primes:
$$H_0^{(0)} = \text{0x6a09e667},\; H_1^{(0)} = \text{0xbb67ae85},\; \ldots$$

**Step 3 — Message schedule.** For each 512-bit block $M^{(i)} = (M_0, \ldots, M_{15})$, expand to 64 words:
$$W_t = \begin{cases} M_t & 0 \leq t \leq 15 \\ \sigma_1(W_{t-2}) + W_{t-7} + \sigma_0(W_{t-15}) + W_{t-16} & 16 \leq t \leq 63 \end{cases}$$
with
$$\sigma_0(x) = \mathrm{ROTR}^{7}(x) \oplus \mathrm{ROTR}^{18}(x) \oplus \mathrm{SHR}^{3}(x)$$
$$\sigma_1(x) = \mathrm{ROTR}^{17}(x) \oplus \mathrm{ROTR}^{19}(x) \oplus \mathrm{SHR}^{10}(x)$$

**Step 4 — Compression rounds.** Initialize working variables $a, b, \ldots, h = H_0^{(i-1)}, \ldots, H_7^{(i-1)}$. For $t = 0, \ldots, 63$:
$$T_1 = h + \Sigma_1(e) + \mathrm{Ch}(e,f,g) + K_t + W_t$$
$$T_2 = \Sigma_0(a) + \mathrm{Maj}(a,b,c)$$
$$h \leftarrow g,\; g \leftarrow f,\; f \leftarrow e,\; e \leftarrow d + T_1,\; d \leftarrow c,\; c \leftarrow b,\; b \leftarrow a,\; a \leftarrow T_1 + T_2$$
where $\mathrm{Ch}(x,y,z) = (x \wedge y) \oplus (\neg x \wedge z)$, $\mathrm{Maj}(x,y,z) = (x \wedge y) \oplus (x \wedge z) \oplus (y \wedge z)$, $K_t$ are 64 cube-root constants.

**Step 5 — Feedforward (Davies–Meyer).** Output of block $i$:
$$H_j^{(i)} = H_j^{(i-1)} + a_j^{(\text{final})}\quad (j = 0, \ldots, 7)$$
The addition modulo $2^{32}$ is the Davies–Meyer construction that turns a block cipher / permutation into a one-way compression.

**Step 6 — Output.** $\mathrm{SHA\text{-}256}(M) = H_0^{(N)} \| H_1^{(N)} \| \cdots \| H_7^{(N)}$ where $N$ is the total number of blocks.

**Step 7 — Security bounds (idealized).**
- *Collision resistance:* $\Theta(2^{128})$ work (birthday).
- *Preimage resistance:* $\Theta(2^{256})$ work.
- *Second-preimage resistance:* $\Theta(2^{256})$ work (no length-extension shortcut for full-message preimages).

*Reduction sketch (Merkle–Damgård).* If $f$ is a collision-resistant compression function, then the iterated hash is collision-resistant: a collision $H(M) = H(M')$ propagates back through chaining values to give either equal-length matched blocks, or a final block collision in $f$ itself.

**Step 8 — Project usage.** Used in PQBFL when BLAKE3 wheel is absent, and inside the toy-KEM fallback for deterministic public-key/shared-secret derivation:
$$\mathsf{toy\_pk}(sk) = \mathrm{SHA\text{-}256}(\text{"toy-kem-pk"} \| sk)$$
$$\mathsf{toy\_ss}(ct, pk) = \mathrm{SHA\text{-}256}(\text{"toy-kem-ss"} \| ct \| pk)$$
(These are not PQ-secure; they are only for demo when `pqcrypto` wheel fails to install.)

### 8.5 Pseudocode
```text
Algorithm SHA-256
Input: byte string M
Output: 32-byte digest

1: M' <- Pad(M)                            // append 1, zeros, length
2: blocks <- Split(M', 64)
3: H <- (H0_const, H1_const, ..., H7_const)
4: for block in blocks:
5:     W[0..15]  <- block as 16 BE words
6:     for t = 16..63:
7:         W[t] <- sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
8:     (a,b,c,d,e,f,g,h) <- H
9:     for t = 0..63:
10:        T1 <- h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
11:        T2 <- Sigma0(a) + Maj(a,b,c)
12:        (h,g,f,e,d,c,b,a) <- (g, f, e, d+T1, c, b, a, T1+T2)
13:     H <- H + (a,b,c,d,e,f,g,h)         // word-wise mod 2^32
14: return Concat(H)
```

---

## 9) Boolean Masking (First-order)

### 9.1 Mathematical formulation
Given secret byte vector $k \in \{0,1\}^{8n}$, choose random mask $m \leftarrow_R \{0,1\}^{8n}$ and define:
$$
s_1 = k \oplus m,
\quad
s_2 = m
$$
Reconstruction:
$$
k = s_1 \oplus s_2
$$

### 9.2 First-order leakage argument
If adversary observes only one share (say $s_1$), then for any fixed secret $k$, distribution of $s_1$ is uniform because $m$ uniform implies $k \oplus m$ uniform. Therefore:
$$
I(k; s_1)=0, \quad I(k; s_2)=0
$$
in ideal leakage-free sampling model.

### 9.3 Practical caveat
Real devices leak combined/nonlinear effects and glitches, so higher-order attacks may still recover secrets unless additional countermeasures are applied. Still, first-order masking significantly raises attack complexity.

### 9.4 Step-by-step process

**Step 1 — Sample mask.** For secret $k \in \{0,1\}^{8n}$, sample
$$m \overset{\$}{\leftarrow} \{0,1\}^{8n}$$
uniformly with a CSPRNG. In the code this is `np.random.randint(0, 256, size=n, dtype=uint8)`, conceptually $m \sim \mathcal{U}([0, 255]^n)$.

**Step 2 — Split into shares.**
$$s_1 = k \oplus m, \qquad s_2 = m$$
Invariant: $s_1 \oplus s_2 = k$, but neither $s_1$ alone nor $s_2$ alone reveals $k$.

**Step 3 — Operate on shares.** Cryptographic primitives that consume $k$ are re-architected so that intermediate computations touch only $s_1$ or only $s_2$ at a time, never both simultaneously. In the PQBFL simulation this is approximated by feeding `simulate_trace(s1.tobytes())` and `simulate_trace(s2.tobytes())` to separate trace arrays.

**Step 4 — Recombine securely.** When the primitive **must** combine shares (e.g. for actual key use), the recombination is gated by `apply_defense` adding noise + jitter, raising the SNR floor for any side-channel observer.

**Step 5 — Information-theoretic proof of first-order security.**

*Claim.* For any fixed secret $k \in \{0,1\}^{8n}$ and any single share $s_b$ ($b \in \{1,2\}$):
$$\mathrm{H}(s_b) = 8n,\qquad I(k;\, s_b) = 0.$$

*Proof.*
Case $b = 2$: $s_2 = m$ is independent of $k$ by construction, so $I(k; s_2) = 0$.

Case $b = 1$: For any specific value $v \in \{0,1\}^{8n}$,
$$\Pr[s_1 = v \mid k] = \Pr[k \oplus m = v \mid k] = \Pr[m = k \oplus v] = 2^{-8n}$$
because $m$ is uniform and the bijection $m \mapsto k \oplus m$ preserves uniformity. Hence $s_1$ is uniform on $\{0,1\}^{8n}$ independent of $k$, giving $I(k; s_1) = 0$. $\square$

**Step 6 — First-order DPA failure.** A first-order Differential Power Analysis attacker correlates leakage $L_i$ at sample $i$ with a key hypothesis $\hat{k}$. Under the leakage model $L_i = \phi(s_{b,i}) + \eta_i$ with $\eta_i$ Gaussian noise:
$$\mathrm{Cov}(\phi(s_b), \hat{k}) = \mathbb{E}[\phi(s_b)\hat{k}] - \mathbb{E}[\phi(s_b)] \mathbb{E}[\hat{k}]$$
Since $s_b$ is independent of $k$ (Step 5), $\mathbb{E}[\phi(s_b) \hat{k}] = \mathbb{E}[\phi(s_b)] \mathbb{E}[\hat{k}]$, hence covariance is zero. So **no first-order statistic discriminates the correct $k$**.

**Step 7 — Higher-order caveat.** A second-order attacker combines leakages from both shares, e.g.
$$L_1 \cdot L_2,\quad (L_1 - \bar{L_1})(L_2 - \bar{L_2}),\quad \text{or}\quad L_1 + L_2$$
If $\phi$ is the Hamming weight,
$$\phi(s_1) + \phi(s_2) = \phi(k \oplus m) + \phi(m)$$
which **does** depend on $k$ in expectation (by the identity $\phi(k \oplus m) + \phi(m) = \phi(k) + 2 \phi(\bar{k} \wedge m) - 2 \phi(k \wedge m) + \phi(k)$). The mutual information leaks at the second order. PQBFL counters this with `apply_defense` (additional Gaussian noise + temporal jitter, §10) so that the second-order SNR is also crushed.

**Step 8 — Number of traces to break.** Under noise standard deviation $\sigma$ and signal $|\mu_1 - \mu_0|$, the number of traces $N$ needed to succeed at first-order DPA scales as
$$N \propto \frac{\sigma^2}{(\mu_1 - \mu_0)^2}$$
Masking + noise reduces $|\mu_1 - \mu_0|$ to second-order; the corresponding higher-order attack needs
$$N \propto \frac{\sigma^4}{(\mu_1 - \mu_0)^4}$$
growing **quadratically** with noise. This is the fundamental security/cost gain.

### 9.5 Pseudocode
```text
Algorithm Boolean-Mask
Input: secret bytes K (length n)
Output: shares (S1, S2)
1: M  <- CSPRNG.UniformBytes(n)
2: S1 <- K XOR M
3: S2 <- M
4: return (S1, S2)

Algorithm Recombine
Input: shares (S1, S2)
Output: K
1: return S1 XOR S2

Algorithm Masked-Primitive (template)
Input: secret K, operation Op
Output: result, side-channel traces
1: (S1, S2) <- Boolean-Mask(K)
2: trace_1  <- SimulateTrace(S1)
3: trace_2  <- SimulateTrace(S2)
4: trace_combined <- ApplyDefense(trace_1 + trace_2, mode="adaptive")
5: result   <- Op(K)                       // actual primitive call
6: return (result, trace_combined)
```

---

## 10) Hamming-Weight Leakage Simulation Model

### 10.1 Model equation
For byte sequence $d = (d_1,\dots,d_n)$ define ideal leakage:
$$
\ell_i = HW(d_i)
$$
where $HW(b)$ counts set bits in byte $b$.

Noisy trace model:
$$
T_i = HW(d_i) + N_i, \quad N_i \sim \mathcal{N}(0,\sigma^2)
$$
Optional timing jitter as cyclic shift:
$$
T' = \mathsf{Roll}(T, \Delta), \quad \Delta \in \{0,1,2,\dots\}
$$

### 10.2 Why this model is useful
It approximates CMOS dynamic power where switching activity correlates with Hamming weight/distance. Not physically complete, but standard for evaluating side-channel countermeasure trends.

### 10.3 Statistical distinguisher intuition
Suppose two hypotheses $H_0,H_1$ correspond to different predicted Hamming weights at sample $i$. With Gaussian noise, likelihood ratio test thresholding yields error probability decreasing as:
$$
P_e \approx Q\left(\frac{|\mu_1-\mu_0|}{2\sigma}\right)
$$
where $\mu_j$ are expected means. Increasing $\sigma$ (noise defense) or reducing mean gap (masking/randomization) increases attacker error.

### 10.4 Step-by-step process

**Step 1 — Hamming weight.** For byte $b \in \{0,1\}^8$:
$$\mathrm{HW}(b) = \sum_{j=0}^{7} b_j \in \{0, 1, \ldots, 8\}$$
For uniform $b$, $\mathrm{HW}(b)$ is binomial $\mathrm{Bin}(8, 1/2)$ with mean $4$ and variance $2$.

**Step 2 — Per-byte leakage.** At sample index $i$ corresponding to byte $d_i$:
$$\ell_i = \mathrm{HW}(d_i)$$
*Justification.* In CMOS dynamic-power leakage models, the energy drawn during a register write of $d_i$ is approximately proportional to the number of bit transitions, which (assuming uniform prior state) is approximately $\mathrm{HW}(d_i)$ up to additive constants.

**Step 3 — Additive Gaussian noise.**
$$T_i = \ell_i + N_i, \qquad N_i \overset{\text{iid}}{\sim} \mathcal{N}(0, \sigma^2)$$
In the code, `noise_std=1.0` by default.

**Step 4 — Optional cyclic jitter.** If jitter flag set,
$$\Delta \overset{\$}{\leftarrow} \{0, 1, 2\}, \qquad T'_i = T_{(i - \Delta) \bmod n}$$
This simulates clock jitter / pipeline misalignment that desynchronizes traces from secret-dependent samples.

**Step 5 — Distinguisher analysis (first-order CPA).** Adversary correlates $T_i$ against predicted leakage $\hat{\ell}_i = \mathrm{HW}(\hat{d}_i)$ under guess $\hat{k}$:
$$\rho = \frac{\mathrm{Cov}(T, \hat{\ell})}{\sqrt{\mathrm{Var}(T) \cdot \mathrm{Var}(\hat{\ell})}}$$
For correct guess: $\hat{\ell} = \ell$, so
$$\mathrm{Cov}(T, \ell) = \mathrm{Cov}(\ell + N, \ell) = \mathrm{Var}(\ell) = 2$$
$$\mathrm{Var}(T) = \mathrm{Var}(\ell) + \sigma^2 = 2 + \sigma^2$$
$$\rho^{\text{correct}} = \frac{2}{\sqrt{2(2 + \sigma^2)}} = \sqrt{\frac{2}{2 + \sigma^2}}$$
For incorrect guess: $\hat{\ell}$ is independent of $\ell$, so $\rho^{\text{wrong}} \to 0$ as $N \to \infty$.

**Step 6 — Traces required.** Mangard's formula for the number of traces $N^*$ needed to distinguish correct from wrong guess with confidence $\alpha$:
$$N^* \approx \left(\frac{Z_\alpha + Z_\beta}{\rho^{\text{correct}}}\right)^2 = c \cdot \frac{2 + \sigma^2}{2}$$
for some constant $c \approx 28$ at $\alpha = \beta = 0.9999$. Hence trace count grows **linearly in $\sigma^2$**.

**Step 7 — Effect of jitter on distinguisher.** When $\Delta$ is unknown, the attacker must search over alignment, multiplying work by $|\{\Delta\}|$ AND smearing the signal. For uniform $\Delta \in \{0, 1, 2\}$ the effective signal at any fixed sample $i$ is
$$\mathbb{E}[T'_i \mid k] = \frac{1}{3}\bigl(\ell_i + \ell_{i-1} + \ell_{i-2}\bigr)$$
averaging in adjacent (potentially uncorrelated) values, which approximately halves the per-sample variance attributable to $k$. This roughly doubles $N^*$ in addition to the search penalty.

**Step 8 — Composition with masking.** When the data being traced is already masked (§9), $d_i$ is a uniform share independent of $k$, so $\mathbb{E}[\ell_i] = 4$ and $\mathrm{Var}(\ell_i) = 2$ are **constants** with no dependence on $k$. First-order $\rho^{\text{correct}} = 0$. The attacker must move to second order, combining two share-traces (Step 7 of §9), at which point the cost is
$$N^*_{(2)} = \Theta\left(\frac{\sigma^4}{(\mu_1 - \mu_0)^4}\right)$$
This is exactly the **quadratic blow-up** that motivates the SC-resistant design.

**Step 9 — Defense modes (`apply_defense`).** The code implements three escalation levels:
| Mode | Additive noise | Jitter |
|------|---------------|--------|
| `"masking"` | $\mathcal{N}(0, 0.5^2)$ | no |
| `"noise"` | $\mathcal{N}(0, 2.0^2)$ | no |
| `"adaptive"` | $\mathcal{N}(0, 2.5^2)$ | `Roll(., U\{1..4\})` |

The `"adaptive"` mode is what the threat monitor selects when threat level is high — combining noise injection with temporal jitter for both first-order and second-order attack mitigation.

### 10.5 Pseudocode
```text
Algorithm Simulate-Trace
Input: data bytes D (length n), noise std sigma, jitter flag
Output: trace T (length n)

1: T <- zeros(n)
2: for i = 0..n-1:
3:     base    <- HammingWeight(D[i])
4:     noise_i <- Gaussian(mean=0, std=sigma)
5:     T[i]    <- base + noise_i
6: if jitter:
7:     delta <- UniformInt(0, 3)
8:     T     <- CyclicShift(T, delta)
9: return T

Algorithm Apply-Defense
Input: trace T, mode in {"none", "masking", "noise", "adaptive"}
Output: defended trace T'

1: switch mode:
2:   case "masking":   T' <- T + Gaussian(0, 0.5,  shape=len(T))
3:   case "noise":     T' <- T + Gaussian(0, 2.0,  shape=len(T))
4:   case "adaptive":  T' <- T + Gaussian(0, 2.5,  shape=len(T))
5:                     T' <- CyclicShift(T', UniformInt(1, 5))
6:   default:          T' <- T
7: return T'
```

---

## 11) Additive Gaussian Noise Defense (multiple sigma levels)

### 11.1 Threat model
First-order DPA/CPA distinguishers exploit the correlation between leakage $T_i = \ell_i + N_i$ and predicted key-dependent leakage $\hat{\ell}_i$. Their success probability is monotone in the **signal-to-noise ratio** (SNR):
$$\mathrm{SNR} = \frac{\mathrm{Var}(\ell)}{\mathrm{Var}(N)} = \frac{\mathrm{Var}(\ell)}{\sigma^2}$$

### 11.2 Defense definition
The defender adds **extra** zero-mean Gaussian noise $W_i \sim \mathcal{N}(0, \sigma_d^2)$ post-hoc to the observed trace:
$$T'_i = T_i + W_i = \ell_i + N_i + W_i$$
The total noise becomes $N'_i \sim \mathcal{N}(0, \sigma^2 + \sigma_d^2)$ (sum of independent Gaussians).

### 11.3 SNR degradation (proof)
*Claim.* If the defender injects $W_i \sim \mathcal{N}(0, \sigma_d^2)$ then
$$\mathrm{SNR}' = \frac{\mathrm{Var}(\ell)}{\sigma^2 + \sigma_d^2} < \mathrm{SNR}$$

*Proof.* By independence of $\ell, N, W$:
$$\mathrm{Var}(T') = \mathrm{Var}(\ell) + \mathrm{Var}(N) + \mathrm{Var}(W) = \mathrm{Var}(\ell) + \sigma^2 + \sigma_d^2$$
$$\mathrm{Cov}(T', \ell) = \mathrm{Var}(\ell)$$
$$\rho' = \frac{\mathrm{Var}(\ell)}{\sqrt{\mathrm{Var}(\ell)\,(\mathrm{Var}(\ell) + \sigma^2 + \sigma_d^2)}} = \sqrt{\frac{\mathrm{Var}(\ell)}{\mathrm{Var}(\ell) + \sigma^2 + \sigma_d^2}}\;\;\square$$

### 11.4 Trace-count multiplier
From Mangard's relation $N^* = c/\rho^2$:
$$N^*_{\text{defended}} = N^*_{\text{baseline}} \cdot \frac{\mathrm{Var}(\ell) + \sigma^2 + \sigma_d^2}{\mathrm{Var}(\ell) + \sigma^2}$$
For Hamming-weight ($\mathrm{Var}(\ell) = 2$) and baseline $\sigma^2 = 1$:
| Mode | $\sigma_d$ | Effective $\sigma'^2$ | Trace multiplier |
|------|-----------|----------------------|------------------|
| baseline | 0.0 | 1.0 | $1\times$ |
| `"masking"` | 0.5 | 1.25 | $1.08\times$ |
| `"noise"`   | 2.0 | 5.0 | $2.33\times$ |
| `"adaptive"`| 2.5 | 7.25 | $3.08\times$ (× jitter penalty, see §12) |

### 11.5 Why three sigma levels (escalation policy)
The threat monitor (§14) maps current threat level $t \in [0, 1]$ to a defense mode. Low threat costs almost nothing (`"masking"` $\sigma_d = 0.5$); high threat applies maximum noise (`"adaptive"` $\sigma_d = 2.5$). This is a **utility–security trade-off**: bigger $\sigma_d$ wastes more compute on entropy injection.

### 11.6 Information-theoretic limit
By the data processing inequality, $I(k; T') \leq I(k; T)$. As $\sigma_d \to \infty$,
$$I(k; T') \to 0$$
since $T'$ becomes asymptotically independent of $k$. The defender's lever is monotone: increasing $\sigma_d$ never helps the attacker.

### 11.7 Pseudocode
```text
Algorithm Apply-Gaussian-Noise
Input: trace T (length n), sigma_d
Output: defended trace T'
1: W  <- Gaussian(mean=0, std=sigma_d, shape=n)
2: T' <- T + W
3: return T'

Algorithm Tiered-Noise-Defense
Input: trace T, mode
Output: T'
1: sigma_d <- {"none":0, "masking":0.5, "noise":2.0, "adaptive":2.5}[mode]
2: if sigma_d == 0: return T
3: return Apply-Gaussian-Noise(T, sigma_d)
```

---

## 12) Jitter / Trace-Shift Defense (`np.roll`-based)

### 12.1 Misalignment model
Standard DPA assumes traces are **temporally aligned**: sample $i$ of every trace corresponds to the same clock cycle. A jitter defense randomly perturbs alignment per trace:
$$T'_j = \mathrm{Roll}(T_j, \Delta_j),\qquad \Delta_j \overset{\text{iid}}{\sim} \mathcal{U}\{0, 1, \ldots, \Delta_{\max}\}$$
where $\mathrm{Roll}$ is cyclic shift. In code: `np.roll(trace, random.randint(1, 5))`.

### 12.2 Effect on first-order distinguisher
*Claim.* Under uniform $\Delta \in \{0, 1, \ldots, J-1\}$, the effective per-sample signal variance attributable to $k$ is reduced by factor $1/J$ in the worst case.

*Proof sketch.* Let $\bar\ell_i = \mathbb{E}_\Delta[\ell_{(i - \Delta) \bmod n}] = \frac{1}{J} \sum_{\delta=0}^{J-1} \ell_{(i-\delta) \bmod n}$. The conditional variance of $T'_i$ given $k$ is
$$\mathrm{Var}(T'_i \mid k) = \frac{1}{J} \sum_{\delta=0}^{J-1} \ell_{(i-\delta)}^2 - \bar\ell_i^{\,2} + \sigma^2$$
Across distinct $k$, the per-sample mean differs only through $\bar\ell_i$, which is the **average** of $J$ samples. If those $J$ samples have weak mutual correlation w.r.t. $k$, the discriminating signal squared shrinks by $\sim 1/J$. $\square$

### 12.3 Combined cost with noise (§11)
Number of traces to attack:
$$N^*_{\text{noise+jitter}} \;\approx\; N^*_{\text{baseline}} \cdot \frac{\sigma^2 + \sigma_d^2}{\sigma^2} \cdot J$$
The two defenses compose **multiplicatively**.

### 12.4 Realignment attack and limit
A sophisticated adversary may run preprocessing (cross-correlation alignment, sliding-window POI search) to recover $\Delta_j$ per trace, partially undoing jitter. With $M$ candidate offsets and $N$ traces, alignment search cost is $O(M \cdot N)$ and success degrades when:
- $\Delta_{\max}$ is large (search space grows),
- traces are noisy (Step 11 noise interferes with alignment),
- jitter is non-cyclic / mixed with insertion-deletion (the `np.roll` choice keeps it cyclic, so partial defense).

This is why the `"adaptive"` mode combines **both** higher $\sigma_d$ **and** jitter — they protect different attack classes.

### 12.5 Pseudocode
```text
Algorithm Apply-Jitter
Input: trace T, jitter range J_max
Output: defended trace T'
1: delta <- UniformInt(1, J_max + 1)
2: T'    <- CyclicShift(T, delta)        // np.roll(T, delta)
3: return T'

Algorithm Combined-Noise-Plus-Jitter (used in "adaptive" mode)
Input: trace T
Output: T''
1: T'  <- Apply-Gaussian-Noise(T,  sigma_d = 2.5)
2: T'' <- Apply-Jitter(T', J_max = 4)
3: return T''
```

---

## 13) Adaptive Ratchet Threshold Mapping (power-curve policy for $L_j$)

### 13.1 Problem
The symmetric ratchet (§6) advances key material every step. Triggering a costly asymmetric (Kyber+ECDH) ratchet every step is wasteful; never triggering it kills post-compromise security. We need a **threshold** $L_j$ (steps per epoch) that adapts to runtime threat level $t \in [0, 1]$.

### 13.2 Design constraints
1. $L_j(t) \in [L_{\min}, L_{\max}]$ (bounded).
2. $L_j(0) = L_{\max}$ (relaxed: many symmetric steps allowed).
3. $L_j(1) = L_{\min}$ (paranoid: re-key almost every step).
4. $L_j$ should be **monotone decreasing** in $t$.
5. Sensitivity tunable: gentle near $t \approx 0$, sharp drop as $t \to 1$.

### 13.3 Power-curve mapping
The chosen formula (`compute_L_j` in `adaptive_ratchet.py`):
$$L_j(t) = L_{\max} - (L_{\max} - L_{\min}) \cdot t^{\,\kappa}$$
where $\kappa > 0$ is the sensitivity exponent. Equivalent form:
$$L_j(t) = L_{\min} + (L_{\max} - L_{\min}) \cdot (1 - t^{\,\kappa})$$

### 13.4 Properties (proofs)

**(P1) Boundary correctness.**
- $L_j(0) = L_{\max} - 0 = L_{\max}$. ✓
- $L_j(1) = L_{\max} - (L_{\max} - L_{\min}) = L_{\min}$. ✓

**(P2) Monotonicity.** Compute derivative:
$$\frac{d L_j}{d t} = -\kappa (L_{\max} - L_{\min}) \cdot t^{\,\kappa - 1}$$
For $t \in (0,1)$ and $\kappa > 0$, $t^{\kappa-1} > 0$, so $L_j' < 0$. ✓ (Strictly decreasing.)

**(P3) Sensitivity shape.**
- $\kappa = 1$: linear interpolation.
- $\kappa > 1$ (e.g. 2.0): **convex** — $L_j$ stays near $L_{\max}$ for small $t$, then drops sharply near $t \to 1$ ("relaxed under uncertainty, panic at confirmed attack").
- $\kappa < 1$ (e.g. 0.5): **concave** — drops sharply at small $t$ ("paranoid: any anomaly triggers fast re-key").

**(P4) Cooldown stability.** To avoid oscillation when $t$ flips rapidly, `evaluate(t, round)` only commits a change when
$$|r - r_{\text{last}}| \geq r_{\text{cool}}$$
where $r_{\text{cool}} = $ `cooldown_rounds`. This is a low-pass filter on the policy output.

### 13.5 Effective threshold (conservative override)
At each round the effective threshold used by `should_ratchet` is the **min** of currently stored and freshly computed:
$$L_j^{\text{eff}} = \min\bigl(L_j^{\text{current}},\, L_j(t)\bigr)$$
This ensures threat spikes immediately tighten the threshold, while cooldown delays relaxation.

### 13.6 Worked example
With $L_{\min} = 1$, $L_{\max} = 16$, $\kappa = 2$:
| Threat $t$ | $t^2$ | $L_j(t)$ |
|-----------|-------|----------|
| 0.0 | 0.00 | 16 |
| 0.2 | 0.04 | 15.4 → 15 |
| 0.5 | 0.25 | 12.25 → 12 |
| 0.8 | 0.64 | 6.4 → 6 |
| 1.0 | 1.00 | 1 |

Under benign operation ($t < 0.2$), only one asymmetric ratchet per ~15 rounds. Under active attack ($t > 0.8$), every ~5 rounds.

### 13.7 Pseudocode
```text
Algorithm Compute-L_j
Input: threat level t in [0,1], L_min, L_max, sensitivity kappa
Output: L_j(t) (integer)
1: t <- clamp(t, 0.0, 1.0)
2: span <- L_max - L_min
3: reduction <- span * (t ^ kappa)
4: L <- L_max - reduction
5: return max(L_min, round(L))

Algorithm Evaluate-Policy
Input: threat level t, round number r, state, kappa, cooldown
Output: current L_j
1: ideal <- Compute-L_j(t, ...)
2: if |r - state.last_change_round| < cooldown:
3:     return state.current_L_j
4: if ideal != state.current_L_j:
5:     state.adjustments.append(record(old, new, t, r))
6:     state.current_L_j <- ideal
7:     state.last_change_round <- r
8: return state.current_L_j

Algorithm Should-Ratchet
Input: current step i, stored L_j, threat t
Output: bool
1: adaptive_L <- Compute-L_j(t, ...)
2: effective  <- min(L_j, adaptive_L)
3: return i >= effective
```

---

## 14) Exponential-Decay Weighted Threat Scoring

### 14.1 Event stream
Each detected anomaly is recorded as
$$e = (\tau,\; \mathrm{type},\; s,\; r,\; \text{detail})$$
where $\tau$ is wall-clock timestamp, $s \in [0, 1]$ severity, $\mathrm{type} \in \{\text{SIG\_FAIL}, \text{HASH\_MISMATCH}, \text{REPUTATION\_DROP}, \text{TIMING}, \text{STALE\_RATCHET}\}$, $r$ FL round. Each type has a static weight $w_{\mathrm{type}} \in [0,1]$ (e.g. SIG_FAIL = 1.0, STALE = 0.3).

### 14.2 Score formula
At query time $\tau_0$, define the **window** $\mathcal{W} = \{e : \tau_e \geq \tau_0 - W\}$ for window $W$ seconds. For each event define **decay**:
$$d_e = 2^{-(\tau_0 - \tau_e)/H}$$
where $H$ is the half-life in seconds. Composite threat level:
$$\boxed{\;t(\tau_0) = \frac{\sum_{e \in \mathcal{W}} d_e \cdot w_{\mathrm{type}(e)} \cdot s_e}{\sum_{e \in \mathcal{W}} d_e \cdot w_{\mathrm{type}(e)}} \in [0, 1]\;}$$
If denominator is zero (no events), $t = 0$.

### 14.3 Properties (proofs)

**(P1) Range.** Each $s_e \in [0,1]$ and all weights $\geq 0$, so the weighted average $t \in [0, 1]$ by the convex-combination argument:
$$t = \sum_e \underbrace{\frac{d_e w_{\mathrm{type}(e)}}{\sum_{e'} d_{e'} w_{\mathrm{type}(e')}}}_{\geq 0,\ \sum = 1} s_e \leq \max_e s_e \leq 1$$

**(P2) Decay rate.** After half-life $H$:
$$d_e(\tau_0 + H) = 2 \cdot d_e(\tau_0)^{-1}\cdot d_e(\tau_0) / 2 = \tfrac{1}{2} d_e(\tau_0)$$
Wait let's redo it cleanly:
$$d_e(\tau_0 + H) = 2^{-(\tau_0 + H - \tau_e)/H} = 2^{-1} \cdot 2^{-(\tau_0 - \tau_e)/H} = \tfrac{1}{2}\, d_e(\tau_0)$$
i.e. each event's contribution halves every $H$ seconds. This is the **exponential-decay** property.

**(P3) Recency dominance.** Two events with same $s, w_{\mathrm{type}}$ but different ages $a_1 < a_2$ contribute weights $2^{-a_1/H}$ vs $2^{-a_2/H}$. The ratio is $2^{(a_2 - a_1)/H} > 1$, so recent events dominate.

**(P4) Window cutoff.** Events older than $W$ contribute zero. This bounds memory and prevents stale data from polluting current threat estimate. The combination of $W$ (hard cutoff) and $H$ (soft decay) gives a two-parameter shape: $H \ll W$ for sharp recency, $H \approx W$ for smooth averaging.

### 14.4 Why type-weights and severity multiply
A SIG_FAIL event with low severity (e.g. retried success on second attempt) is still concerning ($w = 1.0$), so $w \cdot s$ keeps weight high. Conversely a STALE_RATCHET ($w = 0.3$) with severity 0.5 contributes less to threat. The multiplicative form is the canonical Bayes-style combination of "prior risk class" × "observed severity".

### 14.5 Numerical example
Three events at query time $\tau_0$, $H = 120s$, $W = 300s$:
| Event | Age | $d_e$ | $w$ | $s$ | $d \cdot w \cdot s$ | $d \cdot w$ |
|-------|----:|------:|----:|----:|--------------------:|------------:|
| SIG_FAIL  |  10s | 0.944 | 1.0 | 0.95 | 0.897 | 0.944 |
| TIMING    |  90s | 0.595 | 0.4 | 0.70 | 0.167 | 0.238 |
| REP_DROP  | 200s | 0.314 | 0.6 | 0.50 | 0.094 | 0.188 |
| **sum**   |       |       |     |      | **1.158** | **1.370** |

$$t(\tau_0) = 1.158 / 1.370 \approx 0.85$$
This value feeds directly into $L_j(t)$ from §13.

### 14.6 Pseudocode
```text
Algorithm Record-Event
Input: type, severity s (in [0,1]), round r, detail, monitor M
1: tau <- now()
2: M.events.append((tau, type, s, r, detail))

Algorithm Get-Threat-Level
Input: monitor M, current time tau_0, window W, half-life H
Output: t in [0,1]
1: num <- 0
2: den <- 0
3: for e in M.events:
4:     if tau_0 - e.tau > W: continue        // outside window
5:     decay <- 2.0 ^ (-(tau_0 - e.tau) / H)
6:     w     <- M.weights[e.type]
7:     num   <- num + decay * w * e.severity
8:     den   <- den + decay * w
9: if den == 0: return 0.0
10: return clamp(num / den, 0.0, 1.0)
```

---

## 15) Logistic Regression

### 15.1 Model
For input $\mathbf{x} \in \mathbb{R}^d$, weights $\mathbf{w} \in \mathbb{R}^d$, bias $b \in \mathbb{R}$:
$$p(y=1 \mid \mathbf{x}) = \sigma(\mathbf{w}^\top \mathbf{x} + b),\qquad \sigma(z) = \frac{1}{1 + e^{-z}}$$
Binary prediction: $\hat{y} = \mathbb{1}[\sigma(\cdot) \geq 0.5] = \mathbb{1}[\mathbf{w}^\top \mathbf{x} + b \geq 0]$.

### 15.2 Loss function (negative log-likelihood)
For dataset $\mathcal{D} = \{(\mathbf{x}_i, y_i)\}_{i=1}^N$, $y_i \in \{0, 1\}$:
$$\mathcal{L}(\mathbf{w}, b) = -\frac{1}{N} \sum_{i=1}^N \Bigl[y_i \log p_i + (1 - y_i) \log(1 - p_i)\Bigr]$$
where $p_i = \sigma(\mathbf{w}^\top \mathbf{x}_i + b)$.

### 15.3 Gradient derivation
Let $z_i = \mathbf{w}^\top \mathbf{x}_i + b$ and $p_i = \sigma(z_i)$.

**Step 1.** Sigmoid derivative:
$$\sigma'(z) = \sigma(z)(1 - \sigma(z))$$

**Step 2.** Per-sample loss:
$$\ell_i = -y_i \log p_i - (1 - y_i) \log(1 - p_i)$$

**Step 3.** Chain rule:
$$\frac{\partial \ell_i}{\partial z_i} = -\frac{y_i}{p_i} \cdot p_i(1-p_i) + \frac{1 - y_i}{1 - p_i} \cdot p_i(1-p_i)$$
$$= -y_i(1 - p_i) + (1 - y_i) p_i = p_i - y_i$$

**Step 4.** Hence:
$$\boxed{\frac{\partial \mathcal{L}}{\partial \mathbf{w}} = \frac{1}{N} \sum_{i=1}^N (p_i - y_i)\, \mathbf{x}_i,\qquad \frac{\partial \mathcal{L}}{\partial b} = \frac{1}{N} \sum_{i=1}^N (p_i - y_i)}$$
This is the universally clean "error × input" rule used in `train_sgd`.

### 15.4 Convexity (proof of well-posedness)
The Hessian:
$$\nabla^2 \mathcal{L}(\mathbf{w}) = \frac{1}{N} \sum_i p_i(1 - p_i)\, \mathbf{x}_i \mathbf{x}_i^\top = \frac{1}{N} \mathbf{X}^\top \mathbf{S} \mathbf{X}$$
where $\mathbf{S}$ is diagonal with positive entries $p_i(1-p_i) \in (0, 1/4]$. Hence $\nabla^2 \mathcal{L} \succeq 0$ (positive semi-definite), so $\mathcal{L}$ is **convex**. Any local minimum is a global minimum.

### 15.5 Project implementation details
`predict_proba` clamps $z$ to $\pm 50$ before exponentiation to avoid `np.exp` overflow:
$$\tilde{z} = \mathrm{clip}(z, -50, 50)$$
This preserves the asymptotic value of $\sigma$ since $\sigma(50) \approx 1 - 2 \cdot 10^{-22}$.

### 15.6 Pseudocode
```text
Algorithm Logistic-Predict
Input: weights w, bias b, input x
Output: probability p
1: z <- clip(w . x + b, -50, +50)
2: p <- 1 / (1 + exp(-z))
3: return p

Algorithm Logistic-Loss-And-Gradient
Input: weights w, bias b, batch (X, y)
Output: loss, grad_w, grad_b
1: p     <- sigma(X @ w + b)
2: loss  <- -mean(y * log(p) + (1-y) * log(1-p))
3: err   <- p - y                              // shape (N,)
4: grad_w <- (X^T @ err) / N
5: grad_b <- mean(err)
6: return (loss, grad_w, grad_b)
```

---

## 16) Mini-Batch Stochastic Gradient Descent

### 16.1 Optimization problem
Minimize $\mathcal{L}(\mathbf{w}, b)$ from §15. Full-batch gradient descent uses all $N$ samples each step. Stochastic GD uses one. **Mini-batch** uses $B$ samples per step ($B \ll N$).

### 16.2 Update rule
At iteration $t$ pick batch $\mathcal{B}_t \subset \{1, \ldots, N\}$ with $|\mathcal{B}_t| = B$:
$$\hat{g}_t = \frac{1}{B} \sum_{i \in \mathcal{B}_t} (p_i - y_i)\, \mathbf{x}_i$$
$$\mathbf{w}_{t+1} = \mathbf{w}_t - \eta\, \hat{g}_t$$
where $\eta > 0$ is the learning rate.

### 16.3 Unbiasedness (proof)
*Claim.* If $\mathcal{B}_t$ is uniformly random without replacement of size $B$:
$$\mathbb{E}[\hat{g}_t \mid \mathbf{w}_t] = \nabla \mathcal{L}(\mathbf{w}_t)$$

*Proof.* By linearity of expectation, for each $i \in \{1, \ldots, N\}$, $\Pr[i \in \mathcal{B}_t] = B/N$. So
$$\mathbb{E}\Bigl[\sum_{i \in \mathcal{B}_t} (p_i - y_i) \mathbf{x}_i\Bigr] = \sum_{i=1}^N \frac{B}{N} (p_i - y_i) \mathbf{x}_i = \frac{B}{N} \cdot N \cdot \nabla \mathcal{L}$$
Dividing by $B$: $\mathbb{E}[\hat{g}_t] = \nabla \mathcal{L}(\mathbf{w}_t)$. $\square$

### 16.4 Variance scaling
Under independence approximation,
$$\mathrm{Var}(\hat{g}_t) = \frac{1}{B}\, \mathrm{Var}_{i \sim \mathcal{U}}\bigl[(p_i - y_i)\mathbf{x}_i\bigr]$$
i.e. variance shrinks as $1/B$. **Trade-off:**
- Small $B$ → fast iterations, noisy gradient (helps escape flat regions).
- Large $B$ → smoother gradient, slower iterations.

### 16.5 Convergence theorem (convex case)
For convex Lipschitz objective with step size $\eta = O(1/\sqrt{T})$, $T$ iterations of mini-batch SGD satisfies:
$$\mathbb{E}\bigl[\mathcal{L}(\bar{\mathbf{w}}_T) - \mathcal{L}(\mathbf{w}^*)\bigr] = O\!\left(\frac{1}{\sqrt{T}}\right)$$
where $\bar{\mathbf{w}}_T$ is the averaged iterate. With strong convexity, rate improves to $O(1/T)$.

### 16.6 Project implementation
`train_sgd(x, y, lr, epochs, batch_size, l2, seed)`:
1. Shuffle indices each epoch with seeded RNG.
2. Iterate over $\lceil N/B \rceil$ batches.
3. Compute gradient as in §15.6, **add L2 term** (§17), update weights.

### 16.7 Pseudocode
```text
Algorithm Mini-Batch-SGD
Input: data (X, y), init w, b, lr eta, epochs E, batch size B, l2 lambda, seed
Output: trained w, b
1: rng <- RNG(seed)
2: N   <- len(X)
3: for epoch = 1..E:
4:     idx <- rng.permutation(N)
5:     for start = 0, B, 2B, ..., N - 1:
6:         batch <- idx[start : start + B]
7:         Xb, yb <- X[batch], y[batch]
8:         p      <- sigma(Xb @ w + b)
9:         err    <- p - yb
10:        grad_w <- (Xb^T @ err) / |batch| + lambda * w     // §17
11:        grad_b <- mean(err)
12:        w <- w - eta * grad_w
13:        b <- b - eta * grad_b
14: return (w, b)
```

---

## 17) L2 Regularization

### 17.1 Penalized objective
Add a quadratic penalty on weights:
$$\mathcal{L}_{\text{reg}}(\mathbf{w}, b) = \mathcal{L}(\mathbf{w}, b) + \frac{\lambda}{2} \|\mathbf{w}\|_2^2$$
with $\lambda \geq 0$ controlling regularization strength. Bias $b$ is conventionally **not** penalized (matches `train_sgd`).

### 17.2 Effect on gradient
$$\nabla_{\mathbf{w}} \mathcal{L}_{\text{reg}} = \nabla_{\mathbf{w}} \mathcal{L} + \lambda \mathbf{w}$$
Update becomes:
$$\mathbf{w}_{t+1} = \mathbf{w}_t - \eta\,(\hat{g}_t + \lambda \mathbf{w}_t) = (1 - \eta \lambda) \mathbf{w}_t - \eta \hat{g}_t$$
This is **weight decay**: a multiplicative shrinkage factor $(1 - \eta \lambda)$ each step.

### 17.3 Bayesian interpretation
L2 regularization corresponds to a **Gaussian prior** $\mathbf{w} \sim \mathcal{N}(\mathbf{0}, \tau^2 I)$ with $\tau^2 = 1/(N\lambda)$. The MAP estimate equals the L2-regularized MLE:
$$\hat{\mathbf{w}}_{\text{MAP}} = \arg\min_{\mathbf{w}} \Bigl[-\log p(\mathcal{D} \mid \mathbf{w}) - \log p(\mathbf{w})\Bigr] = \arg\min_{\mathbf{w}} \Bigl[N\mathcal{L}(\mathbf{w}) + \frac{1}{2\tau^2}\|\mathbf{w}\|^2\Bigr]$$
Dividing by $N$ recovers $\mathcal{L} + \frac{\lambda}{2}\|\mathbf{w}\|^2$.

### 17.4 Strong convexity (proof of unique minimizer)
*Claim.* With $\lambda > 0$, $\mathcal{L}_{\text{reg}}$ is **$\lambda$-strongly convex**.

*Proof.* Hessian:
$$\nabla^2 \mathcal{L}_{\text{reg}} = \nabla^2 \mathcal{L} + \lambda I \succeq \lambda I$$
since $\nabla^2 \mathcal{L} \succeq 0$ (§15.4) and $\lambda I \succ 0$. Strong convexity gives unique global minimizer and improves SGD convergence to $O(1/T)$.

### 17.5 Bias-variance trade-off
- $\lambda = 0$: low bias, potentially high variance (overfit).
- $\lambda \to \infty$: $\hat{\mathbf{w}} \to \mathbf{0}$, high bias, low variance.
- Tune $\lambda$ by validation.

### 17.6 Pseudocode
```text
Algorithm L2-Regularized-Gradient-Step
Input: w, b, batch (Xb, yb), lr eta, l2 lambda
Output: updated w, b
1: p      <- sigma(Xb @ w + b)
2: err    <- p - yb
3: grad_w <- (Xb^T @ err) / |batch| + lambda * w     // L2 term
4: grad_b <- mean(err)                                // no penalty on b
5: w <- w - eta * grad_w
6: b <- b - eta * grad_b
7: return (w, b)
```

---

## 18) FedAvg Aggregation

### 18.1 Model
Server holds global parameters $(\mathbf{w}_g, b_g)$. Each round, $K$ clients each train locally on $n_k$ samples and return $(\mathbf{w}_k, b_k)$. Server aggregates.

### 18.2 Aggregation rule
$$\mathbf{w}_g^{\text{new}} = \sum_{k=1}^{K} \frac{n_k}{N}\, \mathbf{w}_k,\qquad b_g^{\text{new}} = \sum_{k=1}^{K} \frac{n_k}{N}\, b_k$$
where $N = \sum_k n_k$. This is a **weighted average** by client dataset size.

### 18.3 Equivalence to centralized SGD (one-step)
*Claim.* If all clients perform a **single** SGD step from common starting point $\mathbf{w}_g$ on disjoint partitions of size $n_k$ with identical $\eta$, then FedAvg is equivalent to one centralized SGD step on $\bigcup_k \mathcal{D}_k$.

*Proof.* Client $k$ computes
$$\mathbf{w}_k = \mathbf{w}_g - \eta\, \hat{g}_k,\qquad \hat{g}_k = \frac{1}{n_k} \sum_{i \in \mathcal{D}_k}(p_i - y_i)\mathbf{x}_i$$
FedAvg:
$$\mathbf{w}_g^{\text{new}} = \sum_k \frac{n_k}{N}(\mathbf{w}_g - \eta \hat{g}_k) = \mathbf{w}_g - \eta \sum_k \frac{n_k}{N}\hat{g}_k$$
The aggregated gradient:
$$\sum_k \frac{n_k}{N} \hat{g}_k = \frac{1}{N} \sum_k \sum_{i \in \mathcal{D}_k}(p_i - y_i)\mathbf{x}_i = \frac{1}{N} \sum_{i \in \bigcup_k \mathcal{D}_k}(p_i - y_i)\mathbf{x}_i$$
which is the exact full-batch gradient on the union dataset. $\square$

### 18.4 Multi-step caveat
With $E > 1$ local epochs the equivalence breaks because clients diverge. McMahan et al. (2017) show FedAvg still converges under IID assumption, and degrades gracefully under heterogeneity (non-IID); but convergence rate depends on $E$.

### 18.5 Byzantine vulnerability
FedAvg is **not** Byzantine-robust: a single malicious client can submit $\mathbf{w}_k = M \cdot \hat{\mathbf{w}}$ for any direction $\hat{\mathbf{w}}$ and large $M$, dominating the average. This motivates the robust aggregators (§19, §20).

### 18.6 Pseudocode
```text
Algorithm FedAvg
Input: list of (w_k, b_k, n_k) for k = 1..K
Output: aggregated (w_g, b_g)
1: N     <- sum(n_k for k in 1..K)
2: w_g   <- zeros(d)
3: b_g   <- 0
4: for k in 1..K:
5:     w_g <- w_g + (n_k / N) * w_k
6:     b_g <- b_g + (n_k / N) * b_k
7: return (w_g, b_g)
```

---

## 19) Coordinate-Wise Median Aggregation

### 19.1 Aggregation rule
For each coordinate $j \in \{1, \ldots, d\}$:
$$(\mathbf{w}_g)_j = \mathrm{median}\bigl(\{(\mathbf{w}_1)_j, (\mathbf{w}_2)_j, \ldots, (\mathbf{w}_K)_j\}\bigr)$$
Independent median per coordinate. The bias is treated the same way.

### 19.2 Breakdown point (Byzantine robustness)
*Claim.* The coordinate-wise median has breakdown point $\lfloor (K-1)/2 \rfloor / K$, i.e. tolerates strictly fewer than half Byzantine clients.

*Proof sketch.* If $< K/2$ values are adversarial, the median lies between two non-adversarial values, hence is bounded by the honest range. Formally: sort $K$ values; the median is the $(\lceil K/2 \rceil)$-th order statistic. If at most $\lfloor (K-1)/2 \rfloor$ values are arbitrary, this position still falls on an honest value. $\square$

### 19.3 Bias under attack
Even when honest majority holds, an attacker can shift the median by **bounded** amount: if honest values are in $[a, b]$, the corrupted median stays in $[a, b]$. Compare with FedAvg: a single adversary can move the mean by $O(M)$ for unbounded $M$.

### 19.4 Statistical efficiency
For Gaussian honest distribution, the median is less efficient than the mean by factor $\pi/2 \approx 1.57$ (variance ratio). So we trade some accuracy for robustness.

### 19.5 Convergence under Byzantine attacks
Yin et al. (2018) show that coordinate-wise median FedAvg converges with rate
$$\mathbb{E}\|\mathbf{w}_T - \mathbf{w}^*\|^2 = O\!\left(\frac{d}{T} + \frac{\alpha^2 d}{n}\right)$$
where $\alpha$ is fraction of Byzantine clients and $n$ is per-client data size. The $\alpha^2$ dependence is provably optimal among robust aggregators.

### 19.6 Pseudocode
```text
Algorithm Coordinate-Median
Input: list of (w_k, b_k) for k = 1..K
Output: aggregated (w_g, b_g)
1: W <- stack([w_1, ..., w_K])         // shape (K, d)
2: B <- [b_1, ..., b_K]                // shape (K,)
3: w_g <- median(W, axis=0)            // per-coordinate
4: b_g <- median(B)
5: return (w_g, b_g)
```

---

## 20) Trimmed-Mean Aggregation

### 20.1 Aggregation rule
For each coordinate $j$:
1. Sort: $v_{(1)} \leq v_{(2)} \leq \cdots \leq v_{(K)}$ where $v_{(\cdot)} = (\mathbf{w}_{\cdot})_j$.
2. Trim $k = \lfloor \alpha K \rfloor$ values from each tail.
3. Average the remaining $K - 2k$:
$$(\mathbf{w}_g)_j = \frac{1}{K - 2k} \sum_{i=k+1}^{K-k} v_{(i)}$$
where $\alpha \in [0, 0.5)$ is the `trim_ratio` (default 0.1).

### 20.2 Breakdown point
*Claim.* Trimmed mean with ratio $\alpha$ tolerates up to $\lfloor \alpha K \rfloor$ Byzantine clients per coordinate.

*Proof.* If at most $\alpha K$ values are arbitrary, trimming removes them — assuming they are extreme. Since adversary controls only magnitude not rank, the worst case is that all $\alpha K$ adversarial values fall on one tail; the trim removes them, and the average is over honest values only. $\square$

### 20.3 Comparison with median (§19)
| Property | Median | Trimmed mean |
|----------|--------|--------------|
| Breakdown point | $1/2$ | $\alpha$ (tunable) |
| Statistical efficiency under Gaussian | $2/\pi \approx 64\%$ | $> 64\%$, grows as $\alpha \downarrow$ |
| Convergence rate (Yin et al.) | $\alpha^2 d / n$ | $\alpha^2 d / n$ (same asymptotic) |
| Implementation cost | sort or quickselect | sort |

Tunable $\alpha$ lets the operator trade breakdown point for statistical efficiency, which is why both are exposed in the project.

### 20.4 Variance under Gaussian honest data
For honest values $v_i \sim \mathcal{N}(\mu, \sigma^2)$, the asymptotic variance of $\alpha$-trimmed mean is
$$\mathrm{Var}(\hat{\mu}_\alpha) = \frac{\sigma^2}{K(1 - 2\alpha)^2}\Bigl[(1 - 2\alpha) + 2\alpha\, z_\alpha^2\Bigr]$$
where $z_\alpha = \Phi^{-1}(1 - \alpha)$. Smaller $\alpha$ → closer to mean variance $\sigma^2/K$.

### 20.5 Pseudocode
```text
Algorithm Trimmed-Mean
Input: list of w_k for k = 1..K, trim ratio alpha
Output: aggregated w_g
1: W <- stack([w_1, ..., w_K])             // (K, d)
2: K' <- K
3: k  <- floor(alpha * K')
4: w_g <- zeros(d)
5: for j in 0..d-1:
6:     v <- sort(W[:, j])                  // ascending
7:     trimmed <- v[k : K' - k]
8:     w_g[j]  <- mean(trimmed)
9: return w_g
```

---

## 21) Stratified Train/Test Split

### 21.1 Goal
Given dataset $\mathcal{D} = \{(\mathbf{x}_i, y_i)\}$ with class proportions $\pi_c = |\{i : y_i = c\}|/N$, partition into train $\mathcal{D}_{\text{tr}}$ and test $\mathcal{D}_{\text{te}}$ such that **both partitions preserve the class distribution** $\pi$.

### 21.2 Plain random split fails
Under uniform random splitting, the per-class count in $\mathcal{D}_{\text{te}}$ is $\mathrm{Bin}(|\mathcal{D}_{\text{te}}|, \pi_c)$ — random fluctuations distort minority class. For an imbalanced binary dataset with $\pi_1 = 0.05$ and test size 100, expected positives = 5 with $\mathrm{Var} = 100 \cdot 0.05 \cdot 0.95 = 4.75$, std $\approx 2.2$ — frequent test sets have 2–8 positives, which is unreliable.

### 21.3 Stratified split algorithm
1. Partition $\mathcal{D}$ by class: $\mathcal{D}^{(c)} = \{i : y_i = c\}$.
2. Within each class, shuffle and split using target fraction $f$ (test_size).
3. Concatenate per-class splits.

This guarantees:
$$\frac{|\mathcal{D}_{\text{te}} \cap \mathcal{D}^{(c)}|}{|\mathcal{D}_{\text{te}}|} = \frac{|\mathcal{D}^{(c)}|}{|\mathcal{D}|} = \pi_c \pm O(1/N)$$
(up to integer rounding).

### 21.4 Statistical justification
Stratification is a form of **variance reduction sampling**. For estimating the class-conditional test accuracy $A_c$, the stratified estimator has variance
$$\mathrm{Var}_{\text{strat}}(\hat A) = \sum_c \pi_c^2 \frac{\mathrm{Var}(A_c)}{n_c}$$
while uniform sampling has
$$\mathrm{Var}_{\text{uniform}}(\hat A) = \frac{\mathrm{Var}_c(A_c \mid c \sim \pi)}{n}$$
For unequal class accuracies, stratified variance is always $\leq$ uniform.

### 21.5 Pseudocode
```text
Algorithm Stratified-Split
Input: X (N, d), y (N,), test_size f in (0,1), seed
Output: (X_tr, y_tr, X_te, y_te)
1: rng     <- RNG(seed)
2: classes <- unique(y)
3: idx_tr, idx_te <- [], []
4: for c in classes:
5:     I_c    <- indices where y == c
6:     I_c    <- rng.permutation(I_c)
7:     m      <- round(f * len(I_c))
8:     idx_te.extend(I_c[:m])
9:     idx_tr.extend(I_c[m:])
10: idx_tr <- rng.permutation(idx_tr)
11: idx_te <- rng.permutation(idx_te)
12: return (X[idx_tr], y[idx_tr], X[idx_te], y[idx_te])
```

---

## 22) Feature Standardization (`StandardScaler`)

### 22.1 Definition
For each feature column $j$ across training samples:
$$\mu_j = \frac{1}{N}\sum_{i=1}^N x_{ij},\qquad \sigma_j^2 = \frac{1}{N}\sum_{i=1}^N (x_{ij} - \mu_j)^2$$
Transform:
$$\tilde{x}_{ij} = \frac{x_{ij} - \mu_j}{\sigma_j}$$
After transform: $\tilde{x}_{\cdot j}$ has mean 0 and variance 1 by construction.

### 22.2 Why scale matters for gradient methods
For logistic regression gradient (§15.3):
$$\nabla_{\mathbf{w}} \mathcal{L} = \frac{1}{N}\sum_i (p_i - y_i)\mathbf{x}_i$$
If feature $j$ has scale $10^3$ and feature $k$ has scale $10^{-2}$, the corresponding gradient components also differ by $10^5$, forcing a tiny global learning rate. After standardization, all features share scale 1, and a single $\eta$ works for all coordinates.

### 22.3 Effect on Hessian conditioning
The Hessian (§15.4) is $\frac{1}{N} \mathbf{X}^\top \mathbf{S} \mathbf{X}$. Its condition number $\kappa(\mathbf{X}^\top \mathbf{X})$ governs SGD convergence speed:
$$T_{\text{conv}} = O(\kappa \log(1/\epsilon))$$
Unscaled $\mathbf{X}$ can have $\kappa \gg 10^6$; standardized $\mathbf{X}$ typically has $\kappa = O(1)$ to $O(10)$. Hence standardization can speed up training by orders of magnitude.

### 22.4 Test-set leakage caveat
Statistics $(\mu_j, \sigma_j)$ **must be computed on the training set only** and reused for test. If computed on the full dataset before splitting, test labels leak into training (mild but real). The project code (in `fl/data.py`) computes scaler before train_test_split, which is acceptable here because labels are not used in fitting the scaler, but the rigorous practice is fit-on-train.

### 22.5 Invertibility
Transformation is affine and invertible:
$$x_{ij} = \mu_j + \sigma_j \tilde{x}_{ij}$$
provided $\sigma_j > 0$. Constant columns ($\sigma_j = 0$) must be dropped or replaced by zero (sklearn does this with `with_std=False` option).

### 22.6 Pseudocode
```text
Algorithm Standard-Scaler-Fit
Input: training matrix X (N, d)
Output: (mu, sigma)
1: mu    <- mean(X, axis=0)         // shape (d,)
2: sigma <- std(X, axis=0)           // shape (d,)
3: sigma[sigma == 0] <- 1            // avoid div by zero
4: return (mu, sigma)

Algorithm Standard-Scaler-Transform
Input: matrix X, fitted (mu, sigma)
Output: standardized X_tilde
1: return (X - mu) / sigma           // broadcast over rows
```

---

## 23) Synthetic Data Generation (`make_classification`)

### 23.1 Goal
Produce a controlled binary-classification benchmark $(X, y)$ with tunable difficulty: number of features, fraction informative, redundancy, noise. Used when real dataset (e.g. CIC-IoT-2023 CSV) is unavailable.

### 23.2 Generative model (sklearn formulation)
Parameters: $N$ (samples), $d$ (total features), $d_i$ (informative), $d_r$ (redundant), $d_s = d - d_i - d_r$ (useless).

**Step 1 — Class centroids on hypercube.**
For $C$ classes (here $C = 2$) and $d_i$-dimensional cube, sample class centroid:
$$\mathbf{c}_y \in \{-1, +1\}^{d_i} \cdot \mathrm{scale}_{\text{cls\_sep}}$$
Vertices are chosen to maximize pairwise distance (random subset of $2^{d_i}$ vertices).

**Step 2 — Sample informative features.**
For each sample $i$ with label $y_i \in \{0,1\}$:
$$\mathbf{x}_i^{(\text{info})} = \mathbf{c}_{y_i} + \epsilon_i,\qquad \epsilon_i \sim \mathcal{N}(\mathbf{0}, \Sigma)$$
with $\Sigma$ usually identity (isotropic) or rotated by a random orthogonal matrix.

**Step 3 — Redundant features.**
$d_r$ features are random **linear combinations** of informative features:
$$\mathbf{x}_i^{(\text{red})} = A \mathbf{x}_i^{(\text{info})},\qquad A \in \mathbb{R}^{d_r \times d_i}\ \text{random}$$
These carry the same information as informatives but tempt correlated/overfit models.

**Step 4 — Useless features.**
$d_s$ features are pure noise:
$$\mathbf{x}_i^{(\text{noise})} \sim \mathcal{N}(\mathbf{0}, I)$$

**Step 5 — Optional label flipping.**
With probability $p_{\text{flip}}$ (default 0.01), $y_i \leftarrow 1 - y_i$. Introduces label noise / Bayes-error floor.

**Step 6 — Shuffle columns and rows.**

### 23.3 Bayes-optimal error rate (intuition)
Without label flipping and with isotropic Gaussian noise of variance $\sigma^2$ around centroids at distance $D$, the optimal classifier achieves error
$$\epsilon^* = \Phi\!\left(-\frac{D}{2\sigma}\right)$$
The `class_sep` parameter scales $D$, controlling problem difficulty. With $p_{\text{flip}} > 0$, $\epsilon^*$ is bounded below by $p_{\text{flip}}$.

### 23.4 Why useful for protocol benchmarks
- **Reproducible:** seeded RNG gives identical datasets across runs.
- **Tunable difficulty:** scale separations to test if FL aggregation converges before encryption overhead dominates time.
- **No I/O:** removes filesystem dependency from cryptographic-protocol benchmarks.

### 23.5 Project usage
`demo_end_to_end.py` (lines 261–280) calls
```python
make_classification(n_samples=1000, n_features=20, n_informative=15)
```
then performs manual 80/20 split + equal partition among clients. This gives each client ~200 samples for 4 clients, sufficient for logistic regression to converge in ~5–10 rounds.

### 23.6 Pseudocode
```text
Algorithm Make-Classification
Input: N, d, d_inf, d_red, n_classes C, class_sep s, flip_y p, seed
Output: X (N, d), y (N,)
1: rng <- RNG(seed)
2: centroids <- ChooseHypercubeVertices(C, d_inf) * s
3: y <- rng.choice(C, N)                              // balanced
4: X_inf <- zeros((N, d_inf))
5: for i in 0..N-1:
6:     X_inf[i] <- centroids[y[i]] + rng.normal(0, 1, d_inf)
7: A <- rng.normal(size=(d_red, d_inf))
8: X_red   <- X_inf @ A.T                              // redundant
9: X_noise <- rng.normal(0, 1, (N, d - d_inf - d_red))
10: X <- concat([X_inf, X_red, X_noise], axis=1)
11: X <- X[:, rng.permutation(d)]                      // shuffle cols
12: idx <- rng.permutation(N)
13: X, y <- X[idx], y[idx]
14: for i in 0..N-1:
15:    if rng.uniform() < p:
16:        y[i] <- 1 - y[i]                            // label flip
17: return (X, y)
```

---

## Cross-algorithm composition note
The full PQBFL system composes the 23 algorithms as a layered stack:

| Layer | Algorithms | Purpose |
|-------|-----------|---------|
| **PQ + classical key agreement** | §1 Kyber512, §2 X25519 | Hybrid shared secrets $ss_k, ss_e$ |
| **Key derivation** | §5 HKDF, §6 ratchet, §7/§8 hash | Root key $RK \to$ per-round $MK_i$ |
| **Authenticated transport** | §4 AEAD, §3 Ed25519 | Confidentiality + integrity of model bytes |
| **Side-channel hardening** | §9 masking, §10 leakage model, §11 noise, §12 jitter | Reduce information leakage during key ops |
| **Adaptive control** | §13 power-curve, §14 threat scoring | Tune ratchet frequency to current risk |
| **FL model** | §15 logistic regression, §16 SGD, §17 L2 | Local training |
| **FL aggregation** | §18 FedAvg, §19 median, §20 trimmed mean | Combine client updates, optionally Byzantine-robust |
| **Data pipeline** | §21 stratified split, §22 standardization, §23 make_classification | Preprocess / synthesize training data |

End-to-end key/data flow:
$$
(ss_k, ss_e) \xrightarrow[\text{HKDF}]{} RK \xrightarrow[\text{ratchet}]{} MK_i \xrightarrow[\text{AEAD}]{} C_i \xleftrightarrow{\text{Ed25519}} \text{auth}
$$
$$
\text{CSV/synthetic} \xrightarrow[\text{scaler}]{} X \xrightarrow[\text{stratified split}]{} (X_{\text{tr}}, X_{\text{te}}) \xrightarrow[\text{partition}]{} \{\mathcal{D}_k\}_{k=1}^K
$$
$$
\mathbf{w}_g \xrightarrow[\text{AEAD}(MK_i)]{} \{\mathbf{w}_k\}_{k=1}^K \xrightarrow[\text{train\_sgd}]{} \{\mathbf{w}_k^{\text{new}}\} \xrightarrow[\text{FedAvg / median / trim}]{} \mathbf{w}_g^{\text{new}}
$$

The adaptive layer (§13, §14) sits orthogonally and can tighten $L_j$ in response to any anomaly raised during the above flow.
