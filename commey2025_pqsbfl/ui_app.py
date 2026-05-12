"""
ui_app.py — Streamlit dashboard for Commey et al. (2025) PQS-BFL.
Launch: streamlit run ui_app.py --server.port 8505
"""
from __future__ import annotations
import json, sys
from pathlib import Path
import numpy as np, pandas as pd, altair as alt, streamlit as st

sys.path.insert(0, str(Path(__file__).parent))
from commey2025.crypto.dsa import DSA_BACKEND, DSA_PUBLIC_KEY_BYTES, DSA_SIGNATURE_BYTES
from commey2025.crypto.kem import KEM_BACKEND, KEM_PUBLIC_KEY_BYTES, KEM_CIPHERTEXT_BYTES
from simulate import run_simulation

st.set_page_config(page_title="Commey et al. (2025) — PQS-BFL Simulator",
                   page_icon="⛓️", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif;}
.hero{background:linear-gradient(135deg,#150528,#2a0550,#1a0a40);border-radius:16px;
      padding:2rem 2.5rem;margin-bottom:1.5rem;color:white;}
.hero h1{font-size:1.5rem;font-weight:700;margin:0 0 .3rem 0;}
.hero p{font-size:.87rem;opacity:.75;margin:0;}
.badge{display:inline-block;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.2);
       border-radius:20px;padding:3px 12px;font-size:.73rem;margin-top:.6rem;margin-right:6px;}
.kpi{background:#100520;border:1px solid #3a1560;border-radius:12px;
     padding:1rem 1.2rem;text-align:center;}
.kpi-l{font-size:.70rem;color:#aa88cc;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.25rem;}
.kpi-v{font-size:1.65rem;font-weight:700;color:#ddaaff;}
.kpi-s{font-size:.70rem;color:#663388;margin-top:.2rem;}
.gap-box{background:linear-gradient(135deg,#200a00,#3a1500);border-left:4px solid #ff6600;
          border-radius:8px;padding:.8rem 1rem;margin:.4rem 0;font-size:.83rem;color:#ffccaa;}
.pqbfl-box{background:linear-gradient(135deg,#001020,#002040);border-left:4px solid #4488ff;
            border-radius:8px;padding:.8rem 1rem;margin:.4rem 0;font-size:.83rem;color:#aaccff;}
.chain-box{background:linear-gradient(135deg,#0a0020,#1a0040);border-left:4px solid #aa44ff;
            border-radius:8px;padding:.8rem 1rem;margin:.4rem 0;font-size:.83rem;color:#ccaaff;}
.sh{font-size:1rem;font-weight:600;color:#bb88ff;border-bottom:1px solid #3a1560;
    padding-bottom:.3rem;margin:1.2rem 0 .8rem 0;}
</style>""", unsafe_allow_html=True)

st.markdown(f"""
<div class="hero">
  <h1>⛓️ Commey et al. (2025) — PQS-BFL: Post-Quantum Secure Blockchain FL</h1>
  <p>arXiv:2505.01866, 2025 &nbsp;·&nbsp;
     ML-DSA (Dilithium) + PoA Blockchain + FedAvg · Healthcare Analytics Domain</p>
  <span class="badge">ML-DSA ({DSA_BACKEND})</span>
  <span class="badge">{DSA_SIGNATURE_BYTES}B Signature</span>
  <span class="badge">PoA Blockchain</span>
  <span class="badge">Smart Contract</span>
  <span class="badge">Healthcare FL</span>
  <span class="badge">No Ratcheting ✗</span>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### ⚙️ Simulation Parameters")
    n_clients  = st.slider("FL Clients",       2, 15, 5, 1)
    n_rounds   = st.slider("Training Rounds", 5, 40, 20, 1)
    n_samples  = st.slider("Healthcare Samples", 1000, 10000, 4000, 500)
    n_features = st.slider("Feature Dimension", 10, 100, 46, 2)
    lr         = st.select_slider("Learning Rate", [0.001, 0.005, 0.01, 0.05, 0.1], 0.01)
    epochs     = st.slider("Local Epochs", 1, 10, 5, 1)
    st.markdown("---")
    st.caption(f"**DSA:** {DSA_BACKEND}")
    st.caption(f"Sig: {DSA_SIGNATURE_BYTES}B · PK: {DSA_PUBLIC_KEY_BYTES}B")
    st.caption(f"**KEM:** {KEM_BACKEND}")
    run_btn = st.button("▶ Run Simulation", type="primary", use_container_width=True)

if "commey_results" not in st.session_state:
    st.session_state["commey_results"] = None

if run_btn:
    with st.spinner("Running PQS-BFL simulation…"):
        res = run_simulation(n_clients, n_rounds, n_samples, n_features,
                             lr, epochs, verbose=False)
        st.session_state["commey_results"] = res
    st.success("Simulation complete!")

results = st.session_state.get("commey_results")

if results is None:
    st.info("👈 Configure and click **Run Simulation**.")
    st.markdown(f"""
<div class="chain-box">
⛓️ <strong>PQS-BFL Design (Commey et al. 2025):</strong><br>
Every gradient update is signed with ML-DSA ({DSA_BACKEND}, {DSA_SIGNATURE_BYTES}B/sig).
Signatures are verified by a smart contract before FedAvg.
A PoA blockchain commits one block per FL round for auditability.
</div>
<div class="gap-box">
⚠️ <strong>Static Key Gap:</strong><br>
The ML-DSA signing key is generated ONCE and NEVER rotated.
A single key compromise at round R lets an adversary forge gradient signatures
for ALL subsequent rounds — and retroactively authenticate malicious past updates.
No ThreatMonitor, no θ-driven adaptation, no ratchet window L_j.
</div>
<div class="pqbfl-box">
🔵 <strong>JOURNAL-3 closes this gap by adding:</strong><br>
① ML-KEM ratchet with window L_j → key rotation every L_j rounds (PCS)<br>
② On-chain ThreatMonitor → θ-driven L_j modulation (adaptive)<br>
③ Gradient-level DP + ratcheted KEM → healthcare privacy + forward secrecy
</div>""", unsafe_allow_html=True)
    st.stop()

# Results
df  = pd.DataFrame(results["per_round"])
s   = results["summary"]
cfg = results["config"]

# KPI row
st.markdown('<div class="sh">📊 Simulation Summary</div>', unsafe_allow_html=True)
kpi = lambda l,v,sub: f'<div class="kpi"><div class="kpi-l">{l}</div><div class="kpi-v">{v}</div><div class="kpi-s">{sub}</div></div>'
c1,c2,c3,c4,c5 = st.columns(5)
c1.markdown(kpi("Final Accuracy",   f"{s['final_accuracy']*100:.2f}%",    "FedAvg convergence"), unsafe_allow_html=True)
c2.markdown(kpi("Chain Height",     f"{s['chain_height']}",               f"{n_rounds} rounds + genesis"), unsafe_allow_html=True)
c3.markdown(kpi("DSA Sig Overhead", f"{s['avg_sig_overhead']*100:.1f}%",  "of total wire bytes"), unsafe_allow_html=True)
c4.markdown(kpi("Sig Verifications",f"{s['total_sig_verifications']:,}",   f"{s['accept_rate']*100:.1f}% accepted"), unsafe_allow_html=True)
c5.markdown(kpi("Chain Valid",      "✅ Yes" if s["chain_valid"] else "❌ No", "SHA-3 linkage intact"), unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

# Callouts
col_g, col_p = st.columns(2)
with col_g:
    st.markdown(f"""<div class="gap-box">
⚠️ <strong>Static {DSA_BACKEND} key — {DSA_SIGNATURE_BYTES}B/sig × {n_clients} clients = {DSA_SIGNATURE_BYTES*n_clients:,}B/round in signature overhead.</strong><br>
Sig overhead: {s['avg_sig_overhead']*100:.1f}% of total wire. Key NEVER rotates.
Compromise at any round = full training run exposure (no PCS).
</div>""", unsafe_allow_html=True)
with col_p:
    st.markdown(f"""<div class="pqbfl-box">
🔵 <strong>JOURNAL-3 adds ML-KEM ratchet:</strong><br>
Key rotation every L_j rounds → exposure window bounded.
Adaptive L_j driven by on-chain θ → fewer rotations when benign, more when under attack.
Same blockchain + same FL domain — 3 missing pieces added.
</div>""", unsafe_allow_html=True)

# ── Charts ────────────────────────────────────────────────────────────────
st.markdown('<div class="sh">📈 Convergence</div>', unsafe_allow_html=True)
ca, cl = st.columns(2)
with ca:
    ch = alt.Chart(df).mark_line(color="#bb88ff", strokeWidth=2,
         point=alt.OverlayMarkDef(filled=True, size=40, color="#bb88ff")).encode(
        x=alt.X("round:Q", title="Round"),
        y=alt.Y("accuracy:Q", title="Test Accuracy", scale=alt.Scale(domain=[0,1])),
        tooltip=["round", alt.Tooltip("accuracy:Q", format=".4f")],
    ).properties(title=alt.TitleParams("Test Accuracy (FedAvg)", color="#ddaaff", fontSize=13), height=260)
    st.altair_chart(ch, use_container_width=True)
with cl:
    ch = alt.Chart(df).mark_area(color="#8844cc", opacity=0.6,
         line={"color":"#cc88ff","strokeWidth":2}).encode(
        x=alt.X("round:Q", title="Round"),
        y=alt.Y("loss:Q",  title="Cross-Entropy Loss"),
        tooltip=["round", alt.Tooltip("loss:Q", format=".4f")],
    ).properties(title=alt.TitleParams("Training Loss", color="#ddaaff", fontSize=13), height=260)
    st.altair_chart(ch, use_container_width=True)

# ── Wire overhead ─────────────────────────────────────────────────────────
st.markdown('<div class="sh">📦 Communication Overhead</div>', unsafe_allow_html=True)

df_m = df[["round","sig_wire_bytes","grad_wire_bytes"]].melt("round", var_name="component", value_name="bytes")
df_m["component"] = df_m["component"].map({"sig_wire_bytes":"ML-DSA Signatures","grad_wire_bytes":"Encrypted Gradient"})
stack = alt.Chart(df_m).mark_bar().encode(
    x=alt.X("round:Q", title="Round"),
    y=alt.Y("bytes:Q", title="Wire Bytes"),
    color=alt.Color("component:N",
        scale=alt.Scale(domain=["ML-DSA Signatures","Encrypted Gradient"],
                        range=["#ff6633","#8844cc"]),
        legend=alt.Legend(orient="top-right")),
    tooltip=["round","component","bytes"],
).properties(title=alt.TitleParams("Wire bytes per round (stacked)", color="#ddaaff", fontSize=13), height=280)
st.altair_chart(stack, use_container_width=True)

co1, co2 = st.columns(2)
with co1:
    sig_frac = alt.Chart(df).mark_line(color="#ff8844", strokeWidth=2,
         point=alt.OverlayMarkDef(filled=True, size=35, color="#ff8844")).encode(
        x=alt.X("round:Q", title="Round"),
        y=alt.Y("sig_overhead_frac:Q", title="Sig Overhead Fraction",
                scale=alt.Scale(domain=[0,1])),
        tooltip=["round", alt.Tooltip("sig_overhead_frac:Q", format=".2%")],
    ).properties(title=alt.TitleParams("ML-DSA Signature Overhead Fraction per Round",
                                       color="#ddaaff", fontSize=12), height=240)
    st.altair_chart(sig_frac, use_container_width=True)
with co2:
    sign_lat = alt.Chart(df).mark_line(color="#44ccff", strokeWidth=2,
         point=alt.OverlayMarkDef(filled=True, size=35, color="#44ccff")).encode(
        x=alt.X("round:Q", title="Round"),
        y=alt.Y("avg_sign_ms:Q", title="Avg Sign Latency (ms)"),
        tooltip=["round", alt.Tooltip("avg_sign_ms:Q", format=".3f")],
    ).properties(title=alt.TitleParams("Average ML-DSA Sign Latency per Round",
                                       color="#ddaaff", fontSize=12), height=240)
    st.altair_chart(sign_lat, use_container_width=True)

# ── Blockchain ────────────────────────────────────────────────────────────
st.markdown('<div class="sh">⛓️ Blockchain State</div>', unsafe_allow_html=True)
bc1, bc2, bc3, bc4 = st.columns(4)
bc1.metric("Chain Height",           s["chain_height"])
bc2.metric("Rounds Recorded",        s["fl_rounds_recorded"])
bc3.metric("Total Sig Bytes On-Chain", f"{s['total_sig_bytes']:,}B")
bc4.metric("Sig Overhead (chain)",   f"{s['sig_overhead_frac']*100:.1f}%")

with st.expander("📋 Per-round detail"):
    st.dataframe(df[["round","accuracy","loss","n_accepted","n_rejected",
                      "total_wire_bytes","sig_wire_bytes","sig_overhead_frac",
                      "chain_height","avg_sign_ms"]].rename(columns={
        "sig_overhead_frac":"sig_ovhd","avg_sign_ms":"sign_ms"}),
        use_container_width=True, hide_index=True)

st.download_button("⬇ Download Results JSON", json.dumps(results,indent=2),
                   "commey2025_results.json","application/json")
st.markdown("---")
st.caption(f"Commey et al. (2025) · arXiv:2505.01866 · "
           f"DSA: {DSA_BACKEND} ({DSA_SIGNATURE_BYTES}B/sig) · "
           f"KEM: {KEM_BACKEND} · Healthcare FL domain")
