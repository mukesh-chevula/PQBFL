"""
ui_app.py — Streamlit dashboard for Saeed & Alqahtani (2024).
Launch:
    streamlit run ui_app.py --server.port 8504
"""
from __future__ import annotations

import json, sys
from pathlib import Path

import numpy as np
import pandas as pd
import altair as alt
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent))

from saeed2024.attacks.timing_leakage import (
    generate_timing_traces, LeakageMode,
    BASE_LATENCY_US, BRANCH_COEFF, HW_COEFF, NOISE_STD_US,
)
from saeed2024.ai.feature_extractor import FEATURE_NAMES
from simulate import run_simulation

st.set_page_config(
    page_title="Saeed & Alqahtani (2024) — PQC-IoT Side-Channel Simulator",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif;}

.hero{background:linear-gradient(135deg,#0d0d2b,#1a1a4a,#0d2040);border-radius:16px;
      padding:2rem 2.5rem;margin-bottom:1.5rem;color:white;}
.hero h1{font-size:1.5rem;font-weight:700;margin:0 0 .3rem 0;}
.hero p{font-size:.87rem;opacity:.75;margin:0;}
.hero .badge{display:inline-block;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.2);
             border-radius:20px;padding:3px 12px;font-size:.73rem;margin-top:.6rem;margin-right:6px;}

.kpi-card{background:#0d0d2b;border:1px solid #2a2a5a;border-radius:12px;
           padding:1rem 1.2rem;text-align:center;}
.kpi-label{font-size:.70rem;color:#8888cc;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.25rem;}
.kpi-value{font-size:1.65rem;font-weight:700;color:#ccccff;}
.kpi-sub{font-size:.70rem;color:#4455bb;margin-top:.2rem;}

.vuln-box{background:linear-gradient(135deg,#2a0a0a,#3a1010);border-left:4px solid #ff4444;
           border-radius:8px;padding:.8rem 1rem;margin:.4rem 0;font-size:.83rem;color:#ffaaaa;}
.hard-box{background:linear-gradient(135deg,#0a1a2a,#0a2040);border-left:4px solid #4488ff;
           border-radius:8px;padding:.8rem 1rem;margin:.4rem 0;font-size:.83rem;color:#aaccff;}
.pqbfl-box{background:linear-gradient(135deg,#0a2a0a,#1a4a1a);border-left:4px solid #44cc44;
            border-radius:8px;padding:.8rem 1rem;margin:.4rem 0;font-size:.83rem;color:#aaffaa;}
.section-head{font-size:1rem;font-weight:600;color:#8888ff;border-bottom:1px solid #2a2a5a;
               padding-bottom:.3rem;margin:1.2rem 0 .8rem 0;}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
  <h1>🔒 Saeed & Alqahtani (2024) — AI + PQC Cybersecurity for IoT Systems</h1>
  <p>PeerJ Computer Science, 2024 &nbsp;·&nbsp;
     Side-Channel Timing Leakage Model + Random Forest Anomaly Detector + ML-KEM Hardening</p>
  <span class="badge">Side-Channel Analysis</span>
  <span class="badge">AI Anomaly Detection</span>
  <span class="badge">ML-KEM (PQC)</span>
  <span class="badge">Constant-Time Primitives</span>
  <span class="badge">IoT / Healthcare</span>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Experiment Parameters")
    n_samples   = st.slider("Timing Observations / Device", 200, 2000, 800, 100)
    attack_frac = st.slider("Attack Probe Fraction", 0.05, 0.60, 0.25, 0.05)
    n_devices   = st.slider("IoT Devices", 1, 10, 3, 1)
    window_size = st.slider("AI Window Size", 5, 50, 20, 5)
    step        = st.slider("Window Step", 2, 20, 10, 2)
    st.markdown("---")
    st.markdown("**Leakage Model Constants**")
    st.caption(f"Branch coeff: {BRANCH_COEFF} μs/bit")
    st.caption(f"HW coeff: {HW_COEFF} μs/HW")
    st.caption(f"Noise σ: {NOISE_STD_US} μs")
    st.caption(f"Base latency: {BASE_LATENCY_US} μs")
    run_btn = st.button("▶ Run Experiment", type="primary", use_container_width=True)

if "saeed_results" not in st.session_state:
    st.session_state["saeed_results"] = None
if "saeed_traces" not in st.session_state:
    st.session_state["saeed_traces"]  = None

if run_btn:
    with st.spinner("Generating traces & training AI detectors…"):
        results = run_simulation(
            n_samples=n_samples, attack_frac=attack_frac,
            n_devices=n_devices, window_size=window_size,
            step=step, verbose=False,
        )
        # Generate raw traces for visualisation
        vuln_obs = generate_timing_traces(min(n_samples, 400), LeakageMode.VULNERABLE,
                                          attack_frac, 42, 0)
        hard_obs = generate_timing_traces(min(n_samples, 400), LeakageMode.HARDENED,
                                          attack_frac, 42, 0)
        st.session_state["saeed_results"] = results
        st.session_state["saeed_traces"]  = (vuln_obs, hard_obs)
    st.success("Experiment complete!")

results = st.session_state.get("saeed_results")

# ---------------------------------------------------------------------------
# Idle state
# ---------------------------------------------------------------------------
if results is None:
    st.info("👈 Configure parameters and click **Run Experiment** to start.")
    st.markdown("""
    <div class="vuln-box">
    ⚠️ <strong>VULNERABLE implementation:</strong> HMAC comparison exits early at first mismatched byte.
    Timing leaks matching prefix length → adversary recovers key byte-by-byte with N observations.
    Non-constant-time AES multiply and cache-dependent S-box lookups add further leakage channels.
    </div>
    <div class="hard-box">
    🔵 <strong>HARDENED implementation (Saeed & Alqahtani §VI):</strong>
    <code>hmac.compare_digest()</code> for constant-time tag comparison.
    <code>os.urandom(12)</code> nonce per AES-GCM call.
    Domain-separated HKDF with per-derivation random salt.
    ML-KEM for post-quantum key encapsulation.
    </div>
    <div class="pqbfl-box">
    ✅ <strong>JOURNAL-3 adoption (cite{saeed2024}):</strong>
    PQBFL adopts all hardening recommendations from this paper as its implementation baseline.
    Cited twice in the Introduction to justify the constant-time + CSPRNG design requirements.
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ---------------------------------------------------------------------------
# KPI Row
# ---------------------------------------------------------------------------
dv   = results["detector_vulnerable"]
dh   = results["detector_hardened"]
lk   = results["leakage"]
pqc  = results["pqc"]
ts   = results["timing_summary"]

st.markdown('<div class="section-head">📊 Experiment Summary</div>', unsafe_allow_html=True)
kpi = lambda l,v,s: f'<div class="kpi-card"><div class="kpi-label">{l}</div><div class="kpi-value">{v}</div><div class="kpi-sub">{s}</div></div>'

c1,c2,c3,c4,c5 = st.columns(5)
c1.markdown(kpi("Vulnerable Accuracy", f"{dv['accuracy']*100:.1f}%", "AI detects attack easily"), unsafe_allow_html=True)
c2.markdown(kpi("Hardened Accuracy",   f"{dh['accuracy']*100:.1f}%", "Signal removed by hardening"), unsafe_allow_html=True)
c3.markdown(kpi("Leakage CV Reduction", f"{lk['leakage_reduction_pct']:.1f}%", "Hardening effectiveness"), unsafe_allow_html=True)
c4.markdown(kpi("AUC-ROC (vuln)", f"{dv['auc_roc']:.3f}", "Attack detectability"), unsafe_allow_html=True)
c5.markdown(kpi("KEM Latency", f"{pqc['avg_encap_ms']:.2f} ms", f"{pqc['backend']}"), unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)
acc_drop = dv["accuracy"] - dh["accuracy"]
col_v, col_h = st.columns(2)
with col_v:
    st.markdown(f"""<div class="vuln-box">
    ⚠️ <strong>VULNERABLE:</strong> Detector accuracy = {dv['accuracy']*100:.1f}%,
    F1 = {dv['f1']:.3f}, AUC-ROC = {dv['auc_roc']:.3f}.<br>
    Timing std = {ts['vuln_std_us']:.2f} μs → strong leakage signal.
    35–40% of key bits recoverable via gradient direction (Saeed & Alqahtani §III).
    </div>""", unsafe_allow_html=True)
with col_h:
    st.markdown(f"""<div class="hard-box">
    🔵 <strong>HARDENED:</strong> Accuracy drops to {dh['accuracy']*100:.1f}%
    (Δ = {acc_drop:+.1%}), AUC-ROC = {dh['auc_roc']:.3f}.<br>
    Timing std = {ts['hard_std_us']:.2f} μs → leakage CV reduced {lk['leakage_reduction_pct']:.1f}%.
    Hardening eliminates the exploitable timing signal.
    </div>""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Timing trace charts
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">📉 Timing Trace Analysis</div>', unsafe_allow_html=True)

vuln_obs, hard_obs = st.session_state["saeed_traces"]
vuln_df = pd.DataFrame({
    "index":     list(range(len(vuln_obs))),
    "timing_us": [o.measured_us for o in vuln_obs],
    "is_attack": [o.is_attack   for o in vuln_obs],
    "mode":      ["Vulnerable"] * len(vuln_obs),
})
hard_df = pd.DataFrame({
    "index":     list(range(len(hard_obs))),
    "timing_us": [o.measured_us for o in hard_obs],
    "is_attack": [o.is_attack   for o in hard_obs],
    "mode":      ["Hardened"] * len(hard_obs),
})

col_tv, col_th = st.columns(2)

def trace_chart(df, title_str, color_benign, color_attack):
    benign = df[~df["is_attack"]]
    attack = df[df["is_attack"]]
    b_pts = alt.Chart(benign).mark_point(size=12, opacity=0.5, color=color_benign).encode(
        x=alt.X("index:Q", title="Observation #"),
        y=alt.Y("timing_us:Q", title="Timing (μs)"),
        tooltip=["index", alt.Tooltip("timing_us:Q", format=".1f")],
    )
    a_pts = alt.Chart(attack).mark_point(size=18, opacity=0.8, color=color_attack).encode(
        x=alt.X("index:Q"),
        y=alt.Y("timing_us:Q"),
        tooltip=["index", alt.Tooltip("timing_us:Q", format=".1f")],
    )
    return alt.layer(b_pts, a_pts).properties(
        title=alt.TitleParams(title_str, color="#ccccff", fontSize=13),
        height=260,
    )

with col_tv:
    st.altair_chart(trace_chart(vuln_df, "VULNERABLE — Timing Trace (grey=benign, red=attack probe)",
                                "#888888", "#ff4444"), use_container_width=True)
with col_th:
    st.altair_chart(trace_chart(hard_df, "HARDENED — Timing Trace (grey=benign, blue=attack probe)",
                                "#888888", "#4488ff"), use_container_width=True)

# ---------------------------------------------------------------------------
# Distribution comparison
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">📊 Timing Distribution — Vulnerable vs Hardened</div>',
            unsafe_allow_html=True)

vuln_df["mode"] = "Vulnerable"
hard_df["mode"] = "Hardened"
combined = pd.concat([vuln_df, hard_df], ignore_index=True)

hist = alt.Chart(combined).mark_bar(opacity=0.65, binSpacing=1).encode(
    x=alt.X("timing_us:Q", bin=alt.Bin(maxbins=60), title="Timing (μs)"),
    y=alt.Y("count():Q", title="Count", stack=None),
    color=alt.Color("mode:N",
        scale=alt.Scale(domain=["Vulnerable", "Hardened"],
                        range=["#ff6666", "#4488ff"]),
        legend=alt.Legend(title="Implementation", orient="top-right"),
    ),
    tooltip=["mode", "count()"],
).properties(
    title=alt.TitleParams("Timing Distribution: Vulnerable (red) vs Hardened (blue)",
                          color="#ccccff", fontSize=13),
    height=280,
)
st.altair_chart(hist, use_container_width=True)
st.caption(f"Vulnerable σ = {ts['vuln_std_us']:.2f} μs  |  "
           f"Hardened σ = {ts['hard_std_us']:.2f} μs  |  "
           f"Leakage CV reduction = {lk['leakage_reduction_pct']:.1f}%  "
           "(narrower = less exploitable timing signal)")

# ---------------------------------------------------------------------------
# AI detector comparison
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">🤖 AI Detector Performance Comparison</div>',
            unsafe_allow_html=True)

metrics_df = pd.DataFrame([
    {"Metric": "Accuracy",  "Vulnerable": dv["accuracy"],  "Hardened": dh["accuracy"]},
    {"Metric": "F1-Score",  "Vulnerable": dv["f1"],        "Hardened": dh["f1"]},
    {"Metric": "AUC-ROC",   "Vulnerable": dv["auc_roc"],   "Hardened": dh["auc_roc"]},
    {"Metric": "Precision", "Vulnerable": dv["precision"],  "Hardened": dh["precision"]},
    {"Metric": "Recall",    "Vulnerable": dv["recall"],     "Hardened": dh["recall"]},
])
melt = metrics_df.melt("Metric", var_name="Implementation", value_name="Score")

bar_compare = alt.Chart(melt).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4).encode(
    x=alt.X("Metric:N", title=None),
    y=alt.Y("Score:Q", scale=alt.Scale(domain=[0, 1]), title="Score"),
    color=alt.Color("Implementation:N",
        scale=alt.Scale(domain=["Vulnerable", "Hardened"], range=["#ff6666","#4488ff"]),
        legend=alt.Legend(orient="top-right")),
    xOffset="Implementation:N",
    tooltip=["Metric", "Implementation", alt.Tooltip("Score:Q", format=".4f")],
).properties(
    title=alt.TitleParams("Detector Metrics: Vulnerable vs Hardened",
                          color="#ccccff", fontSize=13),
    height=300,
)
st.altair_chart(bar_compare, use_container_width=True)
st.caption(f"Key finding: Hardening drops detector accuracy by {acc_drop:+.1%} — "
           "the AI cannot reliably detect attacks when timing is constant. "
           "This validates Saeed & Alqahtani §VI recommendations, cited in JOURNAL-3.")

# ---------------------------------------------------------------------------
# Feature importance
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">🎯 Top Timing Features (Vulnerable Implementation)</div>',
            unsafe_allow_html=True)

fi_df = pd.DataFrame(dv["top_features"], columns=["Feature", "Importance"])
fi_chart = alt.Chart(fi_df).mark_bar(color="#ff8844").encode(
    x=alt.X("Importance:Q", title="Feature Importance"),
    y=alt.Y("Feature:N", sort="-x", title=None),
    tooltip=["Feature", alt.Tooltip("Importance:Q", format=".4f")],
).properties(
    title=alt.TitleParams("Feature importances (Random Forest — Vulnerable traces)",
                          color="#ccccff", fontSize=12),
    height=220,
)
st.altair_chart(fi_chart, use_container_width=True)

# ---------------------------------------------------------------------------
# PQC overhead
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">🔑 PQC Integration Overhead</div>', unsafe_allow_html=True)

col_p1, col_p2, col_p3 = st.columns(3)
col_p1.metric("KEM Backend",        pqc["backend"])
col_p2.metric("Public Key Size",    f"{pqc['pk_bytes']} bytes")
col_p3.metric("Avg Encap Latency",  f"{pqc['avg_encap_ms']:.3f} ms")

st.markdown(f"""<div class="pqbfl-box">
✅ <strong>JOURNAL-3 (cite{{saeed2024}}):</strong>
This paper provides the threat-model justification for PQBFL's constant-time cryptographic stack.
The {lk['leakage_reduction_pct']:.0f}% leakage CV reduction and {acc_drop:+.1%} detector accuracy
drop confirm that the hardening techniques (constant-time comparison, CSPRNG nonces, random HKDF salts)
eliminate the timing side-channel exploitable by the adversary model in JOURNAL-3 §II.
</div>""", unsafe_allow_html=True)

# Download
st.download_button("⬇ Download Results JSON", json.dumps(results, indent=2),
                   "saeed2024_results.json", "application/json")
st.markdown("---")
st.caption("Saeed & Alqahtani (2024) · PeerJ CS · "
           "Implemented as the side-channel threat model baseline for JOURNAL-3.")
