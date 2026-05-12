"""
ui_app.py  — Streamlit dashboard for Zhang et al. (2025) PQ-FL simulation.

Launch:
    streamlit run ui_app.py

Features:
  • Configure all simulation parameters in sidebar
  • Live-updating accuracy / loss curves
  • Per-round KEM overhead analysis
  • Overhead fraction chart (KEM vs gradient bytes)
  • Side-by-side comparison with adaptive PQBFL overhead
  • Download results as JSON
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import streamlit as st
import pandas as pd
import altair as alt

# Make sure the package is importable when run from the project root
sys.path.insert(0, str(Path(__file__).parent))

from zhang2025.crypto.kem import KEM_BACKEND, KEM_PUBLIC_KEY_BYTES, KEM_CIPHERTEXT_BYTES
from simulate import run_simulation

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Zhang et al. (2025) — PQ-FL Simulator",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"]  { font-family: 'Inter', sans-serif; }

.hero {
    background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
    border-radius: 16px;
    padding: 2rem 2.5rem;
    margin-bottom: 1.5rem;
    color: white;
}
.hero h1  { font-size: 1.6rem; font-weight: 700; margin: 0 0 .3rem 0; }
.hero p   { font-size: 0.9rem; opacity: 0.75; margin: 0; }
.hero .badge {
    display: inline-block;
    background: rgba(255,255,255,0.12);
    border: 1px solid rgba(255,255,255,0.2);
    border-radius: 20px;
    padding: 3px 12px;
    font-size: 0.75rem;
    margin-top: 0.6rem;
    margin-right: 6px;
}

.kpi-card {
    background: #1a1a2e;
    border: 1px solid #2a2a4a;
    border-radius: 12px;
    padding: 1.1rem 1.2rem;
    text-align: center;
}
.kpi-label  { font-size: 0.72rem; color: #8888aa; text-transform: uppercase;
               letter-spacing: 0.05em; margin-bottom: .3rem; }
.kpi-value  { font-size: 1.7rem; font-weight: 700; color: #e0e0ff; }
.kpi-sub    { font-size: 0.72rem; color: #5577cc; margin-top: .2rem; }

.overhead-warn {
    background: linear-gradient(135deg, #2d1b1b, #3d2020);
    border-left: 4px solid #ff4444;
    border-radius: 8px;
    padding: 0.8rem 1rem;
    margin: 0.5rem 0;
    font-size: 0.85rem;
    color: #ffaaaa;
}
.overhead-note {
    background: linear-gradient(135deg, #1b2d1b, #203d20);
    border-left: 4px solid #44cc44;
    border-radius: 8px;
    padding: 0.8rem 1rem;
    margin: 0.5rem 0;
    font-size: 0.85rem;
    color: #aaffaa;
}

.section-head {
    font-size: 1rem; font-weight: 600; color: #8888ff;
    border-bottom: 1px solid #2a2a4a;
    padding-bottom: .3rem; margin: 1.2rem 0 .8rem 0;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Hero header
# ---------------------------------------------------------------------------
st.markdown("""
<div class="hero">
  <h1>🔐 Zhang et al. (2025) — Full-Stack Private Federated Learning with Post-Quantum Security</h1>
  <p>IEEE Transactions on Dependable and Secure Computing &nbsp;·&nbsp;
     Static ML-KEM + AES-256-GCM + FedAvg + Gaussian DP</p>
  <span class="badge">ML-KEM (Kyber)</span>
  <span class="badge">AES-256-GCM</span>
  <span class="badge">FedAvg</span>
  <span class="badge">Differential Privacy</span>
  <span class="badge">Static L_j Ratchet</span>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Sidebar — simulation parameters
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Simulation Parameters")

    st.markdown("**Federated Learning**")
    n_rounds  = st.slider("Training Rounds", 5, 100, 30, 5)
    n_clients = st.slider("Clients",          2, 20,   5, 1)
    lj        = st.slider("Ratchet Window Lⱼ (FIXED)", 2, 20, 10, 1,
                           help="Static threshold — KEM re-keying every Lj rounds. "
                                "Zhang et al. design never adapts this.")
    n_samples = st.slider("Dataset Samples", 1000, 20000, 5000, 500)
    epochs    = st.slider("Local SGD Epochs", 1, 20, 5, 1)
    lr        = st.number_input("Learning Rate", value=0.01, format="%.4f")
    iid       = st.toggle("IID Data Split", value=True)

    st.markdown("---")
    st.markdown("**Differential Privacy**")
    use_dp    = st.toggle("Enable Gaussian DP", value=False)
    dp_eps    = st.slider("ε (epsilon)", 0.1, 10.0, 1.0, 0.1, disabled=not use_dp)
    dp_delta  = st.selectbox("δ (delta)", [1e-5, 1e-4, 1e-3], disabled=not use_dp)

    st.markdown("---")
    st.caption(f"KEM Backend: **{KEM_BACKEND}**")
    st.caption(f"PK size: {KEM_PUBLIC_KEY_BYTES:,} B · CT size: {KEM_CIPHERTEXT_BYTES:,} B")

    run_btn = st.button("▶ Run Simulation", type="primary", use_container_width=True)

# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------
if "results" not in st.session_state:
    st.session_state["results"] = None
if "running" not in st.session_state:
    st.session_state["running"] = False

# ---------------------------------------------------------------------------
# Run simulation
# ---------------------------------------------------------------------------
if run_btn:
    st.session_state["running"] = True
    with st.spinner("Running PQ-FL simulation…"):
        results = run_simulation(
            n_rounds    = n_rounds,
            n_clients   = n_clients,
            lj          = lj,
            n_samples   = n_samples,
            n_features  = 46,
            lr          = lr,
            epochs      = epochs,
            iid         = iid,
            dp_epsilon  = dp_eps if use_dp else 0.0,
            dp_delta    = float(dp_delta) if use_dp else 1e-5,
            verbose     = False,
        )
        st.session_state["results"] = results
        st.session_state["running"] = False
    st.success("Simulation complete!")

# ---------------------------------------------------------------------------
# Results display
# ---------------------------------------------------------------------------
results = st.session_state.get("results")

if results is None:
    st.info("👈  Configure parameters in the sidebar and click **Run Simulation** to start.")

    # Show static overview while idle
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div class="kpi-card">
          <div class="kpi-label">KEM Public Key</div>
          <div class="kpi-value">1,184 B</div>
          <div class="kpi-sub">Kyber-768 (vs 64 B ECDH)</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="kpi-card">
          <div class="kpi-label">KEM Ciphertext</div>
          <div class="kpi-value">1,088 B</div>
          <div class="kpi-sub">Per client per epoch</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class="kpi-card">
          <div class="kpi-label">Overhead vs ECDH-FL</div>
          <div class="kpi-value">~40–50%</div>
          <div class="kpi-sub">Fixed L_j static ratchet</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("""
    <div class="overhead-warn">
    ⚠️ <strong>Static L_j Design (Zhang et al.):</strong> The ratchet window L_j is a fixed constant.
    Every L_j rounds, ALL clients must perform a fresh Kyber KEM exchange, regardless of the
    actual threat level. This imposes a constant ~40-50% communication overhead vs classical ECDH-FL.
    </div>
    <div class="overhead-note">
    ✅ <strong>Adaptive PQBFL (JOURNAL-3) improvement:</strong> Threat-adaptive L_j modulation
    reduces KEM invocations by ~76% by only re-keying when the blockchain threat signal t exceeds
    a threshold — eliminating the redundant overhead during benign operation.
    </div>
    """, unsafe_allow_html=True)

    st.stop()

# ---------- At this point, results are available ----------
summary   = results["summary"]
per_round = results["per_round"]
config    = results["config"]
df        = pd.DataFrame(per_round)

# ---------------------------------------------------------------------------
# KPI Row
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">📊 Simulation Summary</div>', unsafe_allow_html=True)

c1, c2, c3, c4, c5 = st.columns(5)
kpi_html = lambda label, value, sub: f"""
<div class="kpi-card">
  <div class="kpi-label">{label}</div>
  <div class="kpi-value">{value}</div>
  <div class="kpi-sub">{sub}</div>
</div>"""

c1.markdown(kpi_html(
    "Final Accuracy",
    f"{summary['final_accuracy']*100:.2f}%",
    f"over {summary['n_rounds']} rounds"
), unsafe_allow_html=True)

c2.markdown(kpi_html(
    "KEM Overhead",
    f"{summary['avg_overhead_fraction']*100:.1f}%",
    "avg KEM / total wire"
), unsafe_allow_html=True)

c3.markdown(kpi_html(
    "Total KEM Bytes",
    f"{summary['total_kem_bytes']:,}",
    f"in {summary.get('kem_exchanges', '—')} exchanges"
), unsafe_allow_html=True)

c4.markdown(kpi_html(
    "Gradient Bytes",
    f"{summary['total_gradient_bytes']:,}",
    "encrypted via AES-GCM"
), unsafe_allow_html=True)

c5.markdown(kpi_html(
    "Simulation Time",
    f"{summary['total_simulation_ms']:.0f} ms",
    f"KEM: {KEM_BACKEND}"
), unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Overhead comparison callout
# ---------------------------------------------------------------------------
avg_overhead = summary["avg_overhead_fraction"] * 100
adaptive_overhead = avg_overhead * (1 - 0.76)  # 76% reduction from JOURNAL-3

col_warn, col_note = st.columns(2)
with col_warn:
    st.markdown(f"""
    <div class="overhead-warn">
    ⚠️ <strong>Zhang et al. (Static L_j = {config['lj']}):</strong><br>
    Average KEM overhead = <strong>{avg_overhead:.1f}%</strong> of all wire bytes.<br>
    KEM re-keys every {config['lj']} rounds unconditionally.
    Total KEM cost: {summary['total_kem_bytes']:,} bytes.
    </div>""", unsafe_allow_html=True)
with col_note:
    st.markdown(f"""
    <div class="overhead-note">
    ✅ <strong>Adaptive PQBFL estimate (JOURNAL-3):</strong><br>
    Projected overhead ≈ <strong>{adaptive_overhead:.1f}%</strong> (~76% reduction).<br>
    KEM only fires when threat signal t &gt; threshold.
    Saves ≈ {int(summary['total_kem_bytes']*0.76):,} bytes over {summary['n_rounds']} rounds.
    </div>""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">📈 Training Convergence</div>', unsafe_allow_html=True)

chart_theme = {
    "config": {
        "background": "#0d1117",
        "view": {"stroke": "transparent"},
        "axis": {"labelColor": "#8888aa", "titleColor": "#8888aa",
                 "gridColor": "#1a1a2e", "domainColor": "#2a2a4a"},
        "legend": {"labelColor": "#ccccee", "titleColor": "#ccccee"},
    }
}

col_acc, col_loss = st.columns(2)

with col_acc:
    acc_chart = alt.Chart(df).mark_line(
        point=alt.OverlayMarkDef(filled=True, size=40),
        color="#6666ff",
        strokeWidth=2,
    ).encode(
        x=alt.X("round:Q", title="Training Round"),
        y=alt.Y("accuracy:Q", title="Accuracy", scale=alt.Scale(zero=False)),
        tooltip=["round", "accuracy"],
    ).properties(
        title="Global Model Accuracy",
        height=260,
    ).configure_title(color="#ccccff", fontSize=13)
    st.altair_chart(acc_chart, use_container_width=True)

with col_loss:
    loss_chart = alt.Chart(df).mark_line(
        point=alt.OverlayMarkDef(filled=True, size=40),
        color="#ff6666",
        strokeWidth=2,
    ).encode(
        x=alt.X("round:Q", title="Training Round"),
        y=alt.Y("loss:Q", title="Cross-Entropy Loss", scale=alt.Scale(zero=False)),
        tooltip=["round", "loss"],
    ).properties(
        title="Global Model Loss",
        height=260,
    ).configure_title(color="#ccccff", fontSize=13)
    st.altair_chart(loss_chart, use_container_width=True)

# ---------------------------------------------------------------------------
# Overhead chart
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">🔑 Communication Overhead Analysis</div>',
            unsafe_allow_html=True)

col_wire, col_frac = st.columns(2)

with col_wire:
    df_melt = df[["round", "gradient_bytes", "kem_bytes"]].melt(
        id_vars="round",
        var_name="type",
        value_name="bytes",
    )
    df_melt["type"] = df_melt["type"].map({
        "gradient_bytes": "Gradient (AES-GCM)",
        "kem_bytes": "KEM overhead (Kyber)",
    })

    stacked = alt.Chart(df_melt).mark_bar().encode(
        x=alt.X("round:Q", title="Training Round"),
        y=alt.Y("bytes:Q", title="Bytes"),
        color=alt.Color("type:N",
            scale=alt.Scale(
                domain=["Gradient (AES-GCM)", "KEM overhead (Kyber)"],
                range=["#4444cc", "#cc4444"],
            ),
            legend=alt.Legend(title="Payload type", orient="bottom"),
        ),
        tooltip=["round", "type", "bytes"],
    ).properties(
        title="Wire Bytes per Round (Stacked)",
        height=280,
    ).configure_title(color="#ccccff", fontSize=13)
    st.altair_chart(stacked, use_container_width=True)

with col_frac:
    frac_chart = alt.Chart(df).mark_area(
        color="#cc6600",
        opacity=0.7,
        line={"color": "#ff8800", "strokeWidth": 2},
    ).encode(
        x=alt.X("round:Q", title="Training Round"),
        y=alt.Y("overhead_fraction:Q",
                title="KEM Fraction of Total Wire",
                scale=alt.Scale(domain=[0, 1])),
        tooltip=["round", "overhead_fraction"],
    ).properties(
        title=alt.TitleParams("KEM Overhead Fraction per Round",
                              color="#ccccff", fontSize=13),
        height=280,
    )

    # Add average line (no configure_* — it's a sub-spec)
    avg_val = summary["avg_overhead_fraction"]
    avg_line = alt.Chart(pd.DataFrame({"y": [avg_val]})).mark_rule(
        color="#ffff00", strokeWidth=1.5, strokeDash=[5, 5]
    ).encode(y="y:Q")

    combined = alt.layer(frac_chart, avg_line)
    st.altair_chart(combined, use_container_width=True)

# ---------------------------------------------------------------------------
# Lj sensitivity analysis
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">🔬 Static L_j Overhead Model (Kyber-768)</div>',
            unsafe_allow_html=True)

lj_vals   = list(range(2, 21))
gradient_size = 46 * 4 + 4 + 16 + 12   # float32 weights + bias + GCM tag + nonce  (bytes)
kyber_cost = KEM_PUBLIC_KEY_BYTES + KEM_CIPHERTEXT_BYTES  # per client per epoch (2272 B)

lj_df = pd.DataFrame({
    "lj": lj_vals,
    "amortised_kem_bytes_per_round": [kyber_cost / lj for lj in lj_vals],
    "overhead_fraction": [
        (kyber_cost / lj) / (gradient_size + kyber_cost / lj)
        for lj in lj_vals
    ],
})

lj_chart = alt.Chart(lj_df).mark_line(
    point=True, color="#ff8800", strokeWidth=2
).encode(
    x=alt.X("lj:Q", title="Ratchet Window L_j"),
    y=alt.Y("overhead_fraction:Q", title="KEM Overhead Fraction",
            scale=alt.Scale(domain=[0, 1])),
    tooltip=["lj", alt.Tooltip("overhead_fraction:Q", format=".2%"),
             alt.Tooltip("amortised_kem_bytes_per_round:Q", format=".1f",
                         title="KEM bytes/round")],
).properties(
    title=alt.TitleParams("KEM Overhead vs L_j (static — Zhang et al. model)",
                          color="#ccccff", fontSize=13),
    height=260,
)

current_mark = alt.Chart(
    pd.DataFrame({"lj": [config["lj"]],
                  "overhead_fraction": [kyber_cost / config["lj"] / (gradient_size + kyber_cost / config["lj"])]})
).mark_point(color="#ff2222", size=200, shape="diamond").encode(
    x="lj:Q", y="overhead_fraction:Q",
    tooltip=[alt.Tooltip("lj:Q", title="Current Lj"),
             alt.Tooltip("overhead_fraction:Q", format=".2%")],
)

# configure_title only on the final layered chart — not on sub-specs
st.altair_chart(
    alt.layer(lj_chart, current_mark).configure_title(color="#ccccff", fontSize=13),
    use_container_width=True,
)
st.caption(f"🔴 Diamond = your current L_j = {config['lj']}. "
           f"Lower L_j → more KEM exchanges → higher overhead. "
           f"Higher L_j → fewer rekeys → weaker Post-Compromise Security.")

# ---------------------------------------------------------------------------
# Per-round table
# ---------------------------------------------------------------------------
with st.expander("📋 Per-round data table"):
    disp_df = df.copy()
    disp_df["accuracy"] = disp_df["accuracy"].map("{:.4f}".format)
    disp_df["loss"]     = disp_df["loss"].map("{:.4f}".format)
    disp_df["overhead_fraction"] = disp_df["overhead_fraction"].map("{:.2%}".format)
    disp_df.columns     = ["Round","Accuracy","Loss","KEM Exchanges",
                            "Wire Bytes","Gradient Bytes","KEM Bytes",
                            "Overhead Frac","Agg ms"]
    st.dataframe(disp_df, use_container_width=True, hide_index=True)

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
st.download_button(
    label="⬇ Download Results JSON",
    data=json.dumps(results, indent=2),
    file_name="zhang2025_pqfl_results.json",
    mime="application/json",
)

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown("---")
st.caption(
    "Zhang et al. (2025) · IEEE TDSC · "
    "Implemented as the static PQC-FL baseline for comparison with "
    "Threat-Adaptive PQBFL (JOURNAL-3). "
    f"KEM: **{KEM_BACKEND}** · "
    f"PK: {KEM_PUBLIC_KEY_BYTES} B · CT: {KEM_CIPHERTEXT_BYTES} B"
)
