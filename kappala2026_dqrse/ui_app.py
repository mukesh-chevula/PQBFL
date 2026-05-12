"""
ui_app.py — Streamlit dashboard for Kappala et al. (2026) DQRSE simulation.

Launch:
    streamlit run ui_app.py --server.port 8503
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import altair as alt
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent))

from kappala2026.crypto.kem import KEM_BACKEND, KEM_PUBLIC_KEY_BYTES, KEM_CIPHERTEXT_BYTES
from kappala2026.adaptive.policy import DataTier, EncryptionMode, SelectiveEncryptionPolicy
from simulate import run_simulation

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Kappala et al. (2026) — DQRSE Simulator",
    page_icon="🌾",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

.hero {
    background: linear-gradient(135deg, #0a2a0a, #1a4a1a, #0d3d2a);
    border-radius: 16px;
    padding: 2rem 2.5rem;
    margin-bottom: 1.5rem;
    color: white;
}
.hero h1  { font-size: 1.55rem; font-weight: 700; margin: 0 0 .3rem 0; }
.hero p   { font-size: 0.88rem; opacity: 0.75; margin: 0; }
.hero .badge {
    display: inline-block;
    background: rgba(255,255,255,0.12);
    border: 1px solid rgba(255,255,255,0.22);
    border-radius: 20px;
    padding: 3px 12px;
    font-size: 0.74rem;
    margin-top: 0.6rem;
    margin-right: 6px;
}

.kpi-card {
    background: #0d1a0d;
    border: 1px solid #1a3a1a;
    border-radius: 12px;
    padding: 1rem 1.2rem;
    text-align: center;
}
.kpi-label { font-size: 0.70rem; color: #669966; text-transform: uppercase;
              letter-spacing: .05em; margin-bottom: .25rem; }
.kpi-value { font-size: 1.65rem; font-weight: 700; color: #ccffcc; }
.kpi-sub   { font-size: 0.70rem; color: #3a7a3a; margin-top: .2rem; }

.gap-warn {
    background: linear-gradient(135deg, #2a1a00, #3a2800);
    border-left: 4px solid #ff9900;
    border-radius: 8px;
    padding: 0.8rem 1rem;
    margin: .4rem 0;
    font-size: 0.84rem;
    color: #ffcc88;
}
.pqbfl-note {
    background: linear-gradient(135deg, #001a2a, #002a3a);
    border-left: 4px solid #4499ff;
    border-radius: 8px;
    padding: 0.8rem 1rem;
    margin: .4rem 0;
    font-size: 0.84rem;
    color: #aaccff;
}
.section-head {
    font-size: 1rem; font-weight: 600; color: #55cc55;
    border-bottom: 1px solid #1a3a1a;
    padding-bottom: .3rem; margin: 1.2rem 0 .8rem 0;
}
.tier-table td, .tier-table th {
    padding: 4px 10px; border: 1px solid #2a3a2a;
    font-size: 0.80rem;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Hero
# ---------------------------------------------------------------------------
st.markdown("""
<div class="hero">
  <h1>🌾 Kappala et al. (2026) — Dynamic Quantum-Resistant Selective Encryption</h1>
  <p>IEEE Access, 2026 &nbsp;·&nbsp;
     ML-KEM (Kyber-512) + AES-256-GCM + Adaptive Threat Thresholds · Agricultural Sensor Networks</p>
  <span class="badge">ML-KEM (Kyber)</span>
  <span class="badge">Adaptive θ Threshold</span>
  <span class="badge">Selective Encryption</span>
  <span class="badge">IoT / Agricultural</span>
  <span class="badge">Energy-Aware</span>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Simulation Parameters")
    st.markdown("**Network**")
    n_sensors = st.slider("Sensor Nodes",    2, 20,  5, 1)
    pkt_round = st.slider("Packets / Round", 10, 100, 30, 5)
    n_rounds  = st.slider("Simulation Rounds", 5, 50, 20, 1)

    st.markdown("---")
    st.markdown("**Adaptive Thresholds**")
    theta_lo = st.slider("θ_lo (low threshold)",  0.05, 0.50, 0.25, 0.05,
                          help="Below this → relax encryption (energy saving)")
    theta_hi = st.slider("θ_hi (high threshold)", 0.51, 0.95, 0.65, 0.05,
                          help="Above this → maximum encryption (all tiers Kyber)")
    decay_s  = st.slider("Threat decay (s/round)", 0.5, 10.0, 2.0, 0.5,
                          help="Simulated seconds between rounds — controls how fast threat fades")

    st.markdown("---")
    st.markdown("**Scenario**")
    use_attack = st.toggle("Inject Attack Events", value=True,
                            help="Simulates replay, tamper, auth-failure events at specific rounds")

    st.markdown("---")
    st.caption(f"KEM: **{KEM_BACKEND}**")
    st.caption(f"PK: {KEM_PUBLIC_KEY_BYTES} B · CT: {KEM_CIPHERTEXT_BYTES} B")
    run_btn = st.button("▶ Run Simulation", type="primary", use_container_width=True)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
if "kappala_results" not in st.session_state:
    st.session_state["kappala_results"] = None

if run_btn:
    with st.spinner("Simulating sensor field…"):
        results = run_simulation(
            n_sensors         = n_sensors,
            packets_per_round = pkt_round,
            n_rounds          = n_rounds,
            theta_lo          = theta_lo,
            theta_hi          = theta_hi,
            decay_seconds     = decay_s,
            attack_scenario   = use_attack,
            verbose           = False,
        )
        st.session_state["kappala_results"] = results
    st.success("Simulation complete!")

results = st.session_state.get("kappala_results")

# ---------------------------------------------------------------------------
# Idle state
# ---------------------------------------------------------------------------
if results is None:
    st.info("👈 Configure parameters and click **Run Simulation** to start.")

    # Policy table preview
    st.markdown('<div class="section-head">📋 Adaptive Policy Table (Kappala et al. Table III)</div>',
                unsafe_allow_html=True)
    policy = SelectiveEncryptionPolicy(0.25, 0.65)
    rows   = policy.policy_table()
    pol_df = pd.DataFrame(rows)
    pol_df.columns = ["Tier", "Threat Zone", "θ", "Encryption Mode", "Energy Cost (rel.)", "Latency (ms)"]
    st.dataframe(pol_df, use_container_width=True, hide_index=True)

    st.markdown("""
    <div class="gap-warn">
    ⚠️ <strong>Gap vs JOURNAL-3 (Adaptive PQBFL):</strong><br>
    Kappala et al. computes θ from <em>local sensor events only</em> — no blockchain
    verification log, no ratcheting, no FL gradient protection. The threat signal is
    node-local and unverifiable by any peer.
    </div>
    <div class="pqbfl-note">
    🔵 <strong>JOURNAL-3 extends this idea by:</strong><br>
    ① Sourcing θ from <em>on-chain blockchain telemetry</em> (verifiable, distributed).<br>
    ② Driving an ML-KEM <em>ratchet window L_j</em> (Post-Compromise Security).<br>
    ③ Protecting <em>federated learning gradients</em>, not raw sensor readings.
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
summary   = results["summary"]
per_round = results["per_round"]
cfg       = results["config"]
df        = pd.DataFrame(per_round)

# ---------------------------------------------------------------------------
# KPI Row
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">📊 Simulation Summary</div>', unsafe_allow_html=True)

kpi = lambda lbl, val, sub: f"""
<div class="kpi-card">
  <div class="kpi-label">{lbl}</div>
  <div class="kpi-value">{val}</div>
  <div class="kpi-sub">{sub}</div>
</div>"""

c1, c2, c3, c4, c5 = st.columns(5)
c1.markdown(kpi("Kyber Packets",
    f"{summary['kyber_packets']:,}",
    f"{summary['kyber_fraction']*100:.1f}% of total"), unsafe_allow_html=True)
c2.markdown(kpi("Energy Saved",
    f"{summary['energy_saving_pct']:.1f}%",
    "vs always-Kyber baseline"), unsafe_allow_html=True)
c3.markdown(kpi("Total Energy",
    f"{summary['total_energy_uj']/1000:.1f} mJ",
    f"actual adaptive"), unsafe_allow_html=True)
c4.markdown(kpi("KEM Wire Overhead",
    f"{summary['kem_overhead_frac']*100:.1f}%",
    "Kyber CT / total wire"), unsafe_allow_html=True)
c5.markdown(kpi("Decrypt Errors",
    f"{summary['decryption_errors']}",
    f"over {summary['total_packets']:,} pkts"), unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Gap callout
# ---------------------------------------------------------------------------
col_gap, col_pqbfl = st.columns(2)
with col_gap:
    st.markdown(f"""
    <div class="gap-warn">
    ⚠️ <strong>Kappala et al. (θ_lo={cfg['theta_lo']}, θ_hi={cfg['theta_hi']}):</strong><br>
    Kyber used on {summary['kyber_fraction']*100:.1f}% of packets.
    Energy saved: <strong>{summary['energy_saving_pct']:.1f}%</strong> vs always-Kyber.<br>
    Threat θ is <em>node-local</em> — no blockchain verification.
    No ratchet = no Post-Compromise Security.
    </div>""", unsafe_allow_html=True)
with col_pqbfl:
    st.markdown(f"""
    <div class="pqbfl-note">
    🔵 <strong>JOURNAL-3 (Adaptive PQBFL) adds:</strong><br>
    On-chain θ from blockchain telemetry → verifiable by all peers.<br>
    ML-KEM ratchet window L_j → formal Post-Compromise Security.<br>
    Federated gradient protection → healthcare AI privacy guarantee.
    </div>""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">📈 Threat Score θ and Encryption Mode Distribution</div>',
            unsafe_allow_html=True)

col_theta, col_modes = st.columns(2)

with col_theta:
    # Threat trajectory with threshold bands
    theta_chart = alt.Chart(df).mark_line(
        color="#44cc44", strokeWidth=2,
        point=alt.OverlayMarkDef(filled=True, size=40, color="#44cc44"),
    ).encode(
        x=alt.X("round:Q", title="Simulation Round"),
        y=alt.Y("avg_theta:Q", title="Avg Threat Score θ",
                scale=alt.Scale(domain=[0, 1])),
        tooltip=[alt.Tooltip("round:Q"), alt.Tooltip("avg_theta:Q", format=".3f")],
    ).properties(
        title=alt.TitleParams("Threat Score θ per Round", color="#ccffcc", fontSize=13),
        height=280,
    )
    # θ_lo line
    lo_line = alt.Chart(pd.DataFrame({"y": [cfg["theta_lo"]]})).mark_rule(
        color="#ffff00", strokeWidth=1.5, strokeDash=[4, 4]
    ).encode(y="y:Q")
    # θ_hi line
    hi_line = alt.Chart(pd.DataFrame({"y": [cfg["theta_hi"]]})).mark_rule(
        color="#ff6600", strokeWidth=1.5, strokeDash=[4, 4]
    ).encode(y="y:Q")
    # Attack event markers
    attack_rounds = [r for r in per_round if r["injected_events"]]
    if attack_rounds:
        atk_df = pd.DataFrame({"round": [r["round"] for r in attack_rounds],
                                "avg_theta": [r["avg_theta"] for r in attack_rounds]})
        atk_marks = alt.Chart(atk_df).mark_point(
            color="#ff2222", size=150, shape="triangle-up"
        ).encode(x="round:Q", y="avg_theta:Q",
                 tooltip=[alt.Tooltip("round:Q"), alt.Tooltip("avg_theta:Q", format=".3f")])
        combined_theta = alt.layer(theta_chart, lo_line, hi_line, atk_marks)
    else:
        combined_theta = alt.layer(theta_chart, lo_line, hi_line)

    st.altair_chart(combined_theta, use_container_width=True)
    st.caption("🟡 dashed = θ_lo  |  🟠 dashed = θ_hi  |  🔴▲ = injected attack event")

with col_modes:
    # Stacked bar of encryption modes per round
    df_modes = df[["round", "kyber_count", "aes_only_count", "plaintext_count"]].melt(
        id_vars="round", var_name="mode", value_name="count"
    )
    df_modes["mode"] = df_modes["mode"].map({
        "kyber_count":     "KYBER_AES",
        "aes_only_count":  "AES_ONLY",
        "plaintext_count": "PLAINTEXT",
    })
    mode_chart = alt.Chart(df_modes).mark_bar().encode(
        x=alt.X("round:Q", title="Round"),
        y=alt.Y("count:Q", title="Packets"),
        color=alt.Color("mode:N",
            scale=alt.Scale(
                domain=["KYBER_AES", "AES_ONLY", "PLAINTEXT"],
                range=["#4444cc", "#44aacc", "#447744"],
            ),
            legend=alt.Legend(title="Mode", orient="bottom"),
        ),
        tooltip=["round", "mode", "count"],
    ).properties(
        title=alt.TitleParams("Encryption Mode Distribution per Round",
                              color="#ccffcc", fontSize=13),
        height=280,
    )
    st.altair_chart(mode_chart, use_container_width=True)

# ---------------------------------------------------------------------------
# Energy analysis
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">⚡ Energy Analysis</div>', unsafe_allow_html=True)

col_e1, col_e2 = st.columns(2)

with col_e1:
    energy_chart = alt.Chart(df).mark_area(
        color="#44aa44", opacity=0.65,
        line={"color": "#88ff88", "strokeWidth": 2},
    ).encode(
        x=alt.X("round:Q", title="Round"),
        y=alt.Y("total_energy_uj:Q", title="Energy (μJ)",
                scale=alt.Scale(zero=True)),
        tooltip=[alt.Tooltip("round:Q"),
                 alt.Tooltip("total_energy_uj:Q", format=",.0f", title="Energy (μJ)")],
    ).properties(
        title=alt.TitleParams("Energy Consumed per Round (μJ)",
                              color="#ccffcc", fontSize=13),
        height=260,
    )
    st.altair_chart(energy_chart, use_container_width=True)

with col_e2:
    # Kyber fraction over time
    kyber_frac_chart = alt.Chart(df).mark_line(
        color="#cc88ff", strokeWidth=2,
        point=alt.OverlayMarkDef(filled=True, size=35, color="#cc88ff"),
    ).encode(
        x=alt.X("round:Q", title="Round"),
        y=alt.Y("kyber_fraction:Q", title="Kyber Fraction",
                scale=alt.Scale(domain=[0, 1])),
        tooltip=[alt.Tooltip("round:Q"),
                 alt.Tooltip("kyber_fraction:Q", format=".2%")],
    ).properties(
        title=alt.TitleParams("Kyber-AES Packet Fraction per Round",
                              color="#ccffcc", fontSize=13),
        height=260,
    )
    st.altair_chart(kyber_frac_chart, use_container_width=True)

# ---------------------------------------------------------------------------
# Threshold sensitivity model
# ---------------------------------------------------------------------------
st.markdown('<div class="section-head">🔬 θ Threshold Sensitivity — Policy Decision Space</div>',
            unsafe_allow_html=True)

# Show how changing θ_lo/θ_hi changes Kyber fraction for a 20/35/45 tier mix
tier_fracs = {DataTier.CRITICAL: 0.20, DataTier.SENSITIVE: 0.35, DataTier.NORMAL: 0.45}

def kyber_fraction_for_thresholds(tlo, thi, theta, tier_fracs):
    pol = SelectiveEncryptionPolicy(theta_lo=tlo, theta_hi=thi)
    kyber = sum(
        frac
        for tier, frac in tier_fracs.items()
        if pol.decide(tier, theta) == EncryptionMode.KYBER_AES
    )
    return kyber

theta_vals = [round(x, 2) for x in np.arange(0.0, 1.01, 0.05)]
rows_sense = []
for tv in theta_vals:
    kf = kyber_fraction_for_thresholds(cfg["theta_lo"], cfg["theta_hi"], tv, tier_fracs)
    rows_sense.append({"theta": tv, "kyber_fraction": kf})

sense_df = pd.DataFrame(rows_sense)
sense_chart = alt.Chart(sense_df).mark_line(
    color="#ff8844", strokeWidth=2.5,
    point=alt.OverlayMarkDef(filled=True, size=40, color="#ff8844"),
).encode(
    x=alt.X("theta:Q", title="Threat Score θ"),
    y=alt.Y("kyber_fraction:Q", title="Kyber-AES Packet Fraction",
            scale=alt.Scale(domain=[0, 1])),
    tooltip=[alt.Tooltip("theta:Q", format=".2f"),
             alt.Tooltip("kyber_fraction:Q", format=".0%")],
).properties(
    title=alt.TitleParams(
        f"Kyber Fraction vs θ  (θ_lo={cfg['theta_lo']}, θ_hi={cfg['theta_hi']}, tier mix 20/35/45%)",
        color="#ffddcc", fontSize=12),
    height=240,
)

# Current simulation avg theta
avg_theta_overall = float(df["avg_theta"].mean())
cur_mark = alt.Chart(pd.DataFrame({
    "theta": [avg_theta_overall],
    "kyber_fraction": [kyber_fraction_for_thresholds(
        cfg["theta_lo"], cfg["theta_hi"], avg_theta_overall, tier_fracs)],
})).mark_point(color="#ff2222", size=180, shape="diamond").encode(
    x="theta:Q", y="kyber_fraction:Q",
    tooltip=[alt.Tooltip("theta:Q", format=".3f", title="Sim avg θ"),
             alt.Tooltip("kyber_fraction:Q", format=".0%")],
)

st.altair_chart(
    alt.layer(sense_chart, cur_mark).configure_title(color="#ffddcc", fontSize=12),
    use_container_width=True,
)
st.caption(f"🔴 Diamond = simulation average θ = {avg_theta_overall:.3f}. "
           "Step function reflects the 3-tier policy table.")

# ---------------------------------------------------------------------------
# Per-round table
# ---------------------------------------------------------------------------
with st.expander("📋 Per-round detail table"):
    disp = df[["round","avg_theta","kyber_count","aes_only_count",
               "plaintext_count","total_energy_uj","total_wire_bytes",
               "kyber_wire_bytes","decryption_errors"]].copy()
    disp["avg_theta"]       = disp["avg_theta"].map("{:.3f}".format)
    disp["total_energy_uj"] = disp["total_energy_uj"].map("{:,.0f}".format)
    disp.columns = ["Round","θ","Kyber","AES-Only","Plaintext",
                    "Energy (μJ)","Wire (B)","KEM Wire (B)","Dec. Errors"]
    st.dataframe(disp, use_container_width=True, hide_index=True)

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
st.download_button(
    "⬇ Download Results JSON",
    data=json.dumps(results, indent=2),
    file_name="kappala2026_results.json",
    mime="application/json",
)

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown("---")
st.caption(
    "Kappala et al. (2026) · IEEE Access · "
    "Implemented as the adaptive PQC precedent for comparison with "
    "Threat-Adaptive PQBFL (JOURNAL-3). "
    f"KEM: **{KEM_BACKEND}** · "
    f"PK: {KEM_PUBLIC_KEY_BYTES} B · CT: {KEM_CIPHERTEXT_BYTES} B"
)
