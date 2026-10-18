"""
PrivGuard: Privileged Account Anomaly Monitor
Production-Grade SOC Anomaly Command Center Dashboard
Built with Streamlit and Plotly
"""

from datetime import datetime
from pathlib import Path
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ---------------------------------------------------------
# 1. PAGE CONFIGURATION & METADATA
# ---------------------------------------------------------
st.set_page_config(
    page_title="PrivGuard | SOC Anomaly Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------
# 2. CONSTANTS & THEME PALETTES
# ---------------------------------------------------------
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",  # Neon Crimson
    "HIGH": "#f97316",      # Threat Amber-Orange
    "MEDIUM": "#eab308",    # Warning Yellow
    "LOW": "#10b981",       # Safe Mint / Emerald
}

EVENT_ID_LABELS = {
    4672: "Event 4672: Special Privileges Assigned",
    4624: "Event 4624: Successful Logon Activity",
    4625: "Event 4625: Failed Logon Attempt",
}

PERSONA_METADATA = {
    "admin_tanish": {
        "title": "SecOps Administrator",
        "badge_color": "#38bdf8",
        "active_hours": "08:00 – 19:00",
        "auth_hosts": "SEC-WS-01, DC-PROD-01, SEC-MGMT-02, SIEM-COLLECTOR-01",
        "logon_types": "Interactive (2), RDP (10), Network (3)",
    },
    "admin_himanshu": {
        "title": "Infrastructure Administrator",
        "badge_color": "#818cf8",
        "active_hours": "09:00 – 21:00",
        "auth_hosts": "INFRA-WS-02, DC-PROD-02, APP-SRV-01, DB-SRV-02",
        "logon_types": "Interactive (2), Network (3), RDP (10)",
    },
    "admin_backup": {
        "title": "Backup Service Account (Automated)",
        "badge_color": "#ec4899",
        "active_hours": "00:00 – 06:00 (Batch Window)",
        "auth_hosts": "BKP-SRV-01, STORAGE-NAS-01, DC-PROD-01, DB-SRV-01",
        "logon_types": "Batch (4), Service (5), Network (3)",
    },
}

# ---------------------------------------------------------
# 3. ADVANCED SOC DARK THEME CSS
# ---------------------------------------------------------
SOC_CSS = """
<style>
/* Font Imports */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700;800&display=swap');

/* Root Variables */
:root {
    --soc-bg-primary: #070b14;
    --soc-bg-secondary: #0b1120;
    --soc-card-bg: rgba(15, 23, 42, 0.75);
    --soc-border: rgba(56, 189, 248, 0.16);
    --soc-cyan: #38bdf8;
    --soc-red: #ef4444;
    --soc-orange: #f97316;
    --soc-yellow: #eab308;
    --soc-green: #10b981;
}

/* Global Background & Typography */
html, body, [data-testid="stAppViewContainer"] {
    background-color: var(--soc-bg-primary) !important;
    background-image: 
        radial-gradient(at 0% 0%, rgba(14, 165, 233, 0.07) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(99, 102, 241, 0.07) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(15, 23, 42, 0.8) 0px, transparent 50%) !important;
    color: #e2e8f0 !important;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
}

/* Sidebar Styling */
[data-testid="stSidebar"] {
    background-color: var(--soc-bg-secondary) !important;
    border-right: 1px solid rgba(56, 189, 248, 0.15) !important;
    box-shadow: 4px 0 25px rgba(0, 0, 0, 0.6);
}

[data-testid="stSidebar"] hr {
    border-color: rgba(148, 163, 184, 0.15) !important;
}

/* Header Banner */
.soc-header-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1.25rem 1.75rem;
    background: linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.7) 100%);
    border: 1px solid var(--soc-border);
    border-radius: 14px;
    margin-bottom: 1.5rem;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.45);
    backdrop-filter: blur(10px);
}

.soc-title-wrap {
    display: flex;
    align-items: center;
    gap: 14px;
}

.soc-shield-icon {
    font-size: 2.2rem;
    filter: drop-shadow(0 0 12px rgba(56, 189, 248, 0.6));
}

.soc-title {
    font-size: 1.8rem;
    font-weight: 800;
    margin: 0;
    background: linear-gradient(90deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    letter-spacing: -0.5px;
    line-height: 1.15;
}

.soc-subtitle {
    color: #94a3b8;
    font-size: 0.86rem;
    margin-top: 3px;
    font-weight: 400;
    letter-spacing: 0.2px;
}

.soc-status-badge {
    display: inline-flex;
    align-items: center;
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.4);
    padding: 7px 16px;
    border-radius: 9999px;
    font-size: 0.74rem;
    font-weight: 700;
    color: #34d399;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
}

.pulse-dot {
    width: 8px;
    height: 8px;
    background-color: #10b981;
    border-radius: 50%;
    margin-right: 8px;
    box-shadow: 0 0 10px #10b981;
    animation: soc-pulse 1.8s infinite;
}

@keyframes soc-pulse {
    0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
    70% { transform: scale(1); box-shadow: 0 0 0 9px rgba(16, 185, 129, 0); }
    100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}

/* KPI Metric Cards */
.soc-kpi-card {
    background: linear-gradient(145deg, rgba(30, 41, 59, 0.75) 0%, rgba(15, 23, 42, 0.85) 100%);
    border: 1px solid rgba(148, 163, 184, 0.14);
    border-top: 3px solid #38bdf8;
    border-radius: 12px;
    padding: 1.15rem 1.25rem;
    box-shadow: 0 6px 20px -2px rgba(0, 0, 0, 0.5);
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
    backdrop-filter: blur(8px);
    height: 100%;
}

.soc-kpi-card:hover {
    border-color: rgba(56, 189, 248, 0.45);
    box-shadow: 0 10px 28px -4px rgba(56, 189, 248, 0.25);
    transform: translateY(-2px);
}

.kpi-accent-cyan { border-top-color: #38bdf8 !important; }
.kpi-accent-red { border-top-color: #ef4444 !important; }
.kpi-accent-green { border-top-color: #10b981 !important; }
.kpi-accent-purple { border-top-color: #a855f7 !important; }

.soc-kpi-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.soc-kpi-label {
    font-size: 0.73rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.9px;
    color: #94a3b8;
}

.soc-kpi-icon {
    font-size: 1.1rem;
    opacity: 0.9;
}

.soc-kpi-value {
    font-size: 1.95rem;
    font-weight: 800;
    color: #f8fafc;
    letter-spacing: -0.5px;
    margin-bottom: 0.35rem;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1.1;
}

.soc-kpi-subtext {
    font-size: 0.77rem;
    color: #64748b;
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
}

.soc-pill {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 0.72rem;
    font-family: 'JetBrains Mono', monospace;
}

.pill-cyan { background: rgba(56, 189, 248, 0.16); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.35); }
.pill-red { background: rgba(239, 68, 68, 0.16); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.35); }
.pill-green { background: rgba(16, 185, 129, 0.16); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.35); }
.pill-purple { background: rgba(168, 85, 247, 0.16); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.35); }

/* Section Containers */
.soc-panel {
    background: linear-gradient(145deg, rgba(20, 30, 48, 0.65) 0%, rgba(15, 23, 42, 0.75) 100%);
    border: 1px solid rgba(148, 163, 184, 0.12);
    border-radius: 12px;
    padding: 1.25rem;
    margin-bottom: 1.25rem;
    box-shadow: 0 4px 18px rgba(0, 0, 0, 0.35);
}

.soc-panel-title {
    font-size: 0.95rem;
    font-weight: 700;
    color: #cbd5e1;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 8px;
    letter-spacing: 0.2px;
}

/* Badges for Data Table */
.badge-critical {
    background: rgba(239, 68, 68, 0.2) !important;
    color: #f87171 !important;
    border: 1px solid rgba(239, 68, 68, 0.5) !important;
    padding: 3px 8px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 0.72rem;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.5px;
}

.badge-high {
    background: rgba(249, 115, 22, 0.2) !important;
    color: #fb923c !important;
    border: 1px solid rgba(249, 115, 22, 0.5) !important;
    padding: 3px 8px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 0.72rem;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.5px;
}

.badge-medium {
    background: rgba(234, 179, 8, 0.2) !important;
    color: #facc15 !important;
    border: 1px solid rgba(234, 179, 8, 0.5) !important;
    padding: 3px 8px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 0.72rem;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.5px;
}

.badge-low {
    background: rgba(16, 185, 129, 0.2) !important;
    color: #34d399 !important;
    border: 1px solid rgba(16, 185, 129, 0.5) !important;
    padding: 3px 8px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 0.72rem;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.5px;
}

/* Sidebar Custom Elements */
.sidebar-brand-box {
    padding: 0.75rem 0.5rem 1.25rem 0.5rem;
    text-align: left;
}

.sidebar-title {
    font-size: 1.25rem;
    font-weight: 800;
    color: #38bdf8;
    display: flex;
    align-items: center;
    gap: 8px;
    letter-spacing: -0.3px;
}

.sidebar-desc {
    font-size: 0.76rem;
    color: #64748b;
    margin-top: 4px;
    line-height: 1.4;
}

.sidebar-status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    background: rgba(56, 189, 248, 0.08);
    border: 1px solid rgba(56, 189, 248, 0.25);
    border-radius: 6px;
    font-size: 0.72rem;
    color: #38bdf8;
    margin-top: 8px;
    font-family: 'JetBrains Mono', monospace;
}

/* Footer Styling */
.soc-footer {
    text-align: center;
    padding: 1.5rem 0;
    color: #64748b;
    font-size: 0.78rem;
    border-top: 1px solid rgba(148, 163, 184, 0.1);
    margin-top: 2rem;
    font-family: 'JetBrains Mono', monospace;
}
</style>
"""
st.markdown(SOC_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------
# 4. DATA LOADING & EVALUATION ENGINE
# ---------------------------------------------------------
@st.cache_data
def load_datasets():
    """
    Loads both synthetic_privileged_logs.csv and flagged_anomalies.csv cleanly.
    Validates file existence and standardizes datetime schemas.
    """
    script_dir = Path(__file__).parent.resolve()
    raw_path = script_dir / "synthetic_privileged_logs.csv"
    flagged_path = script_dir / "flagged_anomalies.csv"

    if not raw_path.exists():
        st.error(f"Critical Error: Missing raw event log file at: `{raw_path}`")
        st.stop()

    if not flagged_path.exists():
        st.error(f"Critical Error: Missing flagged anomalies file at: `{flagged_path}`")
        st.stop()

    df_raw = pd.read_csv(raw_path)
    df_flagged = pd.read_csv(flagged_path)

    # Convert timestamps to datetime
    df_raw["timestamp"] = pd.to_datetime(df_raw["timestamp"])
    df_flagged["timestamp"] = pd.to_datetime(df_flagged["timestamp"])

    return df_raw, df_flagged


@st.cache_data
def get_full_evaluated_data(df_raw: pd.DataFrame) -> pd.DataFrame:
    """
    Evaluates all raw records using multi-factor detection rules to support
    flexible thresholding (0-100) and full severity level filtering (CRITICAL, HIGH, MEDIUM, LOW).
    """
    try:
        import detect_anomalies
        df_copy = df_raw.copy()
        df_copy["dt"] = df_copy["timestamp"]
        eval_results = df_copy.apply(detect_anomalies.evaluate_record, axis=1, result_type="expand")
        df_eval = pd.concat([df_copy.drop(columns=["dt"]), eval_results], axis=1)
        return df_eval
    except Exception as exc:
        st.warning(f"Engine evaluation warning: {exc}. Utilizing flagged_anomalies.csv baseline.")
        return pd.DataFrame()


# Load Datasets
df_raw_logs, df_flagged_baseline = load_datasets()
df_full_evaluated = get_full_evaluated_data(df_raw_logs)

# Ground-truth evaluation metrics
total_events_analyzed = len(df_raw_logs)
forced_anomalies_count = int((df_raw_logs["is_forced_anomaly"] == 1).sum())

# Compute baseline accuracy and recall against ground truth
tp = int((df_flagged_baseline["is_forced_anomaly"] == 1).sum())
fp = int((df_flagged_baseline["is_forced_anomaly"] == 0).sum())
fn = forced_anomalies_count - tp
tn = total_events_analyzed - forced_anomalies_count - fp

baseline_recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0.0
baseline_precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0.0
baseline_accuracy = ((tp + tn) / total_events_analyzed) * 100 if total_events_analyzed > 0 else 0.0
baseline_f1 = (2 * baseline_precision * baseline_recall) / (baseline_precision + baseline_recall) if (baseline_precision + baseline_recall) > 0 else 0.0

active_personas = sorted(df_raw_logs["username"].unique().tolist())


# ---------------------------------------------------------
# 5. SIDEBAR CONTROLS
# ---------------------------------------------------------
with st.sidebar:
    st.markdown(
        """
        <div class="sidebar-brand-box">
            <div class="sidebar-title">
                <span>🛡️ PrivGuard</span>
            </div>
            <div class="sidebar-desc">
                Privileged Identity Threat Detection and Response (ITDR) SOC Analytics Engine
            </div>
            <div class="sidebar-status-pill">
                <span class="pulse-dot"></span> ENGINE: LIVE SOC MONITOR
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.divider()

    st.markdown("### 🎛️ SOC Filter Controls")

    # 1. Persona Selector Dropdown
    persona_options = ["All Personas (3)"] + active_personas
    selected_persona_option = st.selectbox(
        "Privileged Persona",
        options=persona_options,
        index=0,
        help="Filter telemetry by specific privileged user account or analyze all monitored personas.",
    )
    selected_persona = None if selected_persona_option == "All Personas (3)" else selected_persona_option

    # Persona Profile Quick Card
    if selected_persona and selected_persona in PERSONA_METADATA:
        p_meta = PERSONA_METADATA[selected_persona]
        st.markdown(
            f"""
            <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 10px; margin-bottom: 12px; font-size: 0.78rem;">
                <div style="font-weight: 700; color: {p_meta['badge_color']};">{p_meta['title']}</div>
                <div style="color: #94a3b8; margin-top: 4px;"><b>Active Window:</b> {p_meta['active_hours']}</div>
                <div style="color: #94a3b8; margin-top: 2px;"><b>Logon Types:</b> {p_meta['logon_types']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 2. Risk Score Threshold Slider (Default: 45)
    risk_threshold = st.slider(
        "Risk Score Threshold (>=)",
        min_value=0,
        max_value=100,
        value=45,
        step=5,
        help="Filter events with normalized composite risk score greater than or equal to threshold. (Default: 45)",
    )

    # 3. Severity Level Filter
    severity_options = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    # Determine sensible default based on threshold
    if risk_threshold >= 70:
        default_severities = ["CRITICAL"]
    elif risk_threshold >= 45:
        default_severities = ["CRITICAL", "HIGH"]
    elif risk_threshold >= 25:
        default_severities = ["CRITICAL", "HIGH", "MEDIUM"]
    else:
        default_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    selected_severities = st.multiselect(
        "Severity Level Filter",
        options=severity_options,
        default=default_severities,
        help="Select threat severity levels to include in the dashboard analytics.",
    )

    # Quick Reset Filters Button
    if st.button("🔄 Reset Filters to SOC Default", width="stretch"):
        st.session_state.clear()
        st.rerun()

    st.divider()

    # Telemetry Status Info
    st.markdown("### 📡 Data Source Telemetry")
    st.markdown(
        f"""
        <div style="font-size: 0.77rem; color: #94a3b8; line-height: 1.6; font-family: 'JetBrains Mono', monospace;">
            <div><span style="color: #10b981;">✔</span> <b>synthetic_privileged_logs.csv</b>: {len(df_raw_logs):,} rows</div>
            <div><span style="color: #10b981;">✔</span> <b>flagged_anomalies.csv</b>: {len(df_flagged_baseline):,} rows</div>
            <div style="margin-top: 6px; color: #64748b;">Telemetry Window: Oct 01 - Oct 31, 2026</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------
# 6. DYNAMIC DATA FILTERING
# ---------------------------------------------------------
# If threshold < 45 or MEDIUM/LOW selected, use the full evaluated dataset if available
if (risk_threshold < 45 or any(s in selected_severities for s in ["MEDIUM", "LOW"])) and not df_full_evaluated.empty:
    working_df = df_full_evaluated.copy()
else:
    working_df = df_flagged_baseline.copy()

# Apply Persona Filter
if selected_persona:
    filtered_df = working_df[working_df["username"] == selected_persona].copy()
else:
    filtered_df = working_df.copy()

# Apply Risk Score Threshold
filtered_df = filtered_df[filtered_df["risk_score"] >= risk_threshold]

# Apply Severity Filter
if selected_severities:
    filtered_df = filtered_df[filtered_df["risk_severity"].isin(selected_severities)]
else:
    filtered_df = filtered_df.iloc[0:0]  # Empty if none selected

# Sort by timestamp descending
filtered_df = filtered_df.sort_values(by="timestamp", ascending=False).reset_index(drop=True)


# ---------------------------------------------------------
# 7. TOP EXECUTIVE SOC HEADER & STATUS
# ---------------------------------------------------------
st.markdown(
    f"""
    <div class="soc-header-banner">
        <div class="soc-title-wrap">
            <span class="soc-shield-icon">🛡️</span>
            <div>
                <h1 class="soc-title">PrivGuard | SOC Anomaly Command Center</h1>
                <div class="soc-subtitle">
                    Privileged Identity Threat Detection and Response (ITDR) • Autonomous Behavioral Analytics
                </div>
            </div>
        </div>
        <div>
            <div class="soc-status-badge">
                <span class="pulse-dot"></span> SOC ENGINE OPERATIONAL
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------
# 8. TOP EXECUTIVE KPI METRICS ROW
# ---------------------------------------------------------
kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)

with kpi_col1:
    st.markdown(
        f"""
        <div class="soc-kpi-card kpi-accent-cyan">
            <div class="soc-kpi-header">
                <span class="soc-kpi-label">Total Events Analyzed</span>
                <span class="soc-kpi-icon">📋</span>
            </div>
            <div class="soc-kpi-value">{total_events_analyzed:,}</div>
            <div class="soc-kpi-subtext">
                <span class="soc-pill pill-cyan">100% Ingested</span> Windows Security Logs
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi_col2:
    flagged_count = len(filtered_df)
    flagged_ratio = (flagged_count / total_events_analyzed * 100) if total_events_analyzed > 0 else 0
    st.markdown(
        f"""
        <div class="soc-kpi-card kpi-accent-red">
            <div class="soc-kpi-header">
                <span class="soc-kpi-label">Flagged High-Risk Anomalies</span>
                <span class="soc-kpi-icon">🚨</span>
            </div>
            <div class="soc-kpi-value">{flagged_count:,}</div>
            <div class="soc-kpi-subtext">
                <span class="soc-pill pill-red">{flagged_ratio:.2f}% Flagged</span> Score &ge; {risk_threshold}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi_col3:
    st.markdown(
        f"""
        <div class="soc-kpi-card kpi-accent-green">
            <div class="soc-kpi-header">
                <span class="soc-kpi-label">Detection Accuracy / Recall</span>
                <span class="soc-kpi-icon">🎯</span>
            </div>
            <div class="soc-kpi-value">{baseline_accuracy:.2f}% <span style="font-size: 1.15rem; color: #94a3b8;">/ {baseline_recall:.2f}%</span></div>
            <div class="soc-kpi-subtext">
                <span class="soc-pill pill-green">Precision: {baseline_precision:.0f}%</span> F1: {baseline_f1/100:.4f}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi_col4:
    monitored_count = len(active_personas)
    st.markdown(
        f"""
        <div class="soc-kpi-card kpi-accent-purple">
            <div class="soc-kpi-header">
                <span class="soc-kpi-label">Active Monitored Personas</span>
                <span class="soc-kpi-icon">👤</span>
            </div>
            <div class="soc-kpi-value">{monitored_count} <span style="font-size: 1.15rem; color: #94a3b8;">Accounts</span></div>
            <div class="soc-kpi-subtext">
                <span class="soc-pill pill-purple">Tier-0 Identities</span> Continuous Audit
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)


# ---------------------------------------------------------
# 9. CHART THEME HELPER
# ---------------------------------------------------------
def apply_soc_chart_theme(fig, title: str = "", height: int = 380):
    """Applies a consistent dark SOC styling across Plotly visualizations."""
    fig.update_layout(
        title=dict(
            text=f"<b>{title}</b>",
            font=dict(size=14, color="#f1f5f9", family="Inter, sans-serif"),
            x=0.01,
            y=0.96,
        ),
        paper_bgcolor="rgba(15, 23, 42, 0.75)",
        plot_bgcolor="rgba(15, 23, 42, 0.45)",
        font=dict(family="Inter, sans-serif", color="#94a3b8", size=11),
        height=height,
        margin=dict(l=45, r=25, t=55, b=45),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=11, color="#cbd5e1"),
            bgcolor="rgba(0,0,0,0)",
        ),
        xaxis=dict(
            showgrid=True,
            gridcolor="rgba(255, 255, 255, 0.05)",
            linecolor="rgba(255, 255, 255, 0.12)",
            tickfont=dict(color="#94a3b8", size=10),
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor="rgba(255, 255, 255, 0.05)",
            linecolor="rgba(255, 255, 255, 0.12)",
            tickfont=dict(color="#94a3b8", size=10),
        ),
        hoverlabel=dict(
            bgcolor="#0f172a",
            bordercolor="#38bdf8",
            font=dict(color="#f8fafc", family="JetBrains Mono, monospace", size=12),
        ),
    )
    return fig


# ---------------------------------------------------------
# 10. VISUALIZATION 1: INTERACTIVE TIMELINE CHART
# ---------------------------------------------------------
st.markdown(
    """
    <div class="soc-panel-title">
        <span>📈 Visualization 1: Interactive Anomaly Timeline with Dynamic Severity</span>
    </div>
    """,
    unsafe_allow_html=True,
)

if not filtered_df.empty:
    timeline_view_mode = st.radio(
        "Timeline Display Format:",
        options=["Stacked Severity Volume (Temporal Area/Bar)", "Forensic Scatter (Risk Score vs Timeline)"],
        index=0,
        horizontal=True,
        label_visibility="collapsed",
    )

    if timeline_view_mode == "Stacked Severity Volume (Temporal Area/Bar)":
        df_timeline = filtered_df.copy()
        df_timeline["date"] = df_timeline["timestamp"].dt.date
        timeline_agg = df_timeline.groupby(["date", "risk_severity"]).size().reset_index(name="anomaly_count")

        fig_timeline = px.bar(
            timeline_agg,
            x="date",
            y="anomaly_count",
            color="risk_severity",
            color_discrete_map=SEVERITY_COLORS,
            category_orders={"risk_severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
            labels={"date": "Detection Date (October 2026)", "anomaly_count": "Anomaly Events", "risk_severity": "Severity"},
            barmode="stack",
        )
        fig_timeline.update_layout(
            xaxis=dict(
                rangeselector=dict(
                    buttons=list([
                        dict(count=7, label="7D", step="day", stepmode="backward"),
                        dict(count=14, label="14D", step="day", stepmode="backward"),
                        dict(step="all", label="All Oct"),
                    ]),
                    bgcolor="#1e293b",
                    font=dict(color="#38bdf8", size=10),
                    activecolor="#0ea5e9",
                ),
                rangeslider=dict(visible=True, thickness=0.06, bgcolor="rgba(15, 23, 42, 0.8)"),
                type="date",
            ),
        )
        apply_soc_chart_theme(fig_timeline, title="Daily Threat Volume by Risk Severity (October 2026)", height=410)
        st.plotly_chart(fig_timeline, width="stretch")

    else:
        # Forensic Incident Scatter View
        fig_scatter = px.scatter(
            filtered_df,
            x="timestamp",
            y="risk_score",
            color="risk_severity",
            color_discrete_map=SEVERITY_COLORS,
            category_orders={"risk_severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
            hover_data={
                "timestamp": "|%Y-%m-%d %H:%M:%S",
                "username": True,
                "hostname": True,
                "process_name": True,
                "destination_ip": True,
                "event_id": True,
                "risk_score": True,
                "risk_severity": False,
            },
            labels={"timestamp": "Detection Timestamp", "risk_score": "Risk Score (0-100)", "risk_severity": "Severity"},
            opacity=0.85,
        )
        fig_scatter.update_traces(marker=dict(size=7, line=dict(width=0.5, color="white")))
        apply_soc_chart_theme(fig_scatter, title="Forensic Threat Scatter: Normalized Risk Score vs Time", height=410)
        st.plotly_chart(fig_scatter, width="stretch")

else:
    st.info("ℹ️ No anomalies match the current filter selection. Adjust the risk threshold or severity filters.")

st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)


# ---------------------------------------------------------
# 11. VISUALIZATIONS 2 & 3: PERSONA BREAKDOWN & EVENT ID DONUT
# ---------------------------------------------------------
vis_col1, vis_col2 = st.columns(2)

# Visualization 2: Persona Threat Risk Breakdown Bar Chart
with vis_col1:
    st.markdown(
        """
        <div class="soc-panel-title">
            <span>👥 Visualization 2: Persona Threat Risk Breakdown</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Ensure comparative analysis comparing admin_tanish, admin_himanshu, and admin_backup
    persona_benchmark_df = working_df[
        (working_df["risk_score"] >= risk_threshold) & (working_df["risk_severity"].isin(selected_severities))
    ] if not working_df.empty else filtered_df

    if not persona_benchmark_df.empty:
        persona_agg = (
            persona_benchmark_df.groupby(["username", "risk_severity"])
            .size()
            .reset_index(name="anomaly_count")
        )

        fig_persona = px.bar(
            persona_agg,
            x="username",
            y="anomaly_count",
            color="risk_severity",
            color_discrete_map=SEVERITY_COLORS,
            category_orders={
                "username": ["admin_tanish", "admin_himanshu", "admin_backup"],
                "risk_severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            },
            barmode="group",
            text="anomaly_count",
            labels={"username": "Privileged Persona", "anomaly_count": "Anomaly Count", "risk_severity": "Severity"},
        )
        fig_persona.update_traces(textposition="outside", textfont=dict(size=10, color="#f8fafc"))
        chart_subtitle = "Persona Threat Comparison (admin_tanish vs himanshu vs backup)"
        if selected_persona:
            chart_subtitle += f" • [Filtered: {selected_persona}]"
        apply_soc_chart_theme(fig_persona, title=chart_subtitle, height=370)
        st.plotly_chart(fig_persona, width="stretch")
    else:
        st.info("No data available for persona breakdown under current filters.")

# Visualization 3: Security Event ID Distribution Donut Chart
with vis_col2:
    st.markdown(
        """
        <div class="soc-panel-title">
            <span>🍩 Visualization 3: Security Event ID Distribution</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    donut_dataset = filtered_df if not filtered_df.empty else df_raw_logs

    # Calculate distribution across target Windows Event IDs (4624, 4625, 4672)
    # Even if 4625 is 0, we represent the full security event taxonomy
    event_counts = {
        "Event 4672 (Admin Elevation)": int((donut_dataset["event_id"] == 4672).sum()),
        "Event 4624 (Logon Activity)": int((donut_dataset["event_id"] == 4624).sum()),
        "Event 4625 (Failed Logon)": int((donut_dataset["event_id"] == 4625).sum()),
    }

    event_labels = list(event_counts.keys())
    event_values = list(event_counts.values())
    total_events_in_donut = sum(event_values)

    event_colors = ["#ef4444", "#38bdf8", "#fbbf24"]

    fig_donut = go.Figure(
        data=[
            go.Pie(
                labels=event_labels,
                values=event_values,
                hole=0.62,
                marker=dict(colors=event_colors, line=dict(color="#0f172a", width=2)),
                textinfo="label+percent" if total_events_in_donut > 0 else "none",
                textposition="inside",
                insidetextorientation="radial",
                hoverinfo="label+value+percent",
            )
        ]
    )

    # Donut center annotation
    fig_donut.add_annotation(
        text=f"<b>{total_events_in_donut:,}</b><br><span style='font-size:10px; color:#94a3b8;'>TOTAL</span>",
        x=0.5,
        y=0.5,
        font=dict(size=18, color="#f8fafc", family="JetBrains Mono, monospace"),
        showarrow=False,
    )

    apply_soc_chart_theme(fig_donut, title="Windows Security Event ID Distribution (4672 vs 4624 vs 4625)", height=370)
    fig_donut.update_layout(
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.15, xanchor="center", x=0.5),
    )
    st.plotly_chart(fig_donut, width="stretch")

st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)


# ---------------------------------------------------------
# 12. HIGH-DENSITY INTERACTIVE ANOMALY LOG TABLE
# ---------------------------------------------------------
st.markdown(
    """
    <div class="soc-panel-title">
        <span>🚨 High-Density Anomaly Log Table & Threat Alert Center</span>
    </div>
    """,
    unsafe_allow_html=True,
)

# Search & Quick Actions
table_ctrl_col1, table_ctrl_col2 = st.columns([3, 1])

with table_ctrl_col1:
    search_query = st.text_input(
        "🔍 Search Threat Logs",
        placeholder="Filter by Hostname (e.g. ROGUE-LAPTOP-X), Process (psexec.exe), IP, Rule, or Persona...",
        label_visibility="collapsed",
    )

with table_ctrl_col2:
    # CSV Download Button
    csv_export_data = filtered_df.to_csv(index=False).encode("utf-8")
    export_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    st.download_button(
        label="📥 Download Threat Alerts (CSV)",
        data=csv_export_data,
        file_name=f"privguard_threat_alerts_{export_timestamp}.csv",
        mime="text/csv",
        width="stretch",
    )

# Apply Text Search Filter if provided
display_df = filtered_df.copy()
if search_query:
    query = search_query.strip().lower()
    search_cols = ["username", "hostname", "process_name", "destination_ip", "triggered_rules", "anomaly_reason"]
    mask = False
    for col in search_cols:
        if col in display_df.columns:
            mask = mask | display_df[col].astype(str).str.lower().str.contains(query, na=False)
    display_df = display_df[mask]

st.markdown(
    f"""
    <div style="font-size: 0.8rem; color: #94a3b8; margin-bottom: 8px;">
        Showing <b>{len(display_df):,}</b> threat alert records matching active filters.
    </div>
    """,
    unsafe_allow_html=True,
)

if not display_df.empty:
    # Prepare High-Density DataFrame for Streamlit
    columns_to_show = [
        "timestamp",
        "risk_severity",
        "risk_score",
        "username",
        "event_id",
        "hostname",
        "process_name",
        "destination_ip",
        "anomaly_reason",
        "triggered_rules",
    ]
    columns_to_show = [c for c in columns_to_show if c in display_df.columns]

    table_render_df = display_df[columns_to_show].copy()
    badge_map = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🟢 LOW",
    }
    table_render_df["risk_severity"] = table_render_df["risk_severity"].map(lambda s: badge_map.get(s, s))

    st.dataframe(
        table_render_df,
        width="stretch",
        hide_index=True,
        column_config={
            "timestamp": st.column_config.DatetimeColumn(
                "Timestamp",
                format="YYYY-MM-DD HH:mm:ss",
                help="Date and time when the Windows security event occurred.",
            ),
            "risk_severity": st.column_config.TextColumn(
                "Severity",
                help="SOC Normalized Threat Severity: CRITICAL, HIGH, MEDIUM, LOW",
            ),
            "risk_score": st.column_config.ProgressColumn(
                "Risk Score",
                help="Multi-factor anomaly score (0-100)",
                format="%d",
                min_value=0,
                max_value=100,
            ),
            "username": st.column_config.TextColumn("Persona / Account"),
            "event_id": st.column_config.NumberColumn("Event ID", format="%d"),
            "hostname": st.column_config.TextColumn("Target Hostname"),
            "process_name": st.column_config.TextColumn("Process Executed"),
            "destination_ip": st.column_config.TextColumn("Destination IP"),
            "anomaly_reason": st.column_config.TextColumn("Threat Behavior"),
            "triggered_rules": st.column_config.TextColumn("Triggered Rules"),
        },
        height=380,
    )
else:
    st.warning("No records matched your search query. Try clearing the search box.")

st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)


# ---------------------------------------------------------
# 13. FORENSIC INCIDENT INSPECTOR DRAWER
# ---------------------------------------------------------
with st.expander("🔬 Forensic Incident Deep-Dive Inspector (Select Record to Analyze)"):
    if not display_df.empty:
        # Create user-friendly label for selectbox
        sample_records = display_df.head(50)
        options_dict = {}
        for idx, row in sample_records.iterrows():
            key = f"[{row['timestamp']}] | {row['username']} | Score: {row['risk_score']} ({row['risk_severity']}) | {row['process_name']} -> {row['hostname']}"
            options_dict[key] = row

        selected_label = st.selectbox(
            "Select Incident to Inspect (Top 50 Displayed):",
            options=list(options_dict.keys()),
        )
        selected_record = options_dict[selected_label]

        fcol1, fcol2, fcol3 = st.columns(3)
        with fcol1:
            st.markdown(
                f"""
                <div style="background: rgba(15, 23, 42, 0.6); padding: 12px; border-radius: 8px; border: 1px solid rgba(56, 189, 248, 0.2);">
                    <div style="color: #94a3b8; font-size: 0.75rem; text-transform: uppercase;">Identity Forensics</div>
                    <div style="font-size: 1.1rem; font-weight: 700; color: #f8fafc; margin-top: 4px;">{selected_record['username']}</div>
                    <div style="color: #64748b; font-size: 0.8rem; margin-top: 2px;">Event ID: <b>{selected_record['event_id']}</b> | Logon Type: <b>{selected_record.get('logon_type', 'N/A')}</b></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with fcol2:
            st.markdown(
                f"""
                <div style="background: rgba(15, 23, 42, 0.6); padding: 12px; border-radius: 8px; border: 1px solid rgba(56, 189, 248, 0.2);">
                    <div style="color: #94a3b8; font-size: 0.75rem; text-transform: uppercase;">Host & Network Target</div>
                    <div style="font-size: 1.1rem; font-weight: 700; color: #f8fafc; margin-top: 4px;">{selected_record['hostname']}</div>
                    <div style="color: #64748b; font-size: 0.8rem; margin-top: 2px;">IP: <code style="color: #38bdf8;">{selected_record['destination_ip']}</code></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with fcol3:
            sev = selected_record['risk_severity']
            sev_color = SEVERITY_COLORS.get(sev, "#38bdf8")
            st.markdown(
                f"""
                <div style="background: rgba(15, 23, 42, 0.6); padding: 12px; border-radius: 8px; border: 1px solid {sev_color};">
                    <div style="color: #94a3b8; font-size: 0.75rem; text-transform: uppercase;">Threat Severity Assessment</div>
                    <div style="font-size: 1.1rem; font-weight: 700; color: {sev_color}; margin-top: 4px;">{sev} (Score: {selected_record['risk_score']})</div>
                    <div style="color: #64748b; font-size: 0.8rem; margin-top: 2px;">Process: <code style="color: #f87171;">{selected_record['process_name']}</code></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Triggered Rules Chips
        rules = str(selected_record.get("triggered_rules", "NONE")).split(";")
        rule_chips = " ".join([f"<span class='soc-pill pill-red' style='margin: 3px;'>{r}</span>" for r in rules if r])
        st.markdown(
            f"""
            <div style="margin-top: 14px; background: rgba(15, 23, 42, 0.5); padding: 12px; border-radius: 8px; border: 1px solid rgba(148, 163, 184, 0.15);">
                <div style="color: #cbd5e1; font-weight: 600; font-size: 0.85rem; margin-bottom: 6px;">Triggered Multi-Factor Security Rules:</div>
                <div>{rule_chips}</div>
                <div style="margin-top: 8px; color: #94a3b8; font-size: 0.82rem;"><b>Primary SOC Flag Reason:</b> {selected_record.get('anomaly_reason', 'N/A')}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.info("No records available to inspect.")


# ---------------------------------------------------------
# 14. ENTERPRISE FOOTER
# ---------------------------------------------------------
st.markdown(
    """
    <div class="soc-footer">
        🛡️ PrivGuard Privileged Account Anomaly Monitor • Production SOC Command Center v2.4<br>
        Telemetry Sources: <code>synthetic_privileged_logs.csv</code> & <code>flagged_anomalies.csv</code> • Continuous ITDR Behavioral Protection
    </div>
    """,
    unsafe_allow_html=True,
)
