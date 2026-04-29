"""
streamlit_app.py — Interactive Streamlit UI for PhishGuard.

Run:
    streamlit run streamlit_app.py
"""

import sys
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import time

from PhishGuard.predict import predict
from utils.logger import get_recent_scans, get_stats
from utils.feature_extractor import FEATURE_NAMES

# ── Page config ────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="PhishGuard — URL Safety Analyzer",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────

st.markdown("""
<style>
  .main { background: #0d1117; }
  .stApp { background: #0d1117; color: #e6edf3; }
  .verdict-safe  { background: rgba(63,185,80,0.12); border: 1px solid #3fb950; border-radius: 8px; padding: 1rem; }
  .verdict-phish { background: rgba(248,81,73,0.12); border: 1px solid #f85149; border-radius: 8px; padding: 1rem; }
  .verdict-warn  { background: rgba(210,153,34,0.1);  border: 1px solid #d29922; border-radius: 8px; padding: 1rem; }
  div[data-testid="metric-container"] {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0.75rem;
  }
</style>
""", unsafe_allow_html=True)

# ── Header ─────────────────────────────────────────────────────────────────────

st.markdown("## 🛡 PhishGuard — Phishing URL Detection System")
st.markdown("*ML-powered URL safety analyzer with real-time explainability*")
st.markdown("---")

# ── Sidebar: Stats ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### 📊 Session Stats")
    stats = get_stats()
    st.metric("Total Scans",   stats["total"])
    st.metric("Legitimate",    stats["legitimate"])
    st.metric("Phishing",      stats["phishing"])
    st.metric("Phishing Rate", f"{stats['phishing_rate']}%")

    st.markdown("---")
    st.markdown("### 🧠 About")
    st.markdown("""
    Uses an ensemble of:
    - Logistic Regression
    - Random Forest
    - **XGBoost** (best model)

    **23 engineered URL features** extracted and analyzed in real-time.
    """)

# ── Main scanner ───────────────────────────────────────────────────────────────

col1, col2 = st.columns([3, 1])
with col1:
    url_input = st.text_input(
        "Enter URL to analyze",
        placeholder="https://example.com/path?query=value",
        label_visibility="collapsed"
    )
with col2:
    scan_btn = st.button("🔍 Scan URL", use_container_width=True, type="primary")

# Quick examples
st.markdown("**Quick examples:**")
ecols = st.columns(5)
examples = [
    ("✅ Google",    "https://google.com"),
    ("✅ GitHub",    "https://github.com/login"),
    ("⚠ PayPal spoof", "http://paypa1-secure-verify.tk/login"),
    ("⚠ IP login",   "http://192.168.1.1/banking/login"),
    ("⚠ Subdomain",  "http://apple.verify.account-secure.xyz/id/login"),
]
for i, (label, url) in enumerate(examples):
    if ecols[i].button(label, key=f"ex_{i}", use_container_width=True):
        url_input = url
        scan_btn  = True

# ── Run scan ───────────────────────────────────────────────────────────────────

if scan_btn and url_input:
    with st.spinner("Analyzing URL..."):
        result = predict(url_input.strip())

    st.markdown("---")

    # ── Verdict banner ─────────────────────────────────────────────────────────
    is_phish = result["prediction"] == "phishing"
    risk     = result["risk_level"]

    if result["blacklisted"]:
        st.error(f"🚫 BLACKLISTED: {result['blacklist_reason']}")

    if is_phish:
        verdict_class = "verdict-phish"
        verdict_icon  = "⚠️"
        verdict_text  = "PHISHING URL DETECTED"
        verdict_color = "#f85149"
    elif risk == "MEDIUM":
        verdict_class = "verdict-warn"
        verdict_icon  = "⚡"
        verdict_text  = "SUSPICIOUS URL"
        verdict_color = "#d29922"
    else:
        verdict_class = "verdict-safe"
        verdict_icon  = "✅"
        verdict_text  = "LEGITIMATE URL"
        verdict_color = "#3fb950"

    st.markdown(f"""
    <div class="{verdict_class}">
      <h2 style="color:{verdict_color}">{verdict_icon} {verdict_text}</h2>
      <code style="color:#8b949e">{result['url']}</code>
    </div>
    """, unsafe_allow_html=True)

    # ── Key metrics ────────────────────────────────────────────────────────────
    st.markdown("")
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Confidence",       f"{result['confidence']*100:.1f}%")
    with m2:
        st.metric("Risk Level",       result["risk_level"])
    with m3:
        st.metric("Phishing Prob",    f"{result['phishing_probability']*100:.1f}%")
    with m4:
        st.metric("Scan Time",        f"{result['prediction_time_ms']:.1f}ms")

    # ── Gauge chart ────────────────────────────────────────────────────────────
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=result["phishing_probability"] * 100,
        title={"text": "Phishing Probability", "font": {"color": "#e6edf3"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#8b949e"},
            "bar":  {"color": "#f85149" if is_phish else "#3fb950"},
            "steps": [
                {"range": [0,  50], "color": "rgba(63,185,80,0.2)"},
                {"range": [50, 75], "color": "rgba(210,153,34,0.2)"},
                {"range": [75, 100],"color": "rgba(248,81,73,0.2)"},
            ],
            "threshold": {"line": {"color": "#58a6ff", "width": 2}, "value": 50}
        },
        number={"suffix": "%", "font": {"color": "#e6edf3"}},
    ))
    fig_gauge.update_layout(
        paper_bgcolor="#161b22",
        font_color="#e6edf3",
        height=280,
        margin=dict(l=20, r=20, t=40, b=10),
    )

    # ── Feature radar ──────────────────────────────────────────────────────────
    feats = result["features"]
    top_features = [
        "suspicious_keyword_count", "brand_keyword_count", "subdomain_count",
        "dash_count", "dot_count", "special_char_count", "digit_ratio",
        "entropy", "has_ip_address", "tld_suspicious",
    ]
    feat_vals = [feats.get(f, 0) for f in top_features]
    # Normalize 0-1
    max_vals = [5, 3, 5, 8, 10, 20, 1, 6, 1, 1]
    norm_vals = [min(v/m, 1.0) for v, m in zip(feat_vals, max_vals)]

    fig_radar = go.Figure(go.Scatterpolar(
        r=norm_vals + [norm_vals[0]],
        theta=top_features + [top_features[0]],
        fill="toself",
        fillcolor="rgba(248,81,73,0.15)" if is_phish else "rgba(63,185,80,0.15)",
        line=dict(color="#f85149" if is_phish else "#3fb950", width=2),
    ))
    fig_radar.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 1], tickfont=dict(size=8)),
            bgcolor="#161b22",
        ),
        paper_bgcolor="#161b22",
        font_color="#e6edf3",
        height=320,
        margin=dict(l=40, r=40, t=30, b=30),
        title=dict(text="Feature Risk Radar", font=dict(color="#e6edf3")),
    )

    gc1, gc2 = st.columns(2)
    with gc1:
        st.plotly_chart(fig_gauge, use_container_width=True)
    with gc2:
        st.plotly_chart(fig_radar, use_container_width=True)

    # ── Explanations ───────────────────────────────────────────────────────────
    if result["explanations"]:
        st.markdown("### 🔍 Why this URL is suspicious")
        for exp in result["explanations"]:
            sev = exp["severity"]
            icon = {"high": "🔴", "medium": "🟡", "low": "🔵"}[sev]
            st.markdown(f"{icon} **[{sev.upper()}]** {exp['message']}")

    # ── Raw feature table ──────────────────────────────────────────────────────
    with st.expander("📊 All extracted features"):
        feat_df = pd.DataFrame([
            {"Feature": k, "Value": v}
            for k, v in result["features"].items()
        ])
        st.dataframe(feat_df, use_container_width=True, hide_index=True)

# ── History table ──────────────────────────────────────────────────────────────

st.markdown("---")
st.markdown("### 🕒 Recent Scans")

scans = get_recent_scans(limit=15)
if scans:
    df_hist = pd.DataFrame(scans)[["timestamp", "url", "prediction", "confidence", "risk_level"]]
    df_hist["confidence"] = (df_hist["confidence"] * 100).round(1).astype(str) + "%"
    df_hist["timestamp"] = pd.to_datetime(df_hist["timestamp"]).dt.strftime("%H:%M:%S")
    st.dataframe(df_hist, use_container_width=True, hide_index=True)
else:
    st.info("No scans yet. Analyze a URL above to get started.")