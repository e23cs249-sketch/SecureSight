"""
app.py — SecureSight AI: Web Security Configuration Assessment Platform
Main Streamlit application entry point.

Run with:  python -m streamlit run app.py
"""

from __future__ import annotations
import json
import html
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

# Initialize database on first import
from database import (
    init_db,
    create_user,
    authenticate_user,
    get_user_by_id,
    update_display_name,
    create_scan,
    complete_scan,
    fail_scan,
    get_scans_for_user,
    get_scan,
    save_findings,
    get_findings_for_scan,
    get_findings_for_user,
    update_finding_status,
    get_user_stats,
)
from risk_engine import (
    calculate_posture_score,
    get_posture_label,
    count_by_severity,
    get_fix_first_recommendations,
    compare_scan_findings,
)
from scanner import validate_target_url, run_scan
from report_generator import generate_csv, generate_markdown, generate_html

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Page config (must be first Streamlit call)
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SecureSight AI",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------
LAVENDER = "#C8A6F4"
MINT     = "#8ADAD2"
CORAL    = "#FD9384"
FOREST   = "#02391C"
BG_MAIN  = "#0B2419"
BG_SIDE  = "#02391C"
BG_CARD  = "#103626"
BG_SURF  = "#153F2D"
TEXT_PRI = "#F5FFF8"
TEXT_MUT = "#C1D5C8"
BORDER   = "#315844"

SEV_COLORS = {
    "Critical":      CORAL,
    "High":          CORAL,
    "Medium":        LAVENDER,
    "Low":           MINT,
    "Informational": TEXT_MUT,
}

# ---------------------------------------------------------------------------
# Global CSS
# ---------------------------------------------------------------------------

def inject_css():
    st.markdown(f"""
<style>
/* ── Base ── */
html, body, [data-testid="stAppViewContainer"] {{
    background-color: {BG_MAIN} !important;
    color: {TEXT_PRI} !important;
}}
[data-testid="stSidebar"] {{
    background-color: {BG_SIDE} !important;
    border-right: 1px solid {BORDER};
}}
[data-testid="stSidebarContent"] {{
    padding-top: 0 !important;
}}
/* Cards */
.ss-card {{
    background: {BG_CARD};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 18px 20px;
    margin-bottom: 12px;
}}
.ss-card-accent {{
    background: {BG_CARD};
    border: 1px solid {BORDER};
    border-top: 3px solid {LAVENDER};
    border-radius: 10px;
    padding: 18px 20px;
    margin-bottom: 12px;
}}
/* Metric cards */
.metric-card {{
    background: {BG_CARD};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 16px 18px;
    text-align: center;
}}
.metric-value {{
    font-size: 32px;
    font-weight: 800;
    line-height: 1.1;
    color: {LAVENDER};
}}
.metric-label {{
    font-size: 12px;
    color: {TEXT_MUT};
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-top: 4px;
}}
/* Severity badges */
.badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.04em;
}}
.badge-critical {{ background: rgba(253,147,132,.15); color: {CORAL}; border: 1px solid {CORAL}; }}
.badge-high     {{ background: rgba(253,147,132,.10); color: {CORAL}; border: 1px solid rgba(253,147,132,.4); }}
.badge-medium   {{ background: rgba(200,166,244,.12); color: {LAVENDER}; border: 1px solid rgba(200,166,244,.4); }}
.badge-low      {{ background: rgba(138,218,210,.10); color: {MINT}; border: 1px solid rgba(138,218,210,.4); }}
.badge-info     {{ background: rgba(167,182,172,.10); color: {TEXT_MUT}; border: 1px solid rgba(167,182,172,.3); }}
/* Sidebar nav */
.nav-item {{
    display: block;
    padding: 9px 14px;
    border-radius: 8px;
    color: {TEXT_MUT};
    font-size: 14px;
    cursor: pointer;
    margin-bottom: 2px;
    transition: all 0.15s;
    text-decoration: none;
    border: 1px solid transparent;
}}
.nav-item:hover {{
    background: {BG_SURF};
    color: {TEXT_PRI};
}}
.nav-item-active {{
    background: rgba(200,166,244,.15);
    color: {LAVENDER};
    border: 1px solid rgba(200,166,244,.3);
    font-weight: 600;
}}
/* Demo banner */
.demo-banner {{
    background: rgba(253,147,132,.1);
    border: 1px solid {CORAL};
    border-radius: 8px;
    padding: 10px 16px;
    color: {CORAL};
    font-size: 13px;
    font-weight: 600;
    text-align: center;
    margin-bottom: 16px;
}}
/* Section headings */
.section-title {{
    font-size: 13px;
    font-weight: 700;
    color: {TEXT_MUT};
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 18px 0 8px;
}}
/* Progress bar */
.progress-bar-outer {{
    background: {BG_SURF};
    border-radius: 6px;
    height: 8px;
    overflow: hidden;
    margin-top: 6px;
}}
.progress-bar-inner {{
    height: 8px;
    border-radius: 6px;
    transition: width 0.3s;
}}
/* Tables */
.ss-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}
.ss-table th {{
    background: {BG_SURF};
    color: {TEXT_MUT};
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid {BORDER};
}}
.ss-table td {{
    padding: 10px 12px;
    border-bottom: 1px solid rgba(41,61,50,.5);
    vertical-align: top;
}}
.ss-table tr:hover td {{
    background: {BG_SURF};
}}
/* Auth card */
.auth-card {{
    background: {BG_CARD};
    border: 1px solid {BORDER};
    border-radius: 14px;
    padding: 36px 40px;
    max-width: 440px;
    margin: 40px auto;
}}
/* Score circle */
.score-circle {{
    width: 120px;
    height: 120px;
    border-radius: 50%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    margin: 0 auto;
}}
/* Inputs */
[data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea {{
    background-color: {BG_SURF} !important;
    color: {TEXT_PRI} !important;
    border: 1px solid {BORDER} !important;
    border-radius: 8px !important;
}}
[data-testid="stTextInput"] input:focus,
[data-testid="stTextArea"] textarea:focus {{
    border-color: {LAVENDER} !important;
    box-shadow: 0 0 0 2px rgba(200,166,244,.2) !important;
}}
/* Buttons */
[data-testid="stButton"] button {{
    background: {FOREST};
    color: {TEXT_PRI};
    border: 1px solid {LAVENDER};
    border-radius: 8px;
    font-weight: 600;
    transition: all 0.15s;
}}
[data-testid="stButton"] button:hover {{
    background: rgba(200,166,244,.2);
    border-color: {LAVENDER};
}}
/* Expander */
[data-testid="stExpander"] {{
    background: {BG_CARD} !important;
    border: 1px solid {BORDER} !important;
    border-radius: 10px !important;
}}
/* Hide Streamlit default elements */
#MainMenu, footer, header {{ visibility: hidden; }}
[data-testid="stDecoration"] {{ display: none; }}
.block-container {{ padding-top: 16px !important; padding-bottom: 40px !important; }}
/* Divider */
hr {{ border-color: {BORDER}; opacity: 0.5; }}

/* Shared Streamlit surfaces and readable control states */
:root {{
    color-scheme: dark;
}}
body {{
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}}
body, [data-testid="stAppViewContainer"] {{
    background:
        radial-gradient(ellipse at 82% 4%, rgba(138,218,210,.09), transparent 34rem),
        radial-gradient(ellipse at 8% 32%, rgba(200,166,244,.07), transparent 32rem),
        {BG_MAIN} !important;
}}
[data-testid="stMain"], [data-testid="stMainBlockContainer"] {{
    background: transparent !important;
}}
[data-testid="stHeader"] {{
    background: rgba(11,36,25,.82) !important;
}}
[data-testid="stHeader"] button,
[data-testid="stHeader"] button svg {{
    color: {TEXT_PRI} !important;
    fill: {TEXT_PRI} !important;
}}
[data-testid="stSidebar"] {{
    background: linear-gradient(180deg, {FOREST} 0%, {BG_MAIN} 100%) !important;
}}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"],
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] p {{
    color: {TEXT_MUT};
}}
[data-testid="stSidebar"] [data-testid="stButton"] button {{
    min-height: 42px;
    text-align: left;
    justify-content: flex-start;
    border-color: transparent;
    background: transparent;
    color: {TEXT_MUT};
}}
[data-testid="stSidebar"] [data-testid="stButton"] button:hover {{
    background: rgba(138,218,210,.12);
    color: {TEXT_PRI};
    border-color: rgba(138,218,210,.3);
}}
[data-testid="stSidebar"] [data-testid="stButton"] button[kind="primary"] {{
    background: {MINT} !important;
    color: {FOREST} !important;
    border-color: {MINT} !important;
}}
[data-testid="stSidebar"] [data-testid="stButton"] button[kind="primary"] * {{
    color: {FOREST} !important;
}}
.block-container {{
    max-width: 1480px;
    padding-top: 2rem !important;
}}
.ss-card, .ss-card-accent, .metric-card, .auth-card {{
    background: linear-gradient(145deg, rgba(16,54,38,.96), rgba(11,36,25,.98));
    border-color: {BORDER};
    border-radius: 16px;
    box-shadow: 0 14px 36px rgba(0,0,0,.18), inset 0 1px rgba(245,255,248,.035);
}}
.ss-card, .ss-card-accent, .metric-card {{
    transition: transform .18s ease, border-color .18s ease, box-shadow .18s ease;
}}
.ss-card:hover, .ss-card-accent:hover, .metric-card:hover {{
    transform: translateY(-2px);
    border-color: rgba(138,218,210,.52);
    box-shadow: 0 18px 40px rgba(0,0,0,.24), 0 0 22px rgba(138,218,210,.06);
}}
.ss-card-accent {{
    border-top-color: {MINT};
}}
.metric-card {{
    min-height: 108px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    border-top: 2px solid rgba(200,166,244,.55);
}}
.metric-value {{
    font-size: clamp(25px, 2.3vw, 34px);
    letter-spacing: -.04em;
}}
.metric-label {{
    color: {TEXT_MUT};
    font-size: 11px;
    font-weight: 650;
}}
.section-title {{
    color: {MINT};
    font-size: 12px;
}}
[data-testid="stMarkdownContainer"] {{
    color: {TEXT_PRI};
}}
[data-testid="stMarkdownContainer"] p,
[data-testid="stMarkdownContainer"] li,
[data-testid="stMarkdownContainer"] blockquote {{
    color: inherit;
    line-height: 1.65;
}}
[data-testid="stCaptionContainer"] {{
    color: {TEXT_MUT} !important;
}}
[data-testid="stText"],
[data-testid="stWidgetLabel"],
[data-testid="stWidgetLabel"] p,
[data-testid="stHelp"],
[data-testid="stMarkdownContainer"] small {{
    color: {TEXT_MUT};
}}
[data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea,
[data-testid="stNumberInput"] input,
[data-testid="stDateInput"] input {{
    background: {BG_MAIN} !important;
    color: {TEXT_PRI} !important;
    caret-color: {MINT};
    min-height: 44px;
}}
[data-testid="stTextInput"] input::placeholder,
[data-testid="stTextArea"] textarea::placeholder {{
    color: #A9C4B2 !important;
    opacity: 1;
}}
[data-testid="stTextInput"] label,
[data-testid="stTextArea"] label,
[data-testid="stNumberInput"] label,
[data-testid="stSelectbox"] label,
[data-testid="stMultiSelect"] label,
[data-testid="stCheckbox"] label,
[data-testid="stRadio"] label {{
    color: {TEXT_PRI} !important;
    font-weight: 550;
}}
[data-testid="stSelectbox"] [data-baseweb="select"] > div,
[data-testid="stMultiSelect"] [data-baseweb="select"] > div {{
    background-color: {BG_MAIN} !important;
    color: {TEXT_PRI} !important;
    border-color: {BORDER} !important;
}}
[data-testid="stSelectbox"] [data-baseweb="select"] [role="combobox"],
[data-testid="stMultiSelect"] [data-baseweb="select"] [role="combobox"],
[data-testid="stSelectbox"] [data-baseweb="select"] [role="combobox"] *,
[data-testid="stMultiSelect"] [data-baseweb="select"] [role="combobox"] * {{
    color: {TEXT_PRI} !important;
}}
[data-testid="stSelectbox"] [data-baseweb="select"] svg,
[data-testid="stMultiSelect"] [data-baseweb="select"] svg {{
    color: {TEXT_PRI} !important;
    fill: {TEXT_PRI} !important;
}}
[data-baseweb="popover"],
[data-testid="stSelectboxVirtualDropdown"] {{
    background-color: {BG_CARD} !important;
    border: 1px solid {BORDER} !important;
}}
[data-baseweb="popover"] [role="listbox"],
[data-testid="stSelectboxVirtualDropdown"] [role="listbox"] {{
    background-color: {BG_CARD} !important;
    color: {TEXT_PRI} !important;
}}
[data-baseweb="popover"] [role="option"],
[data-testid="stSelectboxVirtualDropdown"] [role="option"] {{
    background-color: {BG_CARD} !important;
    color: {TEXT_PRI} !important;
}}
[data-baseweb="popover"] [role="option"]:hover,
[data-baseweb="popover"] [role="option"]:focus,
[data-baseweb="popover"] [role="option"]:focus-visible,
[data-baseweb="popover"] [role="option"][aria-selected="true"],
[data-baseweb="popover"] [role="option"][data-highlighted="true"],
[data-testid="stSelectboxVirtualDropdown"] [role="option"]:hover,
[data-testid="stSelectboxVirtualDropdown"] [role="option"]:focus,
[data-testid="stSelectboxVirtualDropdown"] [role="option"]:focus-visible,
[data-testid="stSelectboxVirtualDropdown"] [role="option"][aria-selected="true"],
[data-testid="stSelectboxVirtualDropdown"] [role="option"][data-highlighted="true"] {{
    background-color: {BG_SURF} !important;
    color: {TEXT_PRI} !important;
}}
[data-testid="stSelectbox"] [data-baseweb="select"]:focus-within > div,
[data-testid="stMultiSelect"] [data-baseweb="select"]:focus-within > div {{
    border-color: {LAVENDER} !important;
    box-shadow: 0 0 0 2px rgba(200,166,244,.28) !important;
}}
[data-testid="stMultiSelect"] [data-baseweb="select"] input {{
    color: {TEXT_PRI} !important;
    caret-color: {MINT};
}}
[data-testid="stMultiSelect"] [data-baseweb="select"] input::placeholder {{
    color: #A9C4B2 !important;
    opacity: 1;
}}
[data-testid="stCheckbox"] input,
[data-testid="stRadio"] input {{
    accent-color: {MINT};
}}
[data-testid="stButton"] button,
[data-testid="stFormSubmitButton"] button,
[data-testid="stDownloadButton"] button {{
    min-height: 42px;
    border-radius: 10px;
    font-weight: 650;
    transition: transform .16s ease, background .16s ease, box-shadow .16s ease;
}}
[data-testid="stButton"] button[kind="primary"],
[data-testid="stFormSubmitButton"] button[kind="primary"] {{
    background: {MINT} !important;
    color: {FOREST} !important;
    border: 1px solid {MINT} !important;
}}
[data-testid="stFormSubmitButton"] button {{
    background: {FOREST} !important;
    color: {TEXT_PRI} !important;
    border: 1px solid {MINT} !important;
}}
[data-testid="stButton"] button *,
[data-testid="stFormSubmitButton"] button *,
[data-testid="stDownloadButton"] button * {{
    color: inherit !important;
}}
[data-testid="stFormSubmitButton"] button:hover {{
    background: {BG_SURF} !important;
    color: {TEXT_PRI} !important;
    border-color: {MINT} !important;
}}
[data-testid="stButton"] button:focus-visible,
[data-testid="stFormSubmitButton"] button:focus-visible,
[data-testid="stDownloadButton"] button:focus-visible,
[data-testid="stTextInput"] input:focus-visible,
[data-testid="stTextArea"] textarea:focus-visible {{
    outline: 3px solid {LAVENDER} !important;
    outline-offset: 2px;
}}
[data-testid="stButton"] button:hover,
[data-testid="stFormSubmitButton"] button:hover,
[data-testid="stDownloadButton"] button:hover {{
    transform: translateY(-1px);
    box-shadow: 0 7px 18px rgba(0,0,0,.18);
    border-color: {MINT} !important;
}}
[data-testid="stDownloadButton"] button {{
    background: rgba(138,218,210,.12) !important;
    color: {TEXT_PRI} !important;
    border: 1px solid rgba(138,218,210,.5) !important;
}}
[data-testid="stExpander"] {{
    background: rgba(16,54,38,.74) !important;
    border-color: {BORDER} !important;
}}
[data-testid="stExpander"] summary,
[data-testid="stExpander"] summary p {{
    color: {TEXT_PRI} !important;
}}
[data-testid="stExpander"] summary {{
    white-space: normal !important;
}}
[data-testid="stExpander"] summary p {{
    margin: 0 !important;
    line-height: 1.5 !important;
    overflow-wrap: break-word;
    word-break: normal;
}}
[data-testid="stTabs"] button {{
    color: {TEXT_MUT} !important;
}}
[data-testid="stTabs"] button[aria-selected="true"] {{
    color: {MINT} !important;
    border-bottom-color: {MINT} !important;
}}
[data-testid="stAlert"] {{
    border-radius: 12px;
    border: 1px solid {BORDER};
}}
[data-testid="stMetric"] {{
    background: rgba(16,54,38,.86);
    border: 1px solid {BORDER};
    border-radius: 14px;
    padding: 14px 16px;
}}
[data-testid="stMetricLabel"], [data-testid="stMetricDelta"] {{
    color: {TEXT_MUT} !important;
}}
[data-testid="stMetricValue"] {{
    color: {TEXT_PRI} !important;
}}
[data-testid="stDataFrame"], [data-testid="stTable"] {{
    border: 1px solid {BORDER};
    border-radius: 12px;
    overflow: hidden;
}}
.hero-panel {{
    position: relative;
    overflow: hidden;
    display: grid;
    grid-template-columns: minmax(0, 1.35fr) minmax(220px, .65fr);
    align-items: center;
    gap: 24px;
    min-height: 250px;
    margin: 0 0 24px;
    padding: 30px clamp(22px, 4vw, 48px);
    border: 1px solid rgba(138,218,210,.32);
    border-radius: 22px;
    background:
        radial-gradient(circle at 78% 42%, rgba(138,218,210,.2), transparent 19rem),
        linear-gradient(118deg, #103626 0%, #0B2419 62%, #142B22 100%);
    box-shadow: 0 22px 55px rgba(0,0,0,.22), inset 0 1px rgba(245,255,248,.08);
}}
.hero-panel::before {{
    content: "";
    position: absolute;
    inset: 0;
    opacity: .16;
    pointer-events: none;
    background-image: linear-gradient(rgba(193,213,200,.12) 1px, transparent 1px),
        linear-gradient(90deg, rgba(193,213,200,.12) 1px, transparent 1px);
    background-size: 38px 38px;
    mask-image: linear-gradient(90deg, black, transparent 84%);
}}
.hero-copy, .hero-visual {{
    position: relative;
    z-index: 1;
}}
.hero-eyebrow {{
    color: {MINT};
    font-size: 11px;
    font-weight: 750;
    letter-spacing: .14em;
    text-transform: uppercase;
}}
.hero-title {{
    margin: 11px 0 10px;
    color: {TEXT_PRI};
    font-size: clamp(30px, 4vw, 46px);
    font-weight: 780;
    line-height: 1.08;
    letter-spacing: -.045em;
}}
.hero-title span {{
    color: {MINT};
}}
.hero-description {{
    max-width: 580px;
    margin: 0;
    color: {TEXT_MUT};
    font-size: 15px;
    line-height: 1.65;
}}
.hero-visual {{
    display: grid;
    place-items: center;
    min-height: 190px;
    perspective: 700px;
}}
.hero-orbit {{
    position: absolute;
    width: 190px;
    height: 190px;
    border: 1px solid rgba(138,218,210,.26);
    border-radius: 50%;
    box-shadow: 0 0 34px rgba(138,218,210,.12), inset 0 0 30px rgba(138,218,210,.07);
    transform: rotateX(64deg) rotateZ(-22deg);
}}
.hero-orbit::before, .hero-orbit::after {{
    content: "";
    position: absolute;
    border: 1px solid rgba(200,166,244,.3);
    border-radius: inherit;
    inset: 18px;
}}
.hero-orbit::after {{
    inset: 39px;
    border-color: rgba(138,218,210,.28);
}}
.hero-shield {{
    width: 118px;
    height: 138px;
    filter: drop-shadow(0 0 16px rgba(138,218,210,.5));
    animation: shield-float 5s ease-in-out infinite;
}}
@keyframes shield-float {{
    0%, 100% {{ transform: translateY(2px) rotateY(-8deg); }}
    50% {{ transform: translateY(-7px) rotateY(8deg); }}
}}
.page-heading {{
    margin-bottom: 24px !important;
    padding-bottom: 16px !important;
}}
.page-heading h1 {{
    font-size: clamp(25px, 3vw, 32px) !important;
    letter-spacing: -.035em;
}}
.page-heading p {{
    font-size: 14px !important;
    color: {TEXT_MUT} !important;
}}
@media (max-width: 760px) {{
    .block-container {{ padding: 1rem 1rem 2rem !important; }}
    .hero-panel {{ grid-template-columns: 1fr; padding: 24px 22px; }}
    .hero-visual {{ min-height: 150px; }}
    .hero-orbit {{ width: 150px; height: 150px; }}
    .hero-shield {{ width: 92px; height: 108px; }}
    .auth-card {{ padding: 26px 20px; }}
}}
@media (prefers-reduced-motion: reduce) {{
    *, *::before, *::after {{
        scroll-behavior: auto !important;
        animation-duration: .01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: .01ms !important;
    }}
}}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def is_logged_in() -> bool:
    return st.session_state.get("user_id") is not None

def is_demo() -> bool:
    return st.session_state.get("demo_mode", False)

def current_user() -> dict | None:
    uid = st.session_state.get("user_id")
    if uid:
        return {"id": uid, "display_name": st.session_state.get("display_name", "User"),
                "email": st.session_state.get("user_email", "")}
    return None

def load_demo_data() -> tuple[list, list]:
    """Load demo scans and findings from JSON file."""
    demo_path = Path("sample_data/demo_findings.json")
    if demo_path.exists():
        with open(demo_path, "r") as f:
            data = json.load(f)
        return data.get("demo_scans", []), data.get("demo_findings", [])
    return [], []


# ---------------------------------------------------------------------------
# Reusable UI components
# ---------------------------------------------------------------------------

def _html_text(value: object) -> str:
    return html.escape(str(value), quote=True)


def metric_card(label: str, value: str, color: str = LAVENDER) -> str:
    return f"""
<div class="metric-card">
  <div class="metric-value" style="color:{color}">{_html_text(value)}</div>
  <div class="metric-label">{_html_text(label)}</div>
</div>"""


def _sidebar_identity_html(display_name: str, email: str) -> str:
    return f"""
<div style="font-size:13px;font-weight:600;color:{TEXT_PRI};">{_html_text(display_name)}</div>
<div style="font-size:11px;color:{TEXT_MUT};">{_html_text(email)}</div>"""


def _account_profile_text_html(user: dict) -> str:
    return f"""
<div style="font-size:17px;font-weight:700;color:{TEXT_PRI};">{_html_text(user['display_name'])}</div>
<div style="font-size:13px;color:{TEXT_MUT};">{_html_text(user['email'])}</div>
<div style="font-size:11px;color:{TEXT_MUT};">Member since {_html_text(user.get('created_at','')[:10])}</div>"""


def _finding_details_html(finding: dict) -> str:
    return f"""
<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">
  <div><span style="color:{TEXT_MUT};font-size:11px;text-transform:uppercase;">Check</span>
       <div style="color:{TEXT_PRI};">{_html_text(finding.get('check_name',''))}</div></div>
  <div><span style="color:{TEXT_MUT};font-size:11px;text-transform:uppercase;">Confidence</span>
       <div style="color:{TEXT_PRI};">{_html_text(finding.get('confidence',''))}</div></div>
</div>
<div style="background:{BG_SURF};border:1px solid {BORDER};border-radius:6px;padding:10px 14px;
            font-family:monospace;font-size:12px;color:{MINT};margin-bottom:12px;word-break:break-all;">
  {_html_text(finding.get('evidence','N/A'))}
</div>
<div style="margin-bottom:8px;"><strong style="color:{LAVENDER};">Explanation</strong>
<p style="color:{TEXT_PRI};margin-top:4px;">{_html_text(finding.get('explanation',''))}</p></div>
<div style="margin-bottom:8px;"><strong style="color:{CORAL};">Potential Impact</strong>
<p style="color:{TEXT_PRI};margin-top:4px;">{_html_text(finding.get('impact',''))}</p></div>
<div><strong style="color:{MINT};">Recommendation</strong>
<p style="color:{TEXT_PRI};margin-top:4px;">{_html_text(finding.get('recommendation',''))}</p></div>"""


def _finding_evidence_html(evidence: object) -> str:
    return f"""
<div style="background:{BG_SURF};border:1px solid {BORDER};border-radius:6px;padding:10px 14px;
font-family:monospace;font-size:12px;color:{MINT};margin:8px 0;word-break:break-all;">
{_html_text(evidence)}
</div>"""


def severity_badge(severity: str) -> str:
    cls_map = {"Critical": "badge-critical", "High": "badge-high",
               "Medium": "badge-medium", "Low": "badge-low",
               "Informational": "badge-info"}
    cls = cls_map.get(severity, "badge-info")
    return f'<span class="badge {cls}">{_html_text(severity)}</span>'

def severity_expander_label(severity: str, title: str) -> str:
    return f"{_html_text(severity.upper())}  |  {_html_text(title)}"

def logo_html() -> str:
    return f"""
<div style="padding:20px 16px 12px; border-bottom:1px solid {BORDER}; margin-bottom:8px;">
  <div style="font-size:20px; font-weight:800; color:{TEXT_PRI}; letter-spacing:-0.02em;">
    <span style="color:{LAVENDER};">⬡</span> Secure<span style="color:{MINT};">Sight</span> AI
  </div>
  <div style="font-size:11px; color:{TEXT_MUT}; margin-top:2px; letter-spacing:0.04em;">
    WEB SECURITY INTELLIGENCE
  </div>
</div>"""

def page_header(title: str, subtitle: str = "") -> None:
    st.markdown(f"""
<div class="page-heading" style="margin-bottom:20px; padding-bottom:14px; border-bottom:1px solid {BORDER};">
  <div style="font-size:10px;font-weight:750;letter-spacing:.14em;color:{MINT};margin-bottom:7px;">SECURESIGHT AI · RISK ANALYTICS</div>
  <h1 style="font-size:22px; font-weight:800; color:{TEXT_PRI}; margin:0 0 4px;">{_html_text(title)}</h1>
  <p style="font-size:13px; color:{TEXT_MUT}; margin:0;">{_html_text(subtitle)}</p>
</div>""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Auth pages
# ---------------------------------------------------------------------------

def page_login():
    inject_css()
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown(f"""
<div style="text-align:center; padding:40px 0 24px;">
  <div style="font-size:36px; color:{LAVENDER};">⬡</div>
  <div style="font-size:26px; font-weight:800; color:{TEXT_PRI}; margin-top:4px;">
    Secure<span style="color:{MINT};">Sight</span> AI
  </div>
  <div style="font-size:12px; color:{TEXT_MUT}; letter-spacing:0.08em; margin-top:2px;">
    WEB SECURITY INTELLIGENCE
  </div>
</div>
<div class="auth-card">
  <h2 style="font-size:18px; font-weight:700; margin-bottom:4px; color:{TEXT_PRI};">Welcome back</h2>
  <p style="font-size:13px; color:{TEXT_MUT}; margin-bottom:20px;">Sign in to your SecureSight account</p>
""", unsafe_allow_html=True)

        with st.form("login_form"):
            email = st.text_input("Email address", placeholder="you@example.com")
            password = st.text_input("Password", type="password", placeholder="••••••••")
            submitted = st.form_submit_button("Sign In", use_container_width=True)

        if submitted:
            if not email or not password:
                st.error("Please enter your email and password.")
            else:
                user = authenticate_user(email, password)
                if user:
                    st.session_state["user_id"] = user["id"]
                    st.session_state["display_name"] = user["display_name"]
                    st.session_state["user_email"] = user["email"]
                    st.session_state["demo_mode"] = False
                    st.session_state["page"] = "Overview"
                    st.rerun()
                else:
                    st.error("Invalid email or password. Please check your credentials.")

        st.markdown(f"""
<div style="text-align:center; margin-top:16px; font-size:13px; color:{TEXT_MUT};">
  Don't have an account?
</div>""", unsafe_allow_html=True)

        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("Create Account", use_container_width=True):
                st.session_state["auth_page"] = "signup"
                st.rerun()
        with col_b:
            if st.button("Try Demo Mode", use_container_width=True):
                st.session_state["demo_mode"] = True
                st.session_state["user_id"] = None
                st.session_state["display_name"] = "Demo User"
                st.session_state["page"] = "Overview"
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown(f"""
<div style="text-align:center; margin-top:16px; font-size:11px; color:{TEXT_MUT};">
  Password reset and email verification are not available in this local demonstration.
</div>""", unsafe_allow_html=True)


def page_signup():
    inject_css()
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown(f"""
<div style="text-align:center; padding:40px 0 24px;">
  <div style="font-size:36px; color:{LAVENDER};">⬡</div>
  <div style="font-size:26px; font-weight:800; color:{TEXT_PRI}; margin-top:4px;">
    Secure<span style="color:{MINT};">Sight</span> AI
  </div>
  <div style="font-size:12px; color:{TEXT_MUT}; letter-spacing:0.08em; margin-top:2px;">
    WEB SECURITY INTELLIGENCE
  </div>
</div>
<div class="auth-card">
  <h2 style="font-size:18px; font-weight:700; margin-bottom:4px; color:{TEXT_PRI};">Create your account</h2>
  <p style="font-size:13px; color:{TEXT_MUT}; margin-bottom:20px;">Start assessing web security configurations</p>
""", unsafe_allow_html=True)

        with st.form("signup_form"):
            full_name = st.text_input("Full name", placeholder="Your Name")
            email = st.text_input("Email address", placeholder="you@example.com")
            password = st.text_input("Password", type="password", placeholder="8+ characters")
            confirm  = st.text_input("Confirm password", type="password", placeholder="Repeat password")
            agree = st.checkbox("I understand this tool is for authorized testing only")
            submitted = st.form_submit_button("Create Account", use_container_width=True)

        if submitted:
            errors = []
            if not full_name.strip():
                errors.append("Full name is required.")
            if not email.strip() or "@" not in email:
                errors.append("A valid email address is required.")
            if len(password) < 8:
                errors.append("Password must be at least 8 characters.")
            if password != confirm:
                errors.append("Passwords do not match.")
            if not agree:
                errors.append("Please acknowledge the authorized-use requirement.")
            if errors:
                for e in errors:
                    st.error(e)
            else:
                user = create_user(email, full_name, password)
                if user is None:
                    st.error("An account with this email already exists. Please sign in.")
                else:
                    st.success("Account created! Please sign in.")
                    st.session_state["auth_page"] = "login"
                    time.sleep(1)
                    st.rerun()

        # Password strength hint
        st.markdown(f"""
<div style="font-size:11px; color:{TEXT_MUT}; margin-top:6px;">
  Use 8+ characters. Avoid obvious passwords.
</div>""", unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

        if st.button("← Back to Sign In", use_container_width=True):
            st.session_state["auth_page"] = "login"
            st.rerun()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

NAV_ITEMS = [
    ("Overview",         "◈"),
    ("Security Scanner", "⬡"),
    ("Findings & Risks", "⚑"),
    ("Scan History",     "⊙"),
    ("Compare Scans",    "⊞"),
    ("Reports",          "⊟"),
    ("Learning Center",  "◎"),
    ("Account Settings", "⊕"),
]


def render_sidebar():
    with st.sidebar:
        st.markdown(logo_html(), unsafe_allow_html=True)

        if is_demo():
            st.markdown(f"""
<div class="demo-banner">
  ⚠ DEMO MODE — Sample Data Only
</div>""", unsafe_allow_html=True)

        current_page = st.session_state.get("page", "Overview")
        st.markdown(f'<div class="section-title">Navigation</div>', unsafe_allow_html=True)

        for name, icon in NAV_ITEMS:
            if st.sidebar.button(
                f"{icon}  {name}",
                key=f"nav_{name}",
                use_container_width=True,
                type="primary" if current_page == name else "secondary",
            ):
                st.session_state["page"] = name
                st.rerun()

        st.markdown(f'<div style="height:1px;background:{BORDER};margin:16px 0;"></div>', unsafe_allow_html=True)

        # User info at bottom
        user = current_user()
        if user:
            initials = "".join(w[0].upper() for w in user["display_name"].split()[:2])
            safe_initials = _html_text(initials)
            st.markdown(f"""
<div style="padding:10px 4px; display:flex; align-items:center; gap:10px;">
  <div style="width:34px;height:34px;border-radius:50%;background:{BG_SURF};border:1px solid {LAVENDER};
              display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;color:{LAVENDER};">
    {safe_initials}
  </div>
  <div>
    {_sidebar_identity_html(user["display_name"], "Demo Mode" if is_demo() else user.get("email", ""))}
  </div>
</div>""", unsafe_allow_html=True)
        elif is_demo():
            st.markdown(f"""
<div style="padding:10px 4px; display:flex; align-items:center; gap:10px;">
  <div style="width:34px;height:34px;border-radius:50%;background:{BG_SURF};border:1px solid {CORAL};
              display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;color:{CORAL};">
    D
  </div>
  <div>
    <div style="font-size:13px;font-weight:600;color:{TEXT_PRI};">Demo User</div>
    <div style="font-size:11px;color:{TEXT_MUT};">Sample data only</div>
  </div>
</div>""", unsafe_allow_html=True)

        if st.sidebar.button("⊗  Sign Out", use_container_width=True, key="signout_btn"):
            for key in ["user_id", "display_name", "user_email", "demo_mode", "page",
                        "scan_result", "selected_scan_id"]:
                st.session_state.pop(key, None)
            st.session_state["auth_page"] = "login"
            st.rerun()

        st.markdown(f"""
<div style="text-align:center;font-size:10px;color:{TEXT_MUT};margin-top:8px;">
  SecureSight AI v1.0.0
</div>""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Page: Overview
# ---------------------------------------------------------------------------

def page_overview():
    page_header("Security Overview",
                "Understand your security posture. Prioritize what matters. Improve with confidence.")

    st.markdown(f"""
<section class="hero-panel" aria-label="SecureSight AI security dashboard">
  <div class="hero-copy">
    <div class="hero-eyebrow">Intelligent security · Risk analytics</div>
    <h2 class="hero-title">See risk clearly.<br><span>Strengthen every layer.</span></h2>
    <p class="hero-description">
      Evidence-based website configuration assessments, actionable findings, and practical
      guidance to help you improve your security posture.
    </p>
  </div>
  <div class="hero-visual" aria-hidden="true">
    <div class="hero-orbit"></div>
    <svg class="hero-shield" viewBox="0 0 120 140" role="presentation">
      <defs>
        <linearGradient id="ssShield" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="{MINT}" stop-opacity=".95"/>
          <stop offset="1" stop-color="{LAVENDER}" stop-opacity=".72"/>
        </linearGradient>
      </defs>
      <path d="M60 6 108 24v37c0 34-20 56-48 72C32 117 12 95 12 61V24L60 6Z"
        fill="rgba(138,218,210,.13)" stroke="url(#ssShield)" stroke-width="2.4"/>
      <path d="M60 18 96 32v29c0 25-14 43-36 56C38 104 24 86 24 61V32l36-14Z"
        fill="rgba(16,54,38,.8)" stroke="rgba(245,255,248,.42)" stroke-width="1"/>
      <path d="m43 68 12 12 24-27" fill="none" stroke="{MINT}" stroke-linecap="round"
        stroke-linejoin="round" stroke-width="5"/>
      <circle cx="60" cy="60" r="53" fill="none" stroke="rgba(138,218,210,.15)"/>
    </svg>
  </div>
</section>
""", unsafe_allow_html=True)
    action_col, explore_col, _ = st.columns([1.15, 1.15, 3.7])
    with action_col:
        if st.button("▶  Start Security Scan", type="primary", key="overview_start_scan"):
            st.session_state["page"] = "Security Scanner"
            st.rerun()
    with explore_col:
        explore_label = "Explore Demo" if is_demo() else "View Findings"
        if st.button(explore_label, key="overview_explore"):
            st.session_state["page"] = "Security Scanner" if is_demo() else "Findings & Risks"
            st.rerun()

    if is_demo():
        st.markdown(f'<div class="demo-banner">⚠ SAMPLE DATA — NOT A LIVE SECURITY SCAN</div>',
                    unsafe_allow_html=True)
        demo_scans, demo_findings = load_demo_data()
        scans = demo_scans
        all_findings = demo_findings
        stats = {
            "total_scans": len(demo_scans),
            "domains_assessed": len({s["target_domain"] for s in demo_scans}),
            "open_findings": sum(1 for f in demo_findings if f.get("status") == "open"),
            "high_priority_findings": sum(1 for f in demo_findings if f.get("status") == "open"
                                          and f.get("severity") in ("Critical", "High")),
            "latest_score": max((s.get("posture_score", 0) for s in demo_scans), default=None),
        }
    else:
        uid = st.session_state["user_id"]
        stats = get_user_stats(uid)
        scans = get_scans_for_user(uid)
        all_findings = get_findings_for_user(uid)

    # Metric row
    m_cols = st.columns(5)
    metrics = [
        ("Total Scans",        str(stats["total_scans"]),              LAVENDER),
        ("Sites Assessed",     str(stats["domains_assessed"]),         MINT),
        ("Open Findings",      str(stats["open_findings"]),            CORAL),
        ("High Priority",      str(stats["high_priority_findings"]),   CORAL),
        ("Posture Score",
         f"{stats['latest_score']:.0f}" if stats["latest_score"] is not None else "—",
         MINT if (stats["latest_score"] or 0) >= 60 else CORAL),
    ]
    for col, (label, value, color) in zip(m_cols, metrics):
        with col:
            st.markdown(metric_card(label, value, color), unsafe_allow_html=True)

    st.markdown("---")

    if not scans:
        st.markdown(f"""
<div class="ss-card" style="text-align:center; padding:40px;">
  <div style="font-size:40px; color:{LAVENDER}; margin-bottom:10px;">⬡</div>
  <div style="font-size:18px; font-weight:700; color:{TEXT_PRI}; margin-bottom:8px;">No scans yet</div>
  <div style="font-size:14px; color:{TEXT_MUT};">
    Run your first security scan to see your posture score, findings, and recommendations.
  </div>
</div>""", unsafe_allow_html=True)
        if st.button("→ Run First Scan", key="ov_first_scan"):
            st.session_state["page"] = "Security Scanner"
            st.rerun()
        return

    # Latest score + severity distribution
    col_left, col_right = st.columns([1, 2])

    with col_left:
        latest_score = stats["latest_score"] or 0
        score_label, score_color_key = get_posture_label(latest_score)
        score_color = MINT if score_color_key == "mint" else (LAVENDER if score_color_key == "lavender" else CORAL)

        st.markdown(f'<div class="ss-card-accent">', unsafe_allow_html=True)
        st.markdown(f"**Security Posture Score**")
        try:
            import plotly.graph_objects as go
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=latest_score,
                domain={"x": [0, 1], "y": [0, 1]},
                number={"font": {"color": score_color, "size": 40}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": TEXT_MUT, "tickfont": {"color": TEXT_MUT}},
                    "bar": {"color": score_color},
                    "bgcolor": BG_SURF,
                    "bordercolor": BORDER,
                    "steps": [
                        {"range": [0, 40], "color": "rgba(253,147,132,.15)"},
                        {"range": [40, 70], "color": "rgba(200,166,244,.1)"},
                        {"range": [70, 100], "color": "rgba(138,218,210,.1)"},
                    ],
                },
                title={"text": score_label, "font": {"color": TEXT_MUT, "size": 14}},
            ))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": TEXT_PRI}, height=220, margin=dict(l=20, r=20, t=30, b=10),
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        except ImportError:
            st.markdown(f"""
<div style="text-align:center; padding:20px 0;">
  <div style="font-size:52px; font-weight:900; color:{score_color};">{latest_score:.0f}</div>
  <div style="font-size:14px; color:{TEXT_MUT};">/ 100 — {score_label}</div>
</div>""", unsafe_allow_html=True)

        st.markdown(f"""
<div style="font-size:11px; color:{TEXT_MUT}; text-align:center; margin-top:4px;">
  Configuration-based posture estimate. Not a certified security rating.
</div>""", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with col_right:
        st.markdown(f'<div class="ss-card-accent">', unsafe_allow_html=True)
        st.markdown("**Findings by Severity**")
        counts = count_by_severity(all_findings)

        try:
            import plotly.graph_objects as go
            sevs = ["Critical", "High", "Medium", "Low", "Informational"]
            colors = [CORAL, CORAL, LAVENDER, MINT, TEXT_MUT]
            fig2 = go.Figure(go.Bar(
                x=sevs,
                y=[counts.get(s, 0) for s in sevs],
                marker_color=colors,
                text=[counts.get(s, 0) for s in sevs],
                textposition="outside",
                textfont={"color": TEXT_PRI},
            ))
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": TEXT_PRI}, height=220,
                margin=dict(l=10, r=10, t=20, b=30),
                xaxis={"tickfont": {"color": TEXT_MUT}, "gridcolor": BORDER},
                yaxis={"tickfont": {"color": TEXT_MUT}, "gridcolor": BORDER, "zeroline": False},
                showlegend=False,
            )
            st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
        except ImportError:
            for sev in ["Critical", "High", "Medium", "Low"]:
                c = counts.get(sev, 0)
                color = SEV_COLORS.get(sev, TEXT_MUT)
                pct = min(100, c * 20)
                st.markdown(f"""
<div style="margin-bottom:8px;">
  <div style="display:flex;justify-content:space-between;font-size:13px;">
    <span>{severity_badge(sev)}</span><span style="color:{TEXT_MUT};">{c}</span>
  </div>
  <div class="progress-bar-outer">
    <div class="progress-bar-inner" style="width:{pct}%;background:{color};"></div>
  </div>
</div>""", unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

    # Recent findings + Fix-First
    col_a, col_b = st.columns([3, 2])

    with col_a:
        st.markdown(f'<div class="ss-card">', unsafe_allow_html=True)
        st.markdown("**Recent Findings**")
        recent = sorted(all_findings, key=lambda x: x.get("created_at",""), reverse=True)[:8]
        if recent:
            def _finding_row(f):
                st_color = MINT if f.get("status") == "resolved" else CORAL
                st_text = "✓ Resolved" if f.get("status") == "resolved" else "Open"
                title = f.get("title", "")
                short = title[:55] + ("…" if len(title) > 55 else "")
                return (
                    f"<tr><td>{severity_badge(f.get('severity',''))}</td>"
                    f"<td style='color:{TEXT_PRI};'>{_html_text(short)}</td>"
                    f"<td style='color:{TEXT_MUT};font-size:12px;'>{_html_text(f.get('target',''))}</td>"
                    f"<td><span style='color:{st_color};font-size:12px;'>{_html_text(st_text)}</span></td></tr>"
                )
            rows_html = "".join(_finding_row(f) for f in recent)
            st.markdown(f"""
<table class="ss-table">
<thead><tr><th>Sev</th><th>Finding</th><th>Target</th><th>Status</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>""", unsafe_allow_html=True)
        else:
            st.markdown(f"<p style='color:{TEXT_MUT};'>No findings yet.</p>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with col_b:
        st.markdown(f'<div class="ss-card">', unsafe_allow_html=True)
        st.markdown("**Fix-First Recommendations**")
        recs = get_fix_first_recommendations(all_findings, top_n=3)
        if recs:
            for r in recs:
                priority_color = CORAL if r["priority_label"] == "Fix Immediately" else (LAVENDER if r["priority_label"] == "Fix Next" else TEXT_MUT)
                st.markdown(f"""
<div style="margin-bottom:12px; padding:10px; background:{BG_SURF}; border-radius:8px;
            border-left:3px solid {priority_color};">
  <div style="font-size:11px;font-weight:700;color:{priority_color};text-transform:uppercase;
              letter-spacing:0.05em;margin-bottom:4px;">{_html_text(r['priority_label'])}</div>
  <div style="font-size:13px;font-weight:600;color:{TEXT_PRI};">{_html_text(r['title'][:60])}</div>
  <div style="font-size:12px;color:{TEXT_MUT};margin-top:4px;">{_html_text(r['estimated_effort'])}</div>
</div>""", unsafe_allow_html=True)
        else:
            st.markdown(f"<p style='color:{TEXT_MUT};'>No open findings requiring action.</p>",
                        unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    # Recent scans table
    st.markdown(f'<div class="ss-card">', unsafe_allow_html=True)
    st.markdown("**Recent Scans**")
    recent_scans = sorted(scans, key=lambda x: x.get("started_at",""), reverse=True)[:5]
    if recent_scans:
        def _scan_row(s):
            sc_color = MINT if (s.get("posture_score") or 0) >= 60 else CORAL
            st_color = MINT if s.get("status") == "completed" else CORAL
            ts = s.get("started_at", "")[:16].replace("T", " ")
            return (
                f"<tr><td style='color:{LAVENDER};font-family:monospace;font-size:12px;'>{_html_text(s.get('target_domain',''))}</td>"
                f"<td style='color:{TEXT_MUT};font-size:12px;'>{_html_text(ts)}</td>"
                f"<td style='color:{sc_color};font-weight:700;'>{_html_text(s.get('posture_score','—'))}</td>"
                f"<td style='color:{TEXT_PRI};'>{_html_text(s.get('findings_count','—'))}</td>"
                f"<td><span style='color:{st_color};'>{_html_text(s.get('status','').capitalize())}</span></td></tr>"
            )
        rows = "".join(_scan_row(s) for s in recent_scans)
        st.markdown(f"""
<table class="ss-table">
<thead><tr><th>Domain</th><th>Started</th><th>Score</th><th>Findings</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody>
</table>""", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Page: Security Scanner
# ---------------------------------------------------------------------------

def page_scanner():
    page_header("Security Scanner",
                "Non-destructive HTTP/HTTPS configuration assessment. Only scan websites you own or are authorized to test.")

    if is_demo():
        st.markdown(f'<div class="demo-banner">⚠ DEMO MODE — Real scans are disabled. Use the Demo Scan button below to see sample results.</div>',
                    unsafe_allow_html=True)

    st.markdown(f"""
<div class="ss-card">
  <div style="font-size:14px;font-weight:700;color:{LAVENDER};margin-bottom:10px;">⬡ What this scanner checks</div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:13px;color:{TEXT_MUT};">
    <div>✓ HTTPS usage &amp; TLS certificate validity</div>
    <div>✓ HTTP security response headers (6 checks)</div>
    <div>✓ CORS header configuration</div>
    <div>✓ Response status &amp; timing</div>
    <div style="color:{CORAL};">✗ No port scanning or exploitation</div>
    <div style="color:{CORAL};">✗ No password guessing or crawling</div>
  </div>
</div>""", unsafe_allow_html=True)

    with st.form("scan_form"):
        url_input = st.text_input(
            "Target URL",
            placeholder="https://example.com",
            help="Enter the full URL of the website you are authorized to assess.",
        )
        st.markdown(f"""
<div style="font-size:12px;color:{CORAL};margin-top:-8px;margin-bottom:6px;">
  ⚠ Only scan websites you own or have explicit written authorization to assess.
</div>""", unsafe_allow_html=True)

        col1, col2 = st.columns([2, 1])
        with col1:
            scan_btn = st.form_submit_button("▶ Start Scan", use_container_width=True)
        with col2:
            demo_btn = st.form_submit_button("⊙ Load Demo Results", use_container_width=True)

    if demo_btn:
        demo_scans, demo_findings = load_demo_data()
        if demo_scans:
            st.session_state["scan_result"] = {
                "demo": True,
                "scan": demo_scans[0],
                "findings": [f for f in demo_findings if f["scan_id"] == demo_scans[0]["id"]],
                "score": demo_scans[0]["posture_score"],
            }
            st.rerun()

    if scan_btn:
        if is_demo():
            st.warning("Real scans are not available in demo mode. Use 'Load Demo Results' to see an example.")
        elif url_input:
            is_valid, err, norm_url, hostname = validate_target_url(url_input)
            if not is_valid:
                st.error(f"Invalid target: {err}")
            else:
                uid = st.session_state["user_id"]
                scan_id = create_scan(uid, norm_url, hostname)
                progress_bar = st.progress(0, text="Connecting to target…")
                status_msg = st.empty()

                try:
                    progress_bar.progress(20, text="Fetching response headers…")
                    result = run_scan(scan_id, uid, norm_url, hostname)
                    progress_bar.progress(70, text="Analyzing security configuration…")

                    if result["status"] == "completed":
                        score = calculate_posture_score(result["findings"])
                        complete_scan(scan_id, score, len(result["findings"]))
                        save_findings(result["findings"])
                        progress_bar.progress(100, text="Scan complete.")
                        st.session_state["scan_result"] = {
                            "demo": False,
                            "scan": get_scan(scan_id, uid),
                            "findings": get_findings_for_scan(scan_id, uid),
                            "score": score,
                            "ssl_info": result.get("ssl_info"),
                            "response_status": result.get("response_status"),
                            "response_time_ms": result.get("response_time_ms"),
                            "final_url": result.get("final_url"),
                            "checks_skipped": result.get("checks_skipped", []),
                        }
                    else:
                        save_findings(result.get("findings", []))
                        fail_scan(scan_id, result.get("error", "Unknown error"))
                        progress_bar.empty()
                        st.error(f"Scan failed: {result.get('error', 'Unknown error')}")
                except Exception as exc:
                    fail_scan(scan_id, str(exc))
                    progress_bar.empty()
                    st.error(f"An unexpected error occurred: {exc}")
                    logger.exception("Scan error")

    # Show results
    sr = st.session_state.get("scan_result")
    if sr:
        _render_scan_results(sr)


def _render_scan_results(sr: dict):
    scan = sr.get("scan", {})
    findings = sr.get("findings", [])
    score = sr.get("score", 0)
    is_demo_result = sr.get("demo", False)
    score_label, _ = get_posture_label(score)
    score_color = MINT if score >= 70 else (LAVENDER if score >= 50 else CORAL)

    st.markdown("---")
    if is_demo_result:
        st.markdown(f'<div class="demo-banner">⚠ SAMPLE DATA — NOT A LIVE SECURITY SCAN</div>',
                    unsafe_allow_html=True)

    # Summary row
    col1, col2, col3, col4 = st.columns(4)
    counts = count_by_severity(findings)
    with col1:
        st.markdown(metric_card("Posture Score", f"{score:.0f}/100", score_color), unsafe_allow_html=True)
    with col2:
        st.markdown(metric_card("Total Findings", str(len(findings)), LAVENDER), unsafe_allow_html=True)
    with col3:
        st.markdown(metric_card("High/Critical", str(counts.get("Critical",0)+counts.get("High",0)), CORAL), unsafe_allow_html=True)
    with col4:
        st.markdown(metric_card("Target", scan.get("target_domain","?"), MINT), unsafe_allow_html=True)

    # Response metadata
    if not is_demo_result:
        meta_parts = []
        if sr.get("response_status"):
            meta_parts.append(_html_text(f"HTTP {sr['response_status']}"))
        if sr.get("response_time_ms"):
            meta_parts.append(_html_text(f"{sr['response_time_ms']:.0f}ms"))
        if sr.get("final_url"):
            meta_parts.append(_html_text(f"Final URL: {sr['final_url']}"))
        if meta_parts:
            st.markdown(f"""
<div style="font-size:12px;color:{TEXT_MUT};padding:8px 0;"> {' · '.join(meta_parts)}</div>""",
                        unsafe_allow_html=True)

    # Findings
    if not findings:
        st.markdown(f"""
<div class="ss-card" style="text-align:center;">
  <div style="color:{MINT};font-size:20px;">✓</div>
  <div style="font-weight:700;color:{TEXT_PRI};margin-top:8px;">No configuration issues detected</div>
  <div style="color:{TEXT_MUT};font-size:13px;margin-top:4px;">
    Note: absence of findings does not guarantee the site is secure.
  </div>
</div>""", unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="section-title">Findings ({len(findings)})</div>',
                    unsafe_allow_html=True)
        for f in findings:
            sev = f.get("severity","")
            color = SEV_COLORS.get(sev, TEXT_MUT)
            with st.expander(
                severity_expander_label(sev, f.get("title", "")),
                expanded=(sev in ("Critical", "High")),
            ):
                st.markdown(_finding_details_html(f), unsafe_allow_html=True)

    # Skipped checks
    if sr.get("checks_skipped"):
        with st.expander("Checks that could not be completed"):
            for s in sr["checks_skipped"]:
                st.markdown(f"- {_html_text(s)}")

    # Download buttons
    st.markdown(f'<div class="section-title">Download Report</div>', unsafe_allow_html=True)
    dl_col1, dl_col2, dl_col3 = st.columns(3)

    scan_obj = scan if isinstance(scan, dict) else {}

    with dl_col1:
        csv_data = generate_csv(findings)
        st.download_button("⬇ CSV Export", csv_data, file_name="securesight_findings.csv",
                           mime="text/csv", use_container_width=True)
    with dl_col2:
        md_data = generate_markdown(scan_obj, findings, score)
        st.download_button("⬇ Markdown Report", md_data, file_name="securesight_report.md",
                           mime="text/markdown", use_container_width=True)
    with dl_col3:
        html_data = generate_html(scan_obj, findings, score)
        st.download_button("⬇ HTML Report", html_data, file_name="securesight_report.html",
                           mime="text/html", use_container_width=True)


# ---------------------------------------------------------------------------
# Page: Findings & Risks
# ---------------------------------------------------------------------------

def page_findings():
    page_header("Findings & Risks", "Review, filter, and manage security findings. Mark issues resolved as you fix them.")

    if is_demo():
        st.markdown(f'<div class="demo-banner">⚠ SAMPLE DATA — NOT A LIVE SECURITY SCAN</div>',
                    unsafe_allow_html=True)
        _, all_findings = load_demo_data()
    else:
        uid = st.session_state["user_id"]
        all_findings = get_findings_for_user(uid)

    if not all_findings:
        st.markdown(f"""
<div class="ss-card" style="text-align:center; padding:40px;">
  <div style="font-size:40px; color:{LAVENDER}; margin-bottom:10px;">⚑</div>
  <div style="font-size:18px; font-weight:700; color:{TEXT_PRI}; margin-bottom:8px;">No findings yet</div>
  <div style="font-size:14px; color:{TEXT_MUT};">Run a scan to see security findings here.</div>
</div>""", unsafe_allow_html=True)
        return

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        filter_sev = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low", "Informational"])
    with col2:
        filter_status = st.selectbox("Status", ["All", "open", "resolved"])
    with col3:
        domains = ["All"] + sorted({f.get("target","") for f in all_findings})
        filter_domain = st.selectbox("Domain", domains)

    filtered = all_findings
    if filter_sev != "All":
        filtered = [f for f in filtered if f.get("severity") == filter_sev]
    if filter_status != "All":
        filtered = [f for f in filtered if f.get("status") == filter_status]
    if filter_domain != "All":
        filtered = [f for f in filtered if f.get("target") == filter_domain]

    st.markdown(f"<p style='color:{TEXT_MUT};font-size:13px;'>Showing {len(filtered)} of {len(all_findings)} findings</p>",
                unsafe_allow_html=True)

    for f in filtered:
        sev = f.get("severity", "")
        color = SEV_COLORS.get(sev, TEXT_MUT)
        status = f.get("status", "open")
        status_color = MINT if status == "resolved" else CORAL

        with st.expander(severity_expander_label(sev, f.get("title", "")), expanded=False):
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.markdown("**Check**")
                st.text(f.get("check_name", ""))
            with col_b:
                st.markdown("**Confidence**")
                st.text(f.get("confidence", ""))
            with col_c:
                st.markdown(f"**Status:** <span style='color:{status_color};'>{_html_text(status.capitalize())}</span>",
                            unsafe_allow_html=True)

            st.markdown(_finding_evidence_html(f.get("evidence", "N/A")), unsafe_allow_html=True)

            with st.expander("Details", expanded=False):
                st.markdown("**Explanation**")
                st.text(f.get("explanation", ""))
                st.markdown("**Potential Impact**")
                st.text(f.get("impact", ""))
                st.markdown("**Recommendation**")
                st.text(f.get("recommendation", ""))

            if not is_demo() and status == "open":
                with st.form(f"resolve_form_{f['id']}"):
                    note = st.text_input("Resolution note (optional)", key=f"note_{f['id']}")
                    if st.form_submit_button("✓ Mark Resolved"):
                        update_finding_status(f["id"], uid, "resolved", note)
                        st.success("Finding marked as resolved.")
                        st.rerun()


# ---------------------------------------------------------------------------
# Page: Scan History
# ---------------------------------------------------------------------------

def page_history():
    page_header("Scan History", "Review all past security assessments.")

    if is_demo():
        st.markdown(f'<div class="demo-banner">⚠ SAMPLE DATA — NOT A LIVE SECURITY SCAN</div>',
                    unsafe_allow_html=True)
        scans, demo_findings = load_demo_data()
    else:
        uid = st.session_state["user_id"]
        scans = get_scans_for_user(uid)

    if not scans:
        st.markdown(f"""
<div class="ss-card" style="text-align:center; padding:40px;">
  <div style="font-size:18px; font-weight:700; color:{TEXT_PRI}; margin-bottom:8px;">No scan history</div>
  <div style="font-size:14px; color:{TEXT_MUT};">Complete a scan to see it here.</div>
</div>""", unsafe_allow_html=True)
        return

    # Filter by domain
    all_domains = sorted({s.get("target_domain","") for s in scans})
    filter_domain = st.selectbox("Filter by domain", ["All"] + all_domains)

    display_scans = scans if filter_domain == "All" else [s for s in scans if s.get("target_domain") == filter_domain]

    for s in display_scans:
        score = s.get("posture_score")
        score_color = MINT if (score or 0) >= 60 else CORAL
        status_color = MINT if s.get("status") == "completed" else CORAL

        with st.expander(
            f"⊙  {_html_text(s.get('target_domain',''))}  ·  "
            f"Score: {_html_text(score or '—')}  ·  "
            f"{_html_text(s.get('started_at','')[:16].replace('T',' '))}",
            expanded=False
        ):
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.markdown("**Domain**")
                st.text(s.get("target_domain", ""))
            with c2:
                st.markdown(f"**Score:** <span style='color:{score_color};font-weight:700;'>{_html_text(score or '—')}</span>",
                            unsafe_allow_html=True)
            with c3:
                st.markdown("**Findings**")
                st.text(s.get("findings_count", 0))
            with c4:
                st.markdown(f"**Status:** <span style='color:{status_color};'>{_html_text(s.get('status','').capitalize())}</span>",
                            unsafe_allow_html=True)

            st.markdown("**Scan ID**")
            st.code(s.get("id", ""), language=None)
            st.markdown("**Started**")
            st.text(s.get("started_at", "").replace("T", " "))
            if s.get("completed_at"):
                st.markdown("**Completed**")
                st.text(s.get("completed_at", "").replace("T", " "))

            if not is_demo():
                btn_col1, btn_col2 = st.columns(2)
                with btn_col1:
                    if st.button("View Findings", key=f"view_{s['id']}"):
                        findings = get_findings_for_scan(s["id"], uid)
                        st.session_state["scan_result"] = {
                            "demo": False, "scan": s,
                            "findings": findings,
                            "score": score or 0,
                        }
                        st.session_state["page"] = "Security Scanner"
                        st.rerun()
                with btn_col2:
                    if st.button("Download Report", key=f"dl_{s['id']}"):
                        findings = get_findings_for_scan(s["id"], uid)
                        html_rpt = generate_html(s, findings, score or 0)
                        st.download_button(
                            "⬇ HTML Report",
                            html_rpt,
                            file_name=f"report_{s['id'][:8]}.html",
                            mime="text/html",
                            key=f"dl_html_{s['id']}",
                        )
            else:
                st.markdown(f"<span style='color:{TEXT_MUT};font-size:12px;'>Demo mode — download not available for sample data.</span>",
                            unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Page: Compare Scans
# ---------------------------------------------------------------------------

def page_compare():
    page_header("Compare Scans", "Compare two assessments of the same target to track progress.")

    if is_demo():
        st.markdown(f'<div class="demo-banner">⚠ SAMPLE DATA — NOT A LIVE SECURITY SCAN</div>',
                    unsafe_allow_html=True)
        scans, demo_findings = load_demo_data()
        # Only show scans for same domain
        domains = sorted({s["target_domain"] for s in scans})
    else:
        uid = st.session_state["user_id"]
        scans = get_scans_for_user(uid)
        domains = sorted({s["target_domain"] for s in scans})

    if len(scans) < 2:
        st.markdown(f"""
<div class="ss-card" style="text-align:center; padding:40px;">
  <div style="font-size:18px; font-weight:700; color:{TEXT_PRI}; margin-bottom:8px;">Need at least 2 scans</div>
  <div style="font-size:14px; color:{TEXT_MUT};">Complete two scans of the same target to compare them.</div>
</div>""", unsafe_allow_html=True)
        return

    selected_domain = st.selectbox("Select domain to compare", domains)
    domain_scans = [s for s in scans if s["target_domain"] == selected_domain]

    if len(domain_scans) < 2:
        st.warning(
            f"Only 1 scan found for {_html_text(selected_domain)}. "
            "Scan it again to enable comparison."
        )
        return

    scan_labels = [f"{s.get('started_at','')[:16].replace('T',' ')} — Score: {s.get('posture_score','?')}"
                   for s in domain_scans]

    col1, col2 = st.columns(2)
    with col1:
        idx_a = st.selectbox("Earlier scan (Scan A)", range(len(domain_scans)),
                             format_func=lambda i: scan_labels[i], key="cmp_a")
    with col2:
        idx_b = st.selectbox("Later scan (Scan B)", range(len(domain_scans)),
                             format_func=lambda i: scan_labels[i],
                             index=min(1, len(domain_scans)-1), key="cmp_b")

    if idx_a == idx_b:
        st.warning("Please select two different scans.")
        return

    scan_a = domain_scans[idx_a]
    scan_b = domain_scans[idx_b]

    if is_demo():
        findings_a = [f for f in demo_findings if f["scan_id"] == scan_a["id"]]
        findings_b = [f for f in demo_findings if f["scan_id"] == scan_b["id"]]
    else:
        findings_a = get_findings_for_scan(scan_a["id"], uid)
        findings_b = get_findings_for_scan(scan_b["id"], uid)

    comparison = compare_scan_findings(findings_a, findings_b)

    score_a = scan_a.get("posture_score") or 0
    score_b = scan_b.get("posture_score") or 0
    delta = score_b - score_a
    delta_color = MINT if delta >= 0 else CORAL
    delta_str = f"+{delta:.1f}" if delta >= 0 else f"{delta:.1f}"

    st.markdown(f"""
<div class="ss-card" style="text-align:center; padding:20px;">
  <div style="display:grid;grid-template-columns:1fr auto 1fr;gap:20px;align-items:center;">
    <div>
      <div style="font-size:12px;color:{TEXT_MUT};margin-bottom:4px;">Scan A</div>
      <div style="font-size:40px;font-weight:900;color:{LAVENDER};">{score_a:.0f}</div>
      <div style="font-size:12px;color:{TEXT_MUT};">{_html_text(scan_a.get('started_at','')[:16].replace('T',' '))}</div>
    </div>
    <div>
      <div style="font-size:28px;font-weight:900;color:{delta_color};">{delta_str}</div>
      <div style="font-size:11px;color:{TEXT_MUT};">Score Change</div>
    </div>
    <div>
      <div style="font-size:12px;color:{TEXT_MUT};margin-bottom:4px;">Scan B</div>
      <div style="font-size:40px;font-weight:900;color:{LAVENDER};">{score_b:.0f}</div>
      <div style="font-size:12px;color:{TEXT_MUT};">{_html_text(scan_b.get('started_at','')[:16].replace('T',' '))}</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    def render_finding_list(title: str, findings: list, color: str):
        st.markdown(f"<div style='font-size:14px;font-weight:700;color:{color};margin:16px 0 8px;'>{_html_text(title)} ({len(findings)})</div>",
                    unsafe_allow_html=True)
        if not findings:
            st.markdown(f"<p style='color:{TEXT_MUT};font-size:13px;'>None.</p>", unsafe_allow_html=True)
        else:
            for f in findings:
                severity = f.get("severity", "")
                title_text = _html_text(f.get("title", ""))
                st.markdown(
                    f"""
<div style="display:flex;align-items:flex-start;gap:10px;padding:11px 13px;
            margin:7px 0;background:{BG_CARD};border:1px solid {BORDER};
            border-radius:10px;line-height:1.55;">
  <span style="flex:0 0 auto;">{severity_badge(severity)}</span>
  <span style="min-width:0;color:{TEXT_PRI};overflow-wrap:anywhere;">{title_text}</span>
</div>
""",
                    unsafe_allow_html=True,
                )

    render_finding_list("⊕ New in Scan B", comparison["new_findings"], CORAL)
    render_finding_list("⊙ Persisting in both", comparison["persistent_findings"], LAVENDER)
    render_finding_list("⊟ Not detected in Scan B (not auto-resolved)", comparison["not_detected_in_b"], MINT)
    render_finding_list("✓ Resolved in Scan B", comparison["resolved_findings"], MINT)

    st.markdown(f"""
<div style="font-size:11px;color:{TEXT_MUT};margin-top:12px;">
  Note: 'Not detected in Scan B' does not mean the issue is fixed — it may not have been detectable in that scan.
  Only mark findings resolved after verifying the fix.
</div>""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Page: Reports
# ---------------------------------------------------------------------------

def page_reports():
    page_header("Reports", "Generate and download security assessment reports.")

    if is_demo():
        st.markdown(f'<div class="demo-banner">⚠ SAMPLE DATA — NOT A LIVE SECURITY SCAN</div>',
                    unsafe_allow_html=True)
        demo_scans, demo_findings = load_demo_data()
        scans = demo_scans
    else:
        uid = st.session_state["user_id"]
        scans = get_scans_for_user(uid)
        reportable_scans = []
        for scan in scans:
            if scan.get("status") == "completed":
                reportable_scans.append(scan)
            elif scan.get("status") == "failed" and get_findings_for_scan(scan["id"], uid):
                reportable_scans.append(scan)
        scans = reportable_scans

    if not scans:
        st.info("No reportable scans available. Run a scan first.")
        return

    scan_labels = [f"{_html_text(s.get('target_domain',''))} — {_html_text(s.get('started_at','')[:16].replace('T',' '))} — Score: {_html_text(s.get('posture_score','?'))}"
                   for s in scans]
    selected_idx = st.selectbox("Select scan", range(len(scans)),
                                format_func=lambda i: scan_labels[i])
    selected_scan = scans[selected_idx]

    if is_demo():
        findings = [f for f in demo_findings if f["scan_id"] == selected_scan["id"]]
    else:
        findings = get_findings_for_scan(selected_scan["id"], uid)

    score = selected_scan.get("posture_score") or calculate_posture_score(findings)
    score_label, _ = get_posture_label(score)
    counts = count_by_severity(findings)

    st.markdown(f"""
<div class="ss-card">
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:12px;">
    <div><span style="color:{TEXT_MUT};font-size:11px;text-transform:uppercase;">Target</span>
    <div style="font-weight:700;color:{LAVENDER};">{_html_text(selected_scan.get('target_domain',''))}</div></div>
    <div><span style="color:{TEXT_MUT};font-size:11px;text-transform:uppercase;">Score</span>
    <div style="font-weight:700;color:{MINT};">{score:.0f} — {score_label}</div></div>
    <div><span style="color:{TEXT_MUT};font-size:11px;text-transform:uppercase;">Findings</span>
    <div style="font-weight:700;color:{TEXT_PRI};">{len(findings)}</div></div>
    <div><span style="color:{TEXT_MUT};font-size:11px;text-transform:uppercase;">High/Critical</span>
    <div style="font-weight:700;color:{CORAL};">{counts.get('Critical',0)+counts.get('High',0)}</div></div>
  </div>
</div>""", unsafe_allow_html=True)

    st.markdown(f'<div class="section-title">Export Formats</div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown(f"""
<div class="ss-card">
  <div style="font-size:14px;font-weight:700;color:{LAVENDER};margin-bottom:6px;">CSV Export</div>
  <div style="font-size:12px;color:{TEXT_MUT};margin-bottom:12px;">
    Findings table as comma-separated values. Import into Excel or other tools.
  </div>
</div>""", unsafe_allow_html=True)
        csv_data = generate_csv(findings)
        st.download_button("⬇ Download CSV", csv_data,
                           file_name=f"securesight_{selected_scan.get('target_domain','')}_{selected_scan.get('id','')[:8]}.csv",
                           mime="text/csv", use_container_width=True)

    with c2:
        st.markdown(f"""
<div class="ss-card">
  <div style="font-size:14px;font-weight:700;color:{MINT};margin-bottom:6px;">Markdown Report</div>
  <div style="font-size:12px;color:{TEXT_MUT};margin-bottom:12px;">
    Full narrative report in Markdown format. Renders in GitHub, VS Code, and Obsidian.
  </div>
</div>""", unsafe_allow_html=True)
        md_data = generate_markdown(selected_scan, findings, score)
        st.download_button("⬇ Download Markdown", md_data,
                           file_name=f"securesight_{selected_scan.get('target_domain','')}_{selected_scan.get('id','')[:8]}.md",
                           mime="text/markdown", use_container_width=True)

    with c3:
        st.markdown(f"""
<div class="ss-card">
  <div style="font-size:14px;font-weight:700;color:{CORAL};margin-bottom:6px;">HTML Report</div>
  <div style="font-size:12px;color:{TEXT_MUT};margin-bottom:12px;">
    Polished, self-contained HTML report. Open in any browser or share as a file.
  </div>
</div>""", unsafe_allow_html=True)
        html_data = generate_html(selected_scan, findings, score)
        st.download_button("⬇ Download HTML", html_data,
                           file_name=f"securesight_{selected_scan.get('target_domain','')}_{selected_scan.get('id','')[:8]}.html",
                           mime="text/html", use_container_width=True)

    st.markdown(f"""
<div style="font-size:11px;color:{TEXT_MUT};margin-top:12px;padding:8px;border:1px solid {BORDER};border-radius:6px;">
  PDF export is not available in this version. Use the HTML report and print to PDF from your browser (File → Print → Save as PDF).
</div>""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Page: Learning Center
# ---------------------------------------------------------------------------

LEARNING_TOPICS = [
    {
        "title": "HTTPS and TLS Certificates",
        "icon": "🔒",
        "what": "HTTPS encrypts data in transit using Transport Layer Security (TLS). A valid TLS certificate authenticates the server's identity.",
        "why": "Without HTTPS, network attackers can intercept credentials, cookies, and form data. Browsers mark HTTP sites as 'Not secure'.",
        "can_observe": "Whether the site uses HTTPS, and basic certificate validity and expiry dates.",
        "cannot_prove": "Full TLS version and cipher-suite configuration requires specialized tools like testssl.sh or SSL Labs.",
    },
    {
        "title": "Strict-Transport-Security (HSTS)",
        "icon": "⬡",
        "what": "HSTS tells browsers to always use HTTPS for a domain, even if the user types HTTP. It prevents protocol-downgrade attacks.",
        "why": "On a user's first visit, HTTP can be downgraded by an attacker. HSTS prevents this for subsequent visits within the max-age window.",
        "can_observe": "Presence, max-age value, and includeSubDomains/preload directives.",
        "cannot_prove": "Whether the site is actually on the HSTS preload list without querying the list directly.",
    },
    {
        "title": "Content Security Policy (CSP)",
        "icon": "⊛",
        "what": "CSP is an HTTP header that restricts which scripts, styles, images, and other resources a browser can load.",
        "why": "It is one of the most effective browser-side defences against Cross-Site Scripting (XSS) attacks.",
        "can_observe": "Presence of the header and obvious weakening directives like 'unsafe-inline' or 'unsafe-eval'.",
        "cannot_prove": "Whether the CSP is appropriately strict for the specific application without deep analysis.",
    },
    {
        "title": "X-Frame-Options (Clickjacking)",
        "icon": "⊠",
        "what": "X-Frame-Options prevents the page from being embedded in an <iframe> on other domains.",
        "why": "Clickjacking attacks overlay invisible iframes over a legitimate page to trick users into clicking on hidden controls.",
        "can_observe": "Presence and value of the X-Frame-Options header.",
        "cannot_prove": "Whether the site is actually exploitable — context (login page vs. public blog) matters greatly.",
    },
    {
        "title": "X-Content-Type-Options",
        "icon": "⊙",
        "what": "This header prevents browsers from MIME-sniffing, i.e., guessing a file's type when the server's declared type seems wrong.",
        "why": "MIME confusion can cause browsers to execute uploaded files as scripts when the server declared them as images.",
        "can_observe": "Presence of the header with the value 'nosniff'.",
        "cannot_prove": "Whether the site actually accepts untrusted file uploads — that requires application testing.",
    },
    {
        "title": "Referrer-Policy",
        "icon": "⊟",
        "what": "Controls the Referer header sent with navigation requests. Limits leakage of URL data to third-party sites.",
        "why": "URLs often contain session tokens, user IDs, or sensitive query parameters that should not be shared with external resources.",
        "can_observe": "Presence and value of the Referrer-Policy header.",
        "cannot_prove": "Whether the application actually uses sensitive data in URLs.",
    },
    {
        "title": "Permissions-Policy",
        "icon": "⊕",
        "what": "Controls which browser features (camera, microphone, geolocation, etc.) the page and its iframes can use.",
        "why": "Restricts third-party embedded content from accessing device features you have not explicitly permitted.",
        "can_observe": "Presence of the header and specified feature restrictions.",
        "cannot_prove": "Whether any third-party iframes are present or abusing features.",
    },
    {
        "title": "Cross-Origin Resource Sharing (CORS)",
        "icon": "⊞",
        "what": "CORS controls which external websites can read responses from cross-origin requests to your server.",
        "why": "Overly permissive CORS on authenticated endpoints can allow attacker websites to read private user data.",
        "can_observe": "Access-Control-Allow-Origin and Access-Control-Allow-Credentials response headers.",
        "cannot_prove": "Whether any endpoint actually returns sensitive data to cross-origin requesters — needs full app review.",
    },
    {
        "title": "False Positives and Context",
        "icon": "⚑",
        "what": "A finding is a 'false positive' when the scanner flags something that is not actually a risk in context.",
        "why": "Header checks cannot know the full application context. A CORS wildcard may be fine for a public CDN but risky for an authenticated API.",
        "can_observe": "Configuration patterns that commonly correlate with risk.",
        "cannot_prove": "Actual exploitability without understanding the full application.",
    },
    {
        "title": "Responsible Security Testing",
        "icon": "◎",
        "what": "Responsible security testing means only scanning systems you own or are explicitly authorized to test.",
        "why": "Unauthorized scanning may be illegal and can disrupt services. SecureSight AI is designed for configuration review, not exploitation.",
        "can_observe": "Configuration weaknesses from observable HTTP responses.",
        "cannot_prove": "Nothing about systems you are not authorized to assess.",
    },
]


def page_learning():
    page_header("Learning Center", "Understand web security concepts and what SecureSight AI can and cannot tell you.")

    for topic in LEARNING_TOPICS:
        with st.expander(f"{topic['icon']}  {_html_text(topic['title'])}", expanded=False):
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"""
<div style="margin-bottom:10px;">
  <div style="font-size:11px;text-transform:uppercase;color:{TEXT_MUT};font-weight:700;letter-spacing:.06em;margin-bottom:4px;">What it is</div>
  <div style="font-size:14px;color:{TEXT_PRI};">{_html_text(topic['what'])}</div>
</div>
<div style="margin-bottom:10px;">
  <div style="font-size:11px;text-transform:uppercase;color:{TEXT_MUT};font-weight:700;letter-spacing:.06em;margin-bottom:4px;">Why it matters</div>
  <div style="font-size:14px;color:{TEXT_PRI};">{_html_text(topic['why'])}</div>
</div>""", unsafe_allow_html=True)
            with c2:
                st.markdown(f"""
<div style="margin-bottom:10px;">
  <div style="font-size:11px;text-transform:uppercase;color:{MINT};font-weight:700;letter-spacing:.06em;margin-bottom:4px;">What SecureSight can observe</div>
  <div style="font-size:14px;color:{TEXT_PRI};">{_html_text(topic['can_observe'])}</div>
</div>
<div style="margin-bottom:10px;">
  <div style="font-size:11px;text-transform:uppercase;color:{CORAL};font-weight:700;letter-spacing:.06em;margin-bottom:4px;">What it cannot prove</div>
  <div style="font-size:14px;color:{TEXT_PRI};">{_html_text(topic['cannot_prove'])}</div>
</div>""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Page: Account Settings
# ---------------------------------------------------------------------------

def page_settings():
    page_header("Account Settings", "Manage your profile and data.")

    if is_demo():
        st.info("Account settings are not available in demo mode.")
        return

    uid = st.session_state["user_id"]
    user = get_user_by_id(uid)
    if not user:
        st.error("Could not load user data.")
        return

    st.markdown(f'<div class="ss-card">', unsafe_allow_html=True)
    st.markdown("**Profile**")
    initials = "".join(w[0].upper() for w in user["display_name"].split()[:2])
    safe_initials = _html_text(initials)
    st.markdown(f"""
<div style="display:flex;align-items:center;gap:16px;margin-bottom:16px;">
  <div style="width:56px;height:56px;border-radius:50%;background:{BG_SURF};border:2px solid {LAVENDER};
              display:flex;align-items:center;justify-content:center;font-weight:800;font-size:20px;color:{LAVENDER};">
    {safe_initials}
  </div>
  <div>
    {_account_profile_text_html(user)}
  </div>
</div>""", unsafe_allow_html=True)

    with st.form("update_name_form"):
        new_name = st.text_input("Display name", value=user["display_name"])
        if st.form_submit_button("Save Changes"):
            if new_name.strip():
                update_display_name(uid, new_name)
                st.session_state["display_name"] = new_name.strip()
                st.success("Display name updated.")
                st.rerun()
            else:
                st.error("Display name cannot be empty.")

    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(f'<div class="ss-card">', unsafe_allow_html=True)
    st.markdown("**Data & Privacy**")
    st.markdown(f"""
<div style="font-size:13px;color:{TEXT_MUT};line-height:1.7;">
  <p>Your scan history, findings, and account data are stored locally in a SQLite database file (<code>securesight.db</code>) on this machine.</p>
  <p>No data is transmitted to external servers. Passwords are stored as PBKDF2-SHA256 hashes — never in plaintext.</p>
  <p>To remove your data, delete the <code>securesight.db</code> file. This is an irreversible action.</p>
  <p>This is a local demonstration application. It is not designed for multi-user cloud deployment without additional security controls.</p>
</div>""", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    stats = get_user_stats(uid)
    st.markdown(f'<div class="ss-card">', unsafe_allow_html=True)
    st.markdown("**Your Statistics**")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Total Scans", stats["total_scans"])
    with c2:
        st.metric("Open Findings", stats["open_findings"])
    with c3:
        st.metric("Latest Score", f"{stats['latest_score']:.0f}" if stats["latest_score"] else "—")
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Main router
# ---------------------------------------------------------------------------

def main():
    inject_css()

    # Auth gate
    if not is_logged_in() and not is_demo():
        auth_page = st.session_state.get("auth_page", "login")
        if auth_page == "signup":
            page_signup()
        else:
            page_login()
        return

    render_sidebar()

    page = st.session_state.get("page", "Overview")

    PAGE_MAP = {
        "Overview":         page_overview,
        "Security Scanner": page_scanner,
        "Findings & Risks": page_findings,
        "Scan History":     page_history,
        "Compare Scans":    page_compare,
        "Reports":          page_reports,
        "Learning Center":  page_learning,
        "Account Settings": page_settings,
    }

    renderer = PAGE_MAP.get(page, page_overview)
    renderer()


if __name__ == "__main__":
    main()
