"""SentinelShield unified Streamlit dashboard. Run with ``streamlit run dashboard.py``."""
from __future__ import annotations

import csv
import html as html_lib
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any
import pickle
import warnings
warnings.filterwarnings("ignore")

import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

from adaptive_thresholds import AdaptiveThresholdEngine, scan_crowding
from scan_controller import ScanController
from runtime_config import CONFIG_PATH, load_runtime_config, save_runtime_config
from wifi_fingerprint import WiFiFingerprintStore
from analyst_feedback import record_feedback
from incident_assistant import explain

try:
    from threat_intelligence import get_threat_intelligence
except Exception:
    get_threat_intelligence = None

try:
    from notification_manager import NotificationManager
except Exception:
    NotificationManager = None

try:
    from novelty_alert_engine import evaluate_novelty
except Exception:
    evaluate_novelty = None

try:
    from streamlit_autorefresh import st_autorefresh
except ImportError:
    st_autorefresh = None

try:
    from behavioral_dashboard_view import render_behavioral_dashboard
except Exception:
    render_behavioral_dashboard = None

ROOT = Path(__file__).resolve().parent
SCAN_FILE = ROOT / "current_scan.csv"
ALERT_FILE = ROOT / "alert_history.csv"
FINGERPRINT_FILE = ROOT / "fingerprints.json"
AP_BASELINE_FILE = ROOT / "wifi_fingerprint_baseline.json"
SETTINGS_FILE = ROOT / "dashboard_settings.json"
THRESHOLD_STATE_FILE = ROOT / "adaptive_threshold_state.json"

st.set_page_config(page_title="SentinelShield", page_icon="🛡️", layout="wide")

# ─────────────────────────────────────────────────────────────────────────────
# Canonical Demo / Specification Data (matching PDF Mockups & Live Pipeline)
# ─────────────────────────────────────────────────────────────────────────────
SAMPLE_NETWORKS: list[dict[str, Any]] = [
    {
        "SSID": "Campus-WiFi",
        "BSSID": "A4:5E:60:2A:11:90",
        "RSSI": "-48 dBm",
        "Channel": 6,
        "Frequency": "2437",
        "Security": "WPA2",
        "Vendor": "Demo vendor",
        "Combined_Risk": 12.0,
        "Threat_Level": "SAFE",
        "Reasons": "Known fingerprint",
        "RF_Prediction": "Legitimate",
        "KNN_Prediction": "Legitimate",
        "Isolation_Forest": "Normal",
        "Ensemble_Evidence": "Low risk evidence",
        "Review_Status": "Review baseline",
        "Trust_State": "TRUSTED",
        "Similarity": 0.97,
        "Observations": 23,
        "Security_History": "WPA2",
        "Latest_Change": "No material change",
        "Evidence_Summary": "Known fingerprint",
    },
    {
        "SSID": "Library_Guest",
        "BSSID": "D8:3A:DD:81:20:4C",
        "RSSI": "-62 dBm",
        "Channel": 11,
        "Frequency": "2462",
        "Security": "WPA2",
        "Vendor": "Demo vendor",
        "Combined_Risk": 31.0,
        "Threat_Level": "MEDIUM",
        "Reasons": "New BSSID; verify baseline",
        "RF_Prediction": "Legitimate",
        "KNN_Prediction": "Uncertain",
        "Isolation_Forest": "Anomaly",
        "Ensemble_Evidence": "Mixed indicators",
        "Review_Status": "Investigate",
        "Trust_State": "OBSERVED",
        "Similarity": 0.74,
        "Observations": 6,
        "Security_History": "WPA2",
        "Latest_Change": "RSSI/channel review",
        "Evidence_Summary": "New BSSID; verify baseline",
    },
    {
        "SSID": "Campus-WiFi",
        "BSSID": "72:AF:11:CC:90:21",
        "RSSI": "-41 dBm",
        "Channel": 6,
        "Frequency": "2437",
        "Security": "Open",
        "Vendor": "Demo vendor",
        "Combined_Risk": 78.0,
        "Threat_Level": "HIGH",
        "Reasons": "SSID similarity + security mismatch",
        "RF_Prediction": "Fake-like",
        "KNN_Prediction": "Fake-like",
        "Isolation_Forest": "Anomaly",
        "Ensemble_Evidence": "Multiple indicators",
        "Review_Status": "Investigate",
        "Trust_State": "OBSERVED",
        "Similarity": 0.42,
        "Observations": 2,
        "Security_History": "Open",
        "Latest_Change": "Security mismatch",
        "Evidence_Summary": "SSID similarity + security mismatch",
    },
    {
        "Student_Hotspot": "BE:2C:7A:10:9F:44",
        "SSID": "Student_Hotspot",
        "BSSID": "BE:2C:7A:10:9F:44",
        "RSSI": "-78 dBm",
        "Channel": 1,
        "Frequency": "2412",
        "Security": "WPA2",
        "Vendor": "Demo vendor",
        "Combined_Risk": 18.0,
        "Threat_Level": "SAFE",
        "Reasons": "Low risk; first seen",
        "RF_Prediction": "Legitimate",
        "KNN_Prediction": "Legitimate",
        "Isolation_Forest": "Normal",
        "Ensemble_Evidence": "Low risk evidence",
        "Review_Status": "Low priority",
        "Trust_State": "OBSERVED",
        "Similarity": 0.85,
        "Observations": 1,
        "Security_History": "WPA2",
        "Latest_Change": "First seen",
        "Evidence_Summary": "Low risk; first seen",
    },
    {
        "SSID": "CoffeeGuest",
        "BSSID": "98:DA:C4:66:17:0A",
        "RSSI": "-55 dBm",
        "Channel": 36,
        "Frequency": "5180",
        "Security": "WPA3",
        "Vendor": "Demo vendor",
        "Combined_Risk": 9.0,
        "Threat_Level": "SAFE",
        "Reasons": "Fingerprint consistent",
        "RF_Prediction": "Legitimate",
        "KNN_Prediction": "Legitimate",
        "Isolation_Forest": "Normal",
        "Ensemble_Evidence": "Fingerprint consistent",
        "Review_Status": "Low priority",
        "Trust_State": "TRUSTED",
        "Similarity": 0.94,
        "Observations": 14,
        "Security_History": "WPA3",
        "Latest_Change": "Consistent",
        "Evidence_Summary": "Fingerprint consistent",
    },
    {
        "SSID": "Campus-WiFi",
        "BSSID": "02:1A:11:4B:22:99",
        "RSSI": "-43 dBm",
        "Channel": 6,
        "Frequency": "2437",
        "Security": "Open",
        "Vendor": "Demo vendor",
        "Combined_Risk": 88.0,
        "Threat_Level": "CRITICAL",
        "Reasons": "SSID clone suspicion; evidence review",
        "RF_Prediction": "Fake-like",
        "KNN_Prediction": "Fake-like",
        "Isolation_Forest": "Anomaly",
        "Ensemble_Evidence": "Multiple indicators",
        "Review_Status": "Investigate",
        "Trust_State": "OBSERVED",
        "Similarity": 0.35,
        "Observations": 1,
        "Security_History": "Open",
        "Latest_Change": "SSID clone suspicion",
        "Evidence_Summary": "SSID clone suspicion; evidence review",
    },
]

SAMPLE_ALERTS = [
    {
        "Time": "10:42:18",
        "SSID": "Campus-WiFi",
        "BSSID": "02:1A:11:4B:22:99",
        "Risk": 88,
        "Level": "CRITICAL",
        "Reason": "Fingerprint/security mismatch",
        "Delivery": "Not sent in preview",
    },
    {
        "Time": "10:41:53",
        "SSID": "Campus-WiFi",
        "BSSID": "72:AF:11:CC:90:21",
        "Risk": 78,
        "Level": "HIGH",
        "Reason": "Similar SSID and open security",
        "Delivery": "Not sent in preview",
    },
    {
        "Time": "10:37:02",
        "SSID": "Library_Guest",
        "BSSID": "D8:3A:DD:81:20:4C",
        "Risk": 31,
        "Level": "MEDIUM",
        "Reason": "New network observation",
        "Delivery": "Not sent in preview",
    },
]

SAMPLE_FINGERPRINTS = [
    {
        "SSID": "Campus-WiFi",
        "BSSID": "A4:5E:60:2A:11:90",
        "SIMILARITY": 0.97,
        "OBSERVATIONS": 23,
        "SECURITY HISTORY": "WPA2",
        "TRUST STATE": "TRUSTED",
        "LATEST CHANGE": "No material change",
    },
    {
        "SSID": "Library_Guest",
        "BSSID": "D8:3A:DD:81:20:4C",
        "SIMILARITY": 0.74,
        "OBSERVATIONS": 6,
        "SECURITY HISTORY": "WPA2",
        "TRUST STATE": "OBSERVED",
        "LATEST CHANGE": "RSSI/channel review",
    },
    {
        "SSID": "Campus-WiFi",
        "BSSID": "72:AF:11:CC:90:21",
        "SIMILARITY": 0.42,
        "OBSERVATIONS": 2,
        "SECURITY HISTORY": "Open",
        "TRUST STATE": "OBSERVED",
        "LATEST CHANGE": "Security mismatch",
    },
    {
        "SSID": "CoffeeGuest",
        "BSSID": "98:DA:C4:66:17:0A",
        "SIMILARITY": 0.94,
        "OBSERVATIONS": 14,
        "SECURITY HISTORY": "WPA3",
        "TRUST STATE": "TRUSTED",
        "LATEST CHANGE": "Consistent",
    },
]


def set_demo_mode(enabled: bool) -> None:
    """Safely stage demo mode change across Streamlit runs without widget lock errors."""
    st.session_state["pending_demo_mode"] = enabled


def is_demo_active() -> bool:
    if "pending_demo_mode" in st.session_state:
        return bool(st.session_state["pending_demo_mode"])
    return bool(st.session_state.get("demo_mode", False))


@st.cache_data(show_spinner=False)
def _get_css(mtime: float) -> str:
    css_path = ROOT / "assets" / "style.css"
    return css_path.read_text(encoding="utf-8") if css_path.exists() else ""


def load_dashboard_styles() -> None:
    """Load presentation CSS from assets/style.css with caching."""
    css_path = ROOT / "assets" / "style.css"
    if not css_path.exists():
        return
    try:
        css = _get_css(css_path.stat().st_mtime)
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
    except Exception as exc:
        st.warning(f"Dashboard styling could not be loaded: {exc}")


load_dashboard_styles()


def apply_color_scheme(dark_theme: bool) -> None:
    """Switch presentation tokens for dark theme while preserving backend state."""
    if not dark_theme:
        return
    st.markdown("""
    <style>
    :root { --ink:#e8edf7; --muted:#a7b2c5; --line:#29364b; --panel:#121c2b; --canvas:#0b1320; --accent:#8da5ff; }
    [data-testid="stSidebar"] { background:#101a29; }
    [data-testid="stHeader"] { background:rgba(11,19,32,.88); }
    [data-testid="stVerticalBlockBorderWrapper"], [data-testid="stExpander"] { background:var(--panel); }
    .ss-table-container { background:#121c2b; border-color:#29364b; }
    .ss-table th { background:#162438; color:#a7b2c5; border-color:#29364b; }
    .ss-table td { color:#e8edf7; border-color:#29364b; }
    .ss-table tr:hover td { background:#19293e; }
    .ss-metric-card { background:#121c2b; border-color:#29364b; }
    .ss-metric-value { color:#e8edf7; }
    .ss-header { background:#121c2b; border-color:#29364b; }
    .ss-title { color:#e8edf7; }
    .ss-preview-banner { background:#241d13; border-color:#713f12; color:#fde047; }
    .ss-alert-callout { background:#2b1216; border-color:#7f1d1d; color:#fca5a5; }
    .ss-breadcrumbs span, .ss-analyst-badge { color:#e8edf7; }
    [data-baseweb="select"] > div, [data-baseweb="input"] > div, [data-testid="stTextInput"] input { color:#e8edf7 !important; background:#121c2b !important; }
    .ss-status { color:#8be1bd; background:#102d27; border-color:#245a4c; }
    .ss-status--idle { color:#b7c0cf; background:#1a2636; border-color:#35445a; }
    .ss-empty { background:var(--panel); border-color:#40506a; }
    .ss-critical { background:#321c27; color:#ffb7be; }
    </style>
    """, unsafe_allow_html=True)


def chart_palette() -> dict[str, str]:
    if st.session_state.get("dark_theme", False):
        return {"background": "#121c2b", "text": "#e8edf7", "grid": "#2b3a50", "muted": "#a7b2c5"}
    return {"background": "#ffffff", "text": "#1c2434", "grid": "#e2e8f0", "muted": "#64748b"}


def render_bar_chart(values: pd.Series | pd.DataFrame, color: str = "#3c50e0") -> None:
    if isinstance(values, pd.Series):
        frame = values.rename(values.name or "Value").rename_axis("Category").reset_index()
    else:
        if values.empty or len(values.columns) != 1:
            st.info("No chart data available.")
            return
        frame = values.rename_axis("Category").reset_index()
    if frame.empty:
        st.info("No chart data available.")
        return
    category, value = frame.columns[0], frame.columns[-1]
    colors = chart_palette()
    chart = alt.Chart(frame).mark_bar(color=color, cornerRadiusTopLeft=3, cornerRadiusTopRight=3).encode(
        x=alt.X(f"{category}:N", title=None, sort=None, axis=alt.Axis(labelAngle=0, labelLimit=120)),
        y=alt.Y(f"{value}:Q", title=None),
        tooltip=[alt.Tooltip(f"{category}:N"), alt.Tooltip(f"{value}:Q", format=".2f")],
    ).properties(height=230).configure(background=colors["background"]).configure_view(strokeOpacity=0).configure_axis(
        labelColor=colors["muted"], titleColor=colors["text"], domainColor=colors["grid"], gridColor=colors["grid"], tickColor=colors["grid"]
    )
    st.altair_chart(chart, width="stretch", theme=None)


def render_line_chart(frame: pd.DataFrame, x_column: str, y_column: str, color: str = "#3c50e0") -> None:
    if frame.empty:
        st.info("No chart data available.")
        return
    colors = chart_palette()
    chart = alt.Chart(frame).mark_line(color=color, strokeWidth=2.5, point=alt.OverlayMarkDef(filled=True, size=28)).encode(
        x=alt.X(f"{x_column}:N", title=None, sort=None),
        y=alt.Y(f"{y_column}:Q", title=None),
        tooltip=[alt.Tooltip(f"{x_column}:N"), alt.Tooltip(f"{y_column}:Q", format=".2f")],
    ).properties(height=270).configure(background=colors["background"]).configure_view(strokeOpacity=0).configure_axis(
        labelColor=colors["muted"], titleColor=colors["text"], domainColor=colors["grid"], gridColor=colors["grid"], tickColor=colors["grid"]
    )
    st.altair_chart(chart, width="stretch", theme=None)


def engine() -> AdaptiveThresholdEngine:
    if "threshold_engine" not in st.session_state:
        st.session_state["threshold_engine"] = AdaptiveThresholdEngine(state_path=THRESHOLD_STATE_FILE)
    return st.session_state["threshold_engine"]


@st.cache_data(show_spinner=False)
def _cached_read_csv(path_str: str, mtime: float) -> pd.DataFrame:
    try:
        return pd.read_csv(path_str, on_bad_lines="skip")
    except Exception:
        try:
            return pd.read_csv(path_str, on_bad_lines="skip", engine="python")
        except Exception:
            return pd.DataFrame()


def read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    try:
        mtime = path.stat().st_mtime
        return _cached_read_csv(str(path), mtime).copy()
    except Exception:
        try:
            return pd.read_csv(path, on_bad_lines="skip")
        except Exception:
            return pd.DataFrame()


def number(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        return result if pd.notna(result) else default
    except (TypeError, ValueError, OverflowError):
        return default


def risk_series(df: pd.DataFrame) -> pd.Series:
    for column in ("Combined_Risk", "Risk_Score", "Threat_Score", "ML_Risk", "Risk", "risk"):
        if column in df.columns:
            return pd.to_numeric(df[column], errors="coerce").fillna(0).clip(0, 100)
    return pd.Series(0.0, index=df.index)


def classify(df: pd.DataFrame, thresholds: dict[str, float] | None = None) -> pd.DataFrame:
    if df.empty:
        return df.copy()
    cuts = thresholds or engine().get_thresholds()[0]
    out = df.copy()
    out["Combined_Risk"] = risk_series(out)
    score = out["Combined_Risk"]
    out["Threat_Level"] = "SAFE"
    out.loc[score >= cuts["medium"], "Threat_Level"] = "MEDIUM"
    out.loc[score >= cuts["high"], "Threat_Level"] = "HIGH"
    out.loc[score >= cuts["critical"], "Threat_Level"] = "CRITICAL"
    return out


def normalize_security(raw: Any) -> str:
    """Normalize raw security string to standard category: WPA2, WPA3, Open, WEP, etc."""
    if raw is None or pd.isna(raw):
        return "Unknown"
    text = str(raw).strip()
    if not text or text.lower() in ("unknown", "n/a", "none"):
        return "Unknown"
    upper = text.upper()
    if "WPA3" in upper:
        return "WPA3"
    if "WPA2" in upper or upper == "SECURED":
        return "WPA2"
    if "WEP" in upper:
        return "WEP"
    if upper in ("OPEN", "UNENCRYPTED", "UNSECURED") or "NO ENCRYPTION" in upper:
        return "Open"
    if "WPA" in upper:
        return "WPA"
    return text


def matches_security_filter(raw_security: Any, sec_filter: str) -> bool:
    """Match raw security value against selected dropdown category."""
    if not sec_filter or sec_filter == "All security types":
        return True
    norm = normalize_security(raw_security)
    raw_upper = str(raw_security or "").strip().upper()
    if sec_filter == "WPA2":
        return norm == "WPA2" or "WPA2" in raw_upper or raw_upper == "SECURED"
    if sec_filter == "WPA3":
        return norm == "WPA3" or "WPA3" in raw_upper
    if sec_filter == "Open":
        return norm == "Open" or raw_upper in ("OPEN", "NONE", "UNENCRYPTED", "UNSECURED") or "NO ENCRYPTION" in raw_upper
    if sec_filter == "WEP":
        return norm == "WEP" or "WEP" in raw_upper
    return norm.casefold() == sec_filter.casefold()


def normalise(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df.copy()
    out = df.copy()
    for old, new in (("Signal", "RSSI"), ("Risk_Score", "Combined_Risk"), ("Threat_Score", "Combined_Risk"), ("Risk", "Combined_Risk"), ("risk", "Combined_Risk"), ("Status", "Threat_Level"), ("Reason", "Reasons")):
        if old in out and new not in out:
            out[new] = out[old]
    if "SSID" not in out:
        out["SSID"] = "<Hidden Network>"
    else:
        out["SSID"] = out["SSID"].fillna("<Hidden Network>")
        out.loc[out["SSID"].astype(str).str.strip().isin(["", "nan", "None"]), "SSID"] = "<Hidden Network>"
    return out


def windows_scan_hint() -> str | None:
    if os.name != "nt":
        return None
    try:
        result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, timeout=8, check=False)
        output = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
    except (OSError, subprocess.TimeoutExpired):
        return None
    location = "location" in output and any(term in output for term in ("permission", "turn on", "services"))
    elevated = "requires elevation" in output or "error 5" in output
    if location or elevated:
        actions = []
        if location:
            actions.append("enable Windows Location services in Settings > Privacy & security > Location")
        if elevated:
            actions.append("restart VS Code/terminal as Administrator")
        return "Windows is blocking WLAN scans. Please " + " and ".join(actions) + ", then restart the dashboard."
    if "no wireless interfaces" in output:
        return "Windows reports no wireless adapter. Enable Wi-Fi and retry."
    return None


def scan_to_frame(findings: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for item in findings:
        signals = item.get("signals", []) or item.get("rssi_samples_dbm", []) or []
        reasons = item.get("reasons", []) or []
        temporal = item.get("temporal", {}) or {}
        scores = item.get("evidence_scores", {}) or {}
        ml = item.get("ml") or {}
        ssid_raw = str(item.get("ssid") or item.get("SSID") or "").strip()
        ssid_clean = ssid_raw if ssid_raw and ssid_raw.lower() not in ("nan", "none") else "<Hidden Network>"
        rows.append({
            "SSID": ssid_clean,
            "BSSID": item.get("bssid", item.get("BSSID", "N/A")),
            "RSSI": item.get("rssi_dbm", item.get("rssi", item.get("RSSI", signals[-1] if signals else "N/A"))),
            "Channel": item.get("channel", "N/A"),
            "Frequency": item.get("frequency_mhz", "N/A"),
            "Security": item.get("security", "Unknown"),
            "Vendor": item.get("vendor", "Unknown"),
            "Fingerprint_Similarity": item.get("fingerprint_similarity") if item.get("fingerprint_similarity") is not None else "N/A",
            "Fingerprint_Hash": item.get("fingerprint_hash", ""),
            "Fingerprint_Baseline_Exists": bool(item.get("fingerprint_baseline_exists", False)),
            "Fingerprint_Changed": bool(item.get("fingerprint_changed", False)),
            "Fingerprint_Change_Reasons": "; ".join(item.get("fingerprint_change_reasons", []) or []),
            "Temporal_Score": temporal.get("temporal_score", 0),
            "Density_Score": (item.get("density") or {}).get("score", 0),
            "Confidence": item.get("confidence", "UNKNOWN"),
            "RF_Prediction": item.get("RF_Prediction", ml.get("rf_fake_probability")),
            "KNN_Prediction": item.get("KNN_Prediction", ml.get("knn_fake_probability")),
            "Isolation_Forest": item.get("Isolation_Forest", ml.get("isolation_anomaly_score")),
            "Meta_Model": "Fake" if (ml.get("fake_probability") or 0) >= 0.5 else "Legit" if ml else "N/A",
            "Meta_Confidence": round(float(ml.get("fake_probability", 0)) * 100, 1) if ml else "N/A",
            "ML_Risk": item.get("ML_Risk", ml.get("risk_score")),
            "Combined_Risk": item.get("risk_score", item.get("risk", item.get("Combined_Risk", 0))),
            "Threat_Score": item.get("risk_score", item.get("risk", item.get("Combined_Risk", 0))),
            "Threat_Level": item.get("threat_level", item.get("Threat_Level", "LOW")),
            "AP_Count": item.get("ap_count", item.get("density", {}).get("ssid_bssid_count", 1)),
            "Signal_Fluctuation": item.get("signal_fluctuation", temporal.get("long_term_range", 0)),
            "Signal_History": ", ".join(map(str, signals)),
            "Signal_Variance": temporal.get("rssi_variance"),
            "Signal_StdDev": temporal.get("rssi_stddev"),
            "Signal_Delta": temporal.get("rssi_delta"),
            "Observation_Count": temporal.get("sample_count", len(signals)),
            "Adapter_ID": item.get("adapter_id", ",".join(item.get("adapter_ids", []))),
            "Adapter_Name": item.get("adapter_name", ""),
            "Scan_ID": item.get("scan_id", ""),
            "Scan_Duration_ms": item.get("scan_duration_ms", 0),
            "Detection_Latency_ms": item.get("detection_latency_ms", 0),
            "Evidence_JSON": json.dumps(scores, ensure_ascii=False),
            "Context_JSON": json.dumps(item.get("context") or {}, ensure_ascii=False),
            "Reasons": "; ".join(map(str, reasons)) or item.get("detection_reason", "No major anomaly"),
            "Model_Explanation": (ml.get("explanation") or {}).get("summary") if ml else None,
            "Model_Effects_JSON": json.dumps((ml.get("explanation") or {}).get("effects", []), ensure_ascii=False) if ml and ml.get("explanation") else "",
            "Scan_Time": item.get("timestamp", now),
            "RAIM_Flagged": item.get("RAIM_Flagged", False),
            "RAIM_Distance_m": item.get("RAIM_Distance_m"),
            "RAIM_Score": item.get("RAIM_Score"),
            "Layer2_Deauth_Detected": item.get("Layer2_Deauth_Detected", False),
            "Layer2_Score": (item.get("layer2") or {}).get("score"),
            "Layer2_Reasons": "; ".join((item.get("layer2") or {}).get("reasons", [])),
            "Cloud_Risk": item.get("Cloud_Risk"),
            "Cloud_Reputation_Hit": item.get("Cloud_Reputation_Hit", False),
            "Cloud_Threat_Type": item.get("Cloud_Threat_Type"),
            "BSSID_Reputation": "Hit" if item.get("Cloud_Reputation_Hit") else "Clean",
            "Cloud_Risk_Score": item.get("Cloud_Risk"),
        })
    return pd.DataFrame(rows)


def get_scan_controller() -> ScanController:
    controller = st.session_state.get("scan_controller")
    if controller is None:
        controller = ScanController()
        st.session_state["scan_controller"] = controller
    return controller


ALERT_FIELDS = ["Time", "SSID", "BSSID", "Risk", "Level", "Reason"]


def _ensure_alert_header() -> None:
    if not ALERT_FILE.exists() or ALERT_FILE.stat().st_size == 0:
        with ALERT_FILE.open("w", newline="", encoding="utf-8") as handle:
            csv.writer(handle).writerow(ALERT_FIELDS)
        return
    with ALERT_FILE.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames == ALERT_FIELDS:
            return
        rows = list(reader)
    temp = ALERT_FILE.with_suffix(".tmp")
    with temp.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ALERT_FIELDS, extrasaction="ignore", restval="")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) or "" for key in ALERT_FIELDS})
    temp.replace(ALERT_FILE)


def persist_alert(alert: dict[str, Any]) -> None:
    st.session_state["alerts"].insert(0, alert)
    try:
        _ensure_alert_header()
        with ALERT_FILE.open("a", newline="", encoding="utf-8") as handle:
            csv.DictWriter(handle, fieldnames=ALERT_FIELDS, extrasaction="ignore", restval="").writerow(alert)
    except OSError as exc:
        st.warning(f"Could not save alert history: {exc}")


def get_notifier():
    if NotificationManager is None:
        return None
    notifier = st.session_state.get("notifier")
    if notifier is None:
        notifier = NotificationManager()
        st.session_state["notifier"] = notifier
    return notifier


def notify(alert: dict[str, Any]) -> dict[str, Any]:
    status: dict[str, Any] = {"toast": False, "desktop": False, "email": False, "telegram": False, "sms": False, "suppressed": False, "error": ""}
    risk = number(alert.get("Risk"))
    if hasattr(st, "toast"):
        try:
            st.toast(f"**{alert.get('Level', 'ALERT')}** · `{alert.get('SSID', 'Unknown')}` · {risk:.0f}%\n\n{str(alert.get('Reason', ''))[:150]}", icon="🚨")
            status["toast"] = True
        except Exception as exc:
            status["error"] = f"In-app popup failed: {exc}"
    if st.session_state.get("sound_enabled") and os.name == "nt":
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass
    notifier = get_notifier()
    if notifier is None:
        status["error"] = status["error"] or "notification_manager could not be imported."
    else:
        try:
            status.update(notifier.notify_threat(
                alert.get("SSID", "Unknown"), alert.get("BSSID", "Unknown"), risk, alert.get("Reason", ""),
                force=alert.get("Level") == "TEST", desktop=bool(st.session_state.get("desktop_enabled")),
            ))
            if st.session_state.get("desktop_enabled") and not status["desktop"] and not status["suppressed"]:
                status["error"] = notifier.last_error or "Desktop popup was not accepted by the operating system."
        except Exception as exc:
            status["error"] = f"Notification dispatch failed: {exc}"
    st.session_state["last_notification"] = status
    return status


def describe_notification(status: dict[str, Any]) -> None:
    def mark(ok: bool) -> str:
        return "sent" if ok else "not sent"
    st.caption(
        f"In-app popup: {mark(status.get('toast', False))} · Desktop popup: "
        f"{'off in Settings' if not st.session_state.get('desktop_enabled') else 'held by cooldown' if status.get('suppressed') else mark(status.get('desktop', False))} · "
        f"Email: {mark(status.get('email', False))} · Telegram: {mark(status.get('telegram', False))} · SMS: {mark(status.get('sms', False))} "
        "(email, Telegram and SMS stay off until their environment variables are set)"
    )
    if status.get("error"):
        st.warning(f"Desktop popup problem: {status['error']}")


def process_alerts(df: pd.DataFrame) -> None:
    if df.empty or not st.session_state.get("critical_alerts_enabled", True):
        return
    alert_levels = {"CRITICAL"} | ({"HIGH"} if st.session_state.get("alert_on_high", True) else set())
    for _, row in df.iterrows():
        risk = number(row.get("Combined_Risk"))
        ssid, bssid = str(row.get("SSID", "Unknown")), str(row.get("BSSID", "Unknown"))
        original_level = str(row.get("Threat_Level", "SAFE")).upper()
        assessment = evaluate_novelty(row.to_dict()) if evaluate_novelty else None
        novelty_triggered = bool(assessment and assessment.should_alert)
        level = original_level
        if novelty_triggered and assessment.level in {"HIGH", "CRITICAL"}:
            level = "CRITICAL" if "CRITICAL" in {original_level, assessment.level} else "HIGH"
        if level not in alert_levels:
            continue

        has_attack = bool(
            row.get("Layer2_Deauth_Detected")
            or row.get("Cloud_Reputation_Hit")
            or (assessment and any(t in {"layer2_attack", "cloud_reputation"} for t in assessment.strong_evidence))
        )
        if risk < 35.0 and not has_attack:
            continue

        key = (ssid, bssid, level)
        if key in st.session_state["alert_keys"]:
            continue

        reasons = str(row.get("Reasons", "Adaptive risk threshold exceeded"))
        if assessment and assessment.evidence:
            reasons = (reasons + " | Novelty evidence: " + "; ".join(assessment.evidence)).strip(" |")
        alert = {
            "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "SSID": ssid,
            "BSSID": bssid,
            "Risk": round(risk, 1),
            "Level": level,
            "Reason": reasons,
        }
        outcome = notify(alert)
        if not outcome.get("suppressed"):
            st.session_state["alert_keys"].add(key)
            persist_alert(alert)


def adaptive_scan_update(df: pd.DataFrame) -> pd.DataFrame:
    learner = engine()
    rssi = pd.to_numeric(df["RSSI"].astype(str).str.replace(" dBm", ""), errors="coerce").tolist() if "RSSI" in df.columns else []
    crowd = scan_crowding(len(df), rssi)
    cuts, mode = learner.get_thresholds(ap_count=crowd["ap_count"], interference=crowd["interference"])
    result = classify(df, cuts)
    learner.update(risk_series(result).tolist(), ap_count=crowd["ap_count"], interference=crowd["interference"])
    st.session_state["last_scan_thresholds"] = {"thresholds": cuts, "mode": mode, "crowding": crowd}
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Presentation Layer Helpers (Exact Header, Breadcrumbs, Table & Pill Badges)
# ─────────────────────────────────────────────────────────────────────────────
def render_topbar_and_header(
    section_name: str,
    page_title: str,
    subtitle: str,
    status_text: str | None = None,
    is_demo: bool = True,
) -> None:
    """Render the top breadcrumb rail, preview alert banner, and TailAdmin header."""
    badge_text = status_text or ("SYSTEM ONLINE · DEMO VIEW" if is_demo else "SYSTEM ONLINE")
    status_class = "ss-badge-demo" if is_demo else "ss-status"

    st.markdown(
        f"""
        <div class="ss-topbar">
            <div class="ss-breadcrumbs">Security Operations / <span>{html_lib.escape(section_name)}</span></div>
            <div class="ss-analyst-badge">Analyst Workspace <span class="ss-dot-green">●</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if is_demo:
        st.markdown(
            """
            <div class="ss-preview-banner">
                PREVIEW ONLY · Illustrative sample values, not captured from a live scan or a running Streamlit session.
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown(
        f"""
        <div class="ss-header">
            <div>
                <div class="ss-eyebrow">WIRELESS SECURITY ANALYTICS</div>
                <div class="ss-title">{html_lib.escape(page_title)}</div>
                <div class="ss-subtitle">{html_lib.escape(subtitle)}</div>
            </div>
            <div class="{status_class}">{html_lib.escape(badge_text)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_html_table(
    df: pd.DataFrame,
    columns: list[str] | None = None,
    custom_headers: dict[str, str] | None = None,
) -> None:
    """Render pixel-perfect HTML tables matching the PDF mockups with styled pills."""
    if df.empty:
        st.markdown('<div class="ss-empty">No data available yet.</div>', unsafe_allow_html=True)
        return
    visible = [col for col in (columns or list(df.columns)) if col in df.columns]
    display = df[visible].copy()
    header_dict = custom_headers or {}

    html_parts = ['<div class="ss-table-container"><table class="ss-table"><thead><tr>']
    for col in visible:
        label = header_dict.get(col, col.upper().replace("_", " "))
        html_parts.append(f"<th>{html_lib.escape(label)}</th>")
    html_parts.append("</tr></thead><tbody>")

    for _, row in display.iterrows():
        html_parts.append("<tr>")
        for col in visible:
            val = row.get(col, "")
            val_str = "" if pd.isna(val) or val is None else str(val)

            col_lower = col.lower()
            if col_lower in ("threat_level", "threat level", "level"):
                lvl = val_str.upper()
                if "SAFE" in lvl:
                    cell_html = '<span class="badge-safe">SAFE</span>'
                elif "MEDIUM" in lvl:
                    cell_html = '<span class="badge-medium">MEDIUM</span>'
                elif "HIGH" in lvl:
                    cell_html = '<span class="badge-high">HIGH</span>'
                elif "CRITICAL" in lvl:
                    cell_html = '<span class="badge-critical">CRITICAL</span>'
                elif "TEST" in lvl:
                    cell_html = '<span class="badge-medium">TEST</span>'
                else:
                    cell_html = f'<span class="badge-pill-gray">{html_lib.escape(val_str)}</span>'
                html_parts.append(f"<td>{cell_html}</td>")
            elif col_lower in ("trust_state", "trust state"):
                t = val_str.upper()
                if "TRUSTED" in t or t == "TRUE":
                    cell_html = '<span class="badge-trusted">TRUSTED</span>'
                else:
                    cell_html = '<span class="badge-observed">OBSERVED</span>'
                html_parts.append(f"<td>{cell_html}</td>")
            elif col_lower in ("rf_prediction", "rf output", "knn_prediction", "knn output", "isolation_forest", "if output"):
                out = val_str
                if any(x in out for x in ("Fake", "Anomaly")):
                    cell_html = f'<span class="badge-critical">{html_lib.escape(out)}</span>'
                elif "Uncertain" in out:
                    cell_html = f'<span class="badge-medium">{html_lib.escape(out)}</span>'
                elif "Normal" in out or "Legitimate" in out:
                    cell_html = f'<span class="badge-safe">{html_lib.escape(out)}</span>'
                else:
                    cell_html = f'<span class="badge-pill-gray">{html_lib.escape(out)}</span>'
                html_parts.append(f"<td>{cell_html}</td>")
            elif col_lower in ("risk", "combined_risk"):
                try:
                    num_val = float(val)
                    html_parts.append(f"<td><strong>{num_val:.0f}</strong></td>")
                except (ValueError, TypeError):
                    html_parts.append(f"<td><strong>{html_lib.escape(val_str)}</strong></td>")
            elif col_lower == "rssi":
                if not val_str.endswith("dBm") and val_str not in ("N/A", "—", ""):
                    html_parts.append(f"<td>{html_lib.escape(val_str)} dBm</td>")
                else:
                    html_parts.append(f"<td>{html_lib.escape(val_str)}</td>")
            else:
                html_parts.append(f"<td>{html_lib.escape(val_str)}</td>")
        html_parts.append("</tr>")
    html_parts.append("</tbody></table></div>")
    st.markdown("".join(html_parts), unsafe_allow_html=True)


def render_footer() -> None:
    st.markdown(
        """
        <div class="ss-footer">
            SentinelShield · Wi-Fi Threat Detection | UI preview generated from project dashboard structure
        </div>
        """,
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 01. Overview Page (Matches PDF Page 1)
# ─────────────────────────────────────────────────────────────────────────────
def page_home(df: pd.DataFrame, is_demo: bool = True) -> None:
    render_topbar_and_header(
        "Overview",
        "Overview",
        "Overview of network observations, risk classification, and investigation priorities.",
        is_demo=is_demo,
    )

    levels = df.get("Threat_Level", pd.Series(index=df.index, dtype=str)).astype(str).str.upper()
    safe = int(levels.eq("SAFE").sum())
    medium = int(levels.eq("MEDIUM").sum())
    high = int(levels.eq("HIGH").sum())
    critical = int(levels.eq("CRITICAL").sum())
    suspicious = medium + high + critical
    total = len(df)
    safe_pct = f"{int(round((safe / total) * 100))}% of sessions" if total > 0 else "0% of sessions"

    st.markdown("### Current posture")
    st.markdown(
        f"""
        <div class="ss-metric-grid-4">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Networks detected</div>
                <div class="ss-metric-value">{total}</div>
                <div class="ss-metric-subtext">Saved scan records</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Safe networks</div>
                <div class="ss-metric-value">{safe}</div>
                <div class="ss-metric-subtext">{safe_pct}</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Suspicious</div>
                <div class="ss-metric-value">{suspicious}</div>
                <div class="ss-metric-subtext">Medium to severe</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Critical threats</div>
                <div class="ss-metric-value">{critical}</div>
                <div class="ss-metric-subtext">Illustrative only</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    left, right = st.columns(2, gap="medium")
    with left.container(border=True):
        c_title, c_pill = st.columns([3, 1])
        c_title.markdown("#### Threat distribution")
        c_pill.markdown('<div style="text-align:right;"><span class="badge-pill-gray">CURRENT SCAN</span></div>', unsafe_allow_html=True)
        st.caption("Sample findings grouped by configured threat level.")
        render_bar_chart(pd.Series({"SAFE": safe, "MEDIUM": medium, "HIGH": high, "CRITICAL": critical}), color="#3c50e0")

    with right.container(border=True):
        r_title, r_pill = st.columns([3, 1])
        r_title.markdown("#### Risk distribution")
        r_pill.markdown('<div style="text-align:right;"><span class="badge-pill-gray">0-100 SCORE</span></div>', unsafe_allow_html=True)
        st.caption("Illustrative risk-score bands.")
        risk = risk_series(df)
        if df.empty:
            st.markdown('<div class="ss-empty">No scan data available.</div>', unsafe_allow_html=True)
        else:
            bands = pd.cut(risk, [-1, 24, 49, 74, 100], labels=["0–24", "25–49", "50–74", "75–100"])
            counts = bands.value_counts().reindex(["0–24", "25–49", "50–74", "75–100"], fill_value=0)
            render_bar_chart(counts, color="#10b981")

    st.markdown("### Investigation queue")
    st.caption("Networks ranked from the sample risk score. A high score is an investigation signal, not attribution.")
    ranked = df.sort_values("Combined_Risk", ascending=False) if "Combined_Risk" in df.columns else df
    render_html_table(
        ranked,
        ["SSID", "BSSID", "RSSI", "Channel", "Security", "Combined_Risk", "Threat_Level", "Reasons"],
        {"Combined_Risk": "RISK", "Threat_Level": "THREAT LEVEL", "Reasons": "REASONS"},
    )

    st.markdown("### Scanner status")
    st.markdown(
        """
        <div class="ss-metric-grid-4">
            <div class="ss-metric-card">
                <div class="ss-metric-label">State</div>
                <div class="ss-metric-value" style="font-size:1.3rem;">IDLE</div>
                <div class="ss-metric-subtext">No scan currently running</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Radio mode</div>
                <div class="ss-metric-value" style="font-size:1.3rem;">Local</div>
                <div class="ss-metric-subtext">Illustrative</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Adapters</div>
                <div class="ss-metric-value">1</div>
                <div class="ss-metric-subtext">Sample config</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Adaptive baseline</div>
                <div class="ss-metric-value" style="font-size:1.3rem;">Warm-up</div>
                <div class="ss-metric-subtext">8 warm-up display</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    render_footer()


# ─────────────────────────────────────────────────────────────────────────────
# 02. Live Scan Page (Matches PDF Page 2)
# ─────────────────────────────────────────────────────────────────────────────
def page_live_scan(df: pd.DataFrame, is_demo: bool = True) -> None:
    render_topbar_and_header(
        "Live Scan",
        "Live Scan",
        "Discover nearby networks, verify selected observations, and inspect the current scan output.",
        is_demo=is_demo,
    )

    controller = get_scan_controller()
    status = controller.status()

    st.markdown("### Scan controls")
    profiles = {
        "Quick Scan + adaptive verification (recommended)": "auto",
        "Quick discovery only": "fast",
        "Balanced discovery": "balanced",
        "Deep verification": "deep",
    }
    profile = st.selectbox("Scan profile", list(profiles), index=0, label_visibility="collapsed")
    mode = profiles[profile]

    state = str(status.get("status", "idle"))
    stages = [("1", "Discover", state in {"queued", "scanning"}), ("2", "Verify", state == "deep-verification"), ("3", "Analyze", state == "analyzing")]
    stages_html = "".join(f'<div class="ss-scan-stage {"is-active" if active else ""}"><span>{num}</span>{name}</div>' for num, name, active in stages)
    st.markdown(
        f'<div class="ss-scan-flow">{stages_html}<div class="ss-scan-note">{status.get("preliminary_aps", 0)} preliminary APs illustrative state</div></div>',
        unsafe_allow_html=True,
    )

    continuous_before = controller.continuous_status()
    a, b, c, d = st.columns(4)
    start = a.button("▶ Run selected scan", type="primary", disabled=status.get("status") in {"queued", "scanning", "deep-verification", "analyzing", "stopping"} or bool(continuous_before.get("enabled")), width="stretch")
    stop = b.button("■ Stop scan", disabled=status.get("status") not in {"queued", "scanning", "deep-verification", "analyzing", "stopping"} and not bool(continuous_before.get("enabled")), width="stretch")
    load_saved = c.button("📂 Load Saved Scan", width="stretch")
    clear = d.button("🧹 Clear Display", width="stretch")

    if start:
        hint = windows_scan_hint()
        if hint:
            st.error(hint)
        elif not controller.start(mode):
            st.warning("A scan is already running.")
        else:
            st.session_state["scan_mode"] = mode
            set_demo_mode(False)
            st.rerun()
    if stop:
        stopped = controller.stop_continuous() if controller.continuous_status().get("enabled") else controller.stop()
        if stopped:
            st.info("Stop requested. Future continuous scans are disabled.")

    continuous = controller.continuous_status()
    with st.container(border=True):
        st.markdown("#### Continuous scanning")
        st.caption("Runs the selected scan profile repeatedly. The interval is a target between scan starts; scans are never overlapped, so a slow scan can push the next start later.")
        interval_col, start_col, stop_col = st.columns([1.2, 1, 1])
        interval_seconds = interval_col.number_input("Target interval (seconds)", min_value=1, max_value=3600, value=int(continuous.get("interval_seconds", 5)), step=1, key="continuous_scan_interval")
        continuous_start = start_col.button("▶ Start Continuous Scan", type="primary", disabled=bool(continuous.get("enabled")), width="stretch")
        continuous_stop = stop_col.button("■ Stop Continuous Scan", disabled=not bool(continuous.get("enabled")), width="stretch")

        if continuous_start:
            hint = windows_scan_hint()
            if hint:
                st.error(hint)
            elif controller.start_continuous(mode, interval_seconds=float(interval_seconds)):
                st.session_state["scan_mode"] = mode
                set_demo_mode(False)
                st.success(f"Continuous scanning started with a {int(interval_seconds)}-second target interval.")
                st.rerun()
            else:
                st.warning("Continuous scanning is already running.")
        if continuous_stop and controller.stop_continuous():
            st.info("Continuous scanning stopped.")

        continuous = controller.continuous_status()
        st.caption(f"Continuous mode: {'RUNNING' if continuous.get('enabled') else 'STOPPED'} completed cycles: {continuous.get('scan_count', 0)} · last start: {continuous.get('last_scan_started_at') or '—'} · last finish: {continuous.get('last_scan_finished_at') or '—'}")

    if load_saved:
        st.session_state["scan"] = classify(normalise(read_csv(SCAN_FILE)))
        set_demo_mode(False)
        st.success("Saved scan loaded.")
        st.rerun()
    if clear:
        st.session_state["scan"] = pd.DataFrame()
        st.success("Displayed results cleared.")

    # ── Live Scanner Status & Reactive Poll ──────────────────────────────────
    status = controller.status()
    running = status.get("status") in {"queued", "scanning", "deep-verification", "analyzing", "stopping"}
    continuous_active = bool(controller.continuous_status().get("enabled"))

    if (running or continuous_active) and st_autorefresh is not None:
        st_autorefresh(interval=700, key="scan_controller_poll")

    scanner_state_label = str(status.get("status", "idle")).replace("-", " ").upper()
    adapter_mode_label = status.get("adapter_mode", "local adapter")
    st.status(
        f"Scanner: {scanner_state_label} · {adapter_mode_label} · mode {status.get('mode', mode)}",
        state="running" if running else "complete" if status.get("status") == "completed" else "error" if status.get("status") == "error" else "complete",
        expanded=running,
    )
    if status.get("error"):
        st.error(status["error"])
    for error_msg in status.get("errors", []):
        st.warning(error_msg)

    # ── Collect Finished Scan Results ────────────────────────────────────────
    if status.get("status") == "completed" and status.get("scan_id") != st.session_state.get("processed_controller_scan_id"):
        result = controller.latest()
        if result:
            found = scan_to_frame(result.get("results", []))
            if not found.empty:
                found["Scan_ID"] = result["scan_id"]
                found["Adapter_Mode"] = result["adapter_mode"]
                found["Adapter_Count"] = result["adapter_count"]
                found["Scan_Duration_ms"] = result["scan_duration_ms"]
                found["Detection_Latency_ms"] = result["detection_latency_ms"]
                found = adaptive_scan_update(found)
                found.to_csv(SCAN_FILE, index=False)
                st.session_state["scan"] = found
                set_demo_mode(False)
                st.session_state["processed_controller_scan_id"] = result["scan_id"]
                st.session_state["last_scan"] = result["completed_at"]
                process_alerts(found)
                st.success(f"Scan completed — {len(found)} AP(s) discovered, {result['scan_duration_ms']:.0f} ms scan time, {result['detection_latency_ms']:.0f} ms detection latency.")
                st.rerun()
    elif status.get("status") == "empty":
        st.warning("No AP observations were returned. Check wireless adapter state or enable Location services in Windows Settings.")

    st.markdown("### Current scan observations")
    if is_demo:
        st.caption("Sample table shown only to illustrate the page layout. The screenshot is not from an actual adapter scan.")
    else:
        st.caption(f"Live observations from active wireless adapter. Found {len(df)} network(s).")
    render_html_table(
        df,
        ["SSID", "BSSID", "RSSI", "Channel", "Security", "Vendor", "Combined_Risk", "Threat_Level"],
        {"Combined_Risk": "RISK", "Threat_Level": "THREAT LEVEL"},
    )
    render_footer()


# ─────────────────────────────────────────────────────────────────────────────
# 03. Networks Page (Matches PDF Page 3)
# ─────────────────────────────────────────────────────────────────────────────
def page_networks(df: pd.DataFrame, is_demo: bool = True) -> None:
    render_topbar_and_header(
        "Networks",
        "Networks",
        "Inspect current access point observations and open fingerprint analysis for selected networks.",
        is_demo=is_demo,
    )

    current_tab, fingerprint_tab = st.tabs(["Current scan", "Fingerprint analysis"])

    with current_tab:
        f1, f2, f3 = st.columns([2.5, 1.2, 1.2])
        search_query = f1.text_input("Search", placeholder="Search SSID, BSSID, vendor or reasons", label_visibility="collapsed")
        threat_filter = f2.selectbox("Threat filter", ["All threat levels", "SAFE", "MEDIUM", "HIGH", "CRITICAL"], label_visibility="collapsed")
        sec_filter = f3.selectbox("Security filter", ["All security types", "WPA2", "WPA3", "Open", "WEP"], label_visibility="collapsed")

        view = df.copy()
        if not view.empty:
            if "Security_Category" not in view.columns and "Security" in view.columns:
                view["Security_Category"] = view["Security"].apply(normalize_security)
            if search_query:
                mask = view.astype(str).apply(lambda col: col.str.contains(search_query, case=False, regex=False)).any(axis=1)
                view = view[mask]
            if threat_filter != "All threat levels":
                view = view[view["Threat_Level"].astype(str).str.upper() == threat_filter]
            if sec_filter != "All security types":
                view = view[view["Security"].apply(lambda s: matches_security_filter(s, sec_filter))]

        st.markdown("#### Detected access points")
        if is_demo:
            st.caption("Sample observations with network identifiers and risk classifications.")
        else:
            st.caption(f"Showing {len(view)} of {len(df)} detected access point(s).")

        render_html_table(
            view,
            ["SSID", "BSSID", "RSSI", "Channel", "Frequency", "Security", "Vendor", "Combined_Risk", "Threat_Level"],
            {"Combined_Risk": "RISK", "Threat_Level": "THREAT LEVEL"},
        )

        if not view.empty and "BSSID" in view.columns:
            b_list = [b for b in view["BSSID"].dropna().unique().tolist() if str(b).strip() and str(b) != "N/A"]
            if b_list:
                curr_sel = st.session_state.get("selected_bssid")
                s_idx = b_list.index(curr_sel) if curr_sel in b_list else 0
                chosen = st.selectbox(
                    "Select access point for in-depth threat analysis",
                    b_list,
                    index=s_idx,
                    format_func=lambda b: f"{view[view['BSSID'] == b]['SSID'].iloc[0]} ({b}) — Risk: {number(view[view['BSSID'] == b]['Combined_Risk'].iloc[0]):.0f}% [{view[view['BSSID'] == b]['Threat_Level'].iloc[0]}]",
                    key="networks_bssid_selector",
                )
                st.session_state["selected_bssid"] = chosen

        st.markdown(
            """
            <div class="ss-info-callout">
                Fingerprint differences and unfamiliar BSSIDs are indicators for review, neither alone confirms an Evil Twin attack.
            </div>
            """,
            unsafe_allow_html=True,
        )

    with fingerprint_tab:
        page_fingerprints(df, is_demo=is_demo, render_headers=False)

    render_footer()


# ─────────────────────────────────────────────────────────────────────────────
# 04. Threat Analysis Page (Matches PDF Page 4)
# ─────────────────────────────────────────────────────────────────────────────
def page_threat_analysis(df: pd.DataFrame, is_demo: bool = True) -> None:
    render_topbar_and_header(
        "Threat Analysis",
        "Threat Analysis",
        "Review risk scores, evidence signals, and explanations associated with suspicious access points.",
        is_demo=is_demo,
    )

    if df.empty:
        st.markdown(
            """
            <div class="ss-info-callout" style="margin-top: 1rem; margin-bottom: 2rem;">
                <strong>No scan data is available.</strong> Start a Wi-Fi scan to analyze detected access points.
            </div>
            """,
            unsafe_allow_html=True,
        )
        render_footer()
        return

    unique_bssids = [b for b in df["BSSID"].dropna().unique().tolist() if str(b).strip() and str(b) != "N/A"]
    total_observations = len(df)
    unique_ap_count = len(unique_bssids)
    levels = df.get("Threat_Level", pd.Series(index=df.index, dtype=str)).astype(str).str.upper()
    low_count = int(levels.isin(["SAFE", "LOW"]).sum())
    med_count = int(levels.eq("MEDIUM").sum())
    high_count = int(levels.eq("HIGH").sum())
    crit_count = int(levels.eq("CRITICAL").sum())
    latest_scan_time = st.session_state.get("last_scan")
    if not latest_scan_time and "Scan_Time" in df.columns and not df["Scan_Time"].dropna().empty:
        latest_scan_time = str(df["Scan_Time"].dropna().iloc[0])
    if not latest_scan_time:
        latest_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    st.markdown(
        f"""
        <div class="ss-metric-grid-4">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Findings analyzed</div>
                <div class="ss-metric-value">{total_observations}</div>
                <div class="ss-metric-subtext">{unique_ap_count} Unique Access Points</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Low / Safe</div>
                <div class="ss-metric-value">{low_count}</div>
                <div class="ss-metric-subtext">Baseline consistent</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Medium risk</div>
                <div class="ss-metric-value">{med_count}</div>
                <div class="ss-metric-subtext">Review indicators</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">High / Critical</div>
                <div class="ss-metric-value">{high_count + crit_count}</div>
                <div class="ss-metric-subtext">{crit_count} Critical, {high_count} High</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Risk & evidence review")

    default_idx = 0
    curr_sel = st.session_state.get("selected_bssid")
    if curr_sel in unique_bssids:
        default_idx = unique_bssids.index(curr_sel)
    else:
        if "Combined_Risk" in df.columns and not df.empty:
            top_row = df.sort_values("Combined_Risk", ascending=False).iloc[0]
            top_b = top_row.get("BSSID")
            if top_b in unique_bssids:
                default_idx = unique_bssids.index(top_b)

    selected_bssid = st.selectbox(
        "Select Access Point to Inspect",
        unique_bssids,
        index=default_idx,
        format_func=lambda b: f"{df[df['BSSID'] == b]['SSID'].iloc[0]} ({b}) — Risk: {number(df[df['BSSID'] == b]['Combined_Risk'].iloc[0]):.0f}% [{df[df['BSSID'] == b]['Threat_Level'].iloc[0]}]",
        key="threat_analysis_bssid_select",
    )
    st.session_state["selected_bssid"] = selected_bssid
    selected_row = df[df["BSSID"] == selected_bssid].iloc[0]

    store = WiFiFingerprintStore()
    baseline = store.get(selected_bssid)
    ssid = str(selected_row.get("SSID", "<Hidden Network>"))
    bssid = str(selected_row.get("BSSID", "N/A"))
    rssi_val = number(selected_row.get("RSSI"))
    channel_val = selected_row.get("Channel")
    freq_val = selected_row.get("Frequency", "N/A")
    sec_raw = selected_row.get("Security", "Unknown")
    sec_norm = normalize_security(sec_raw)
    combined_risk = number(selected_row.get("Combined_Risk", 0))
    threat_level = str(selected_row.get("Threat_Level", "SAFE")).upper()

    # 1. Fingerprint mismatch
    fp_available = False
    fp_mismatch_pct = 0.0
    fp_explanation = ""
    if baseline:
        fp_available = True
        mean_rssi = baseline.get("rssi_mean")
        sim = selected_row.get("Fingerprint_Similarity")
        if sim is not None and sim != "N/A" and not pd.isna(sim):
            try:
                fp_mismatch_pct = max(0.0, min(100.0, 100.0 - float(sim)))
            except (ValueError, TypeError):
                fp_mismatch_pct = 0.0
        elif mean_rssi is not None and rssi_val != 0:
            var = float(baseline.get("rssi_variance") or 9.0)
            dev = abs(rssi_val - float(mean_rssi))
            fp_mismatch_pct = min(100.0, (dev / max(10.0, (var ** 0.5) * 2.0)) * 100.0)
        else:
            fp_mismatch_pct = 0.0
        fp_explanation = f"Baseline mean: {mean_rssi:.1f} dBm, variance: {baseline.get('rssi_variance', 0):.1f} ({baseline.get('observation_count', 0)} obs)." if mean_rssi else "Stored baseline exists for this BSSID."
    else:
        candidates = store.candidates_for_ssid(ssid)
        if candidates and ssid not in ("<Hidden Network>", "Unknown", ""):
            fp_available = True
            fp_mismatch_pct = 75.0
            fp_explanation = f"Known SSID '{ssid}' observed under unverified BSSID {bssid} ({len(candidates)} other BSSID(s) known)."
        else:
            fp_available = False
            fp_mismatch_pct = 0.0
            fp_explanation = "Fingerprint comparison unavailable: no trusted baseline exists."

    # 2. Security mismatch
    sec_available = True
    sec_mismatch_pct = 0.0
    sec_explanation = ""
    if baseline and baseline.get("security_history"):
        known_sec = [normalize_security(s) for s in baseline["security_history"]]
        if sec_norm not in known_sec and "Unknown" not in known_sec:
            sec_mismatch_pct = 100.0
            sec_explanation = f"Security changed from baseline ({', '.join(baseline['security_history'])}) to {sec_raw}."
        else:
            sec_mismatch_pct = 0.0
            sec_explanation = f"Security configuration ({sec_norm}) matches stored baseline."
    else:
        if sec_norm == "Open":
            sec_mismatch_pct = 50.0
            sec_explanation = "Unencrypted open network; no baseline recorded."
        elif sec_norm in ("WEP", "WPA"):
            sec_mismatch_pct = 40.0
            sec_explanation = f"Legacy or weak encryption ({sec_norm}); no baseline recorded."
        else:
            sec_mismatch_pct = 0.0
            sec_explanation = f"Encrypted network ({sec_norm}); baseline comparison unavailable."

    # 3. Temporal RSSI change
    fluct = number(selected_row.get("Signal_Fluctuation", 0))
    var = number(selected_row.get("Signal_Variance", 0))
    temp_score = number(selected_row.get("Temporal_Score", 0))
    obs_count = int(number(selected_row.get("Observation_Count", 1)))
    temp_available = (fluct > 0 or var > 0 or obs_count > 1 or temp_score > 0)
    temp_pct = 0.0
    temp_explanation = ""
    if temp_available:
        temp_pct = min(100.0, max(temp_score, (fluct / 25.0) * 100.0, (var / 40.0) * 100.0))
        temp_explanation = f"Signal fluctuation: {fluct:.1f} dB (variance: {var:.2f}) over {obs_count} observation(s)."
    else:
        temp_pct = 0.0
        temp_explanation = "Temporal RSSI analysis unavailable: single observation snapshot."

    # 4. AP density indicator
    same_ssid_count = len(df[df["SSID"] == ssid]["BSSID"].unique()) if ssid and ssid not in ("<Hidden Network>", "") else 1
    channel_count = len(df[df["Channel"] == channel_val]) if channel_val and channel_val != "N/A" else 1
    density_available = True
    density_pct = 0.0
    density_explanation = ""
    if same_ssid_count > 1:
        density_pct = min(100.0, 30.0 + (same_ssid_count - 1) * 25.0)
        density_explanation = f"{same_ssid_count} distinct BSSIDs observed broadcasting SSID '{ssid}' (Potential Rogue/Evil Twin)."
    else:
        density_pct = min(100.0, (channel_count / 12.0) * 50.0)
        density_explanation = f"{channel_count} AP(s) active on Channel {channel_val}."

    # 5. ML model evidence
    ml_conf_val = selected_row.get("Meta_Confidence")
    ml_risk_val = selected_row.get("ML_Risk")
    ml_available = False
    ml_pct = 0.0
    ml_explanation = ""
    if ml_conf_val is not None and ml_conf_val != "N/A" and not pd.isna(ml_conf_val):
        try:
            ml_available = True
            ml_pct = min(100.0, max(0.0, float(ml_conf_val)))
            rf = selected_row.get("RF_Prediction", "N/A")
            knn = selected_row.get("KNN_Prediction", "N/A")
            iso = selected_row.get("Isolation_Forest", "N/A")
            ml_explanation = f"RF: {rf} | KNN: {knn} | IF: {iso} | Meta-confidence: {ml_pct:.1f}%."
        except (ValueError, TypeError):
            ml_available = False
    elif ml_risk_val is not None and ml_risk_val != "N/A" and not pd.isna(ml_risk_val):
        try:
            ml_available = True
            ml_pct = min(100.0, max(0.0, float(ml_risk_val)))
            ml_explanation = f"ML Ensemble Risk Score: {ml_pct:.1f}%."
        except (ValueError, TypeError):
            ml_available = False
    else:
        ml_available = False
        ml_pct = 0.0
        ml_explanation = "ML model evidence unavailable: models not evaluated on this observation."

    left, right = st.columns(2, gap="medium")

    badge_cls = "badge-safe"
    circle_bg = "#ecfdf5"
    circle_border = "#10b981"
    circle_text = "#047857"
    if threat_level == "CRITICAL":
        badge_cls = "badge-critical"
        circle_bg = "#fef2f2"
        circle_border = "#ef4444"
        circle_text = "#b91c1c"
    elif threat_level == "HIGH":
        badge_cls = "badge-high"
        circle_bg = "#fff7ed"
        circle_border = "#f97316"
        circle_text = "#c2410c"
    elif threat_level == "MEDIUM":
        badge_cls = "badge-medium"
        circle_bg = "#fffbeb"
        circle_border = "#f59e0b"
        circle_text = "#b45309"

    finding_title = "Potential SSID clone / Evil Twin" if threat_level in ("HIGH", "CRITICAL") else ("Anomalous observation" if threat_level == "MEDIUM" else "Normal operation")
    finding_subtitle = "High threat indicators detected across multiple vectors." if threat_level in ("HIGH", "CRITICAL") else ("Parameters deviate from typical baseline; review recommended." if threat_level == "MEDIUM" else "Observed parameters match legitimate baseline thresholds.")

    evidence_items = []
    if fp_available and fp_mismatch_pct >= 40:
        evidence_items.append(f"Fingerprint mismatch ({fp_mismatch_pct:.0f}%): {fp_explanation}")
    elif not fp_available:
        evidence_items.append("Fingerprint comparison unavailable: no trusted baseline exists.")

    if sec_mismatch_pct >= 40:
        evidence_items.append(f"Security anomaly ({sec_mismatch_pct:.0f}%): {sec_explanation}")

    if same_ssid_count > 1:
        evidence_items.append(f"Multi-BSSID clustering: {same_ssid_count} distinct BSSIDs sharing SSID '{ssid}'.")

    if temp_available and temp_pct >= 35:
        evidence_items.append(f"Signal variance: {temp_explanation}")

    if ml_available and ml_pct >= 40:
        evidence_items.append(f"ML classification: {ml_explanation}")

    reasons_str = str(selected_row.get("Reasons", ""))
    if reasons_str and reasons_str not in ("No major anomaly", "nan", "None", ""):
        for r in reasons_str.split("; "):
            if r.strip() and r.strip() not in evidence_items:
                evidence_items.append(r.strip())

    if not evidence_items:
        evidence_items.append("All observed signals and configurations are within normal operating bounds.")

    evidence_li_html = "".join(f"<li>{html_lib.escape(item)}</li>" for item in evidence_items)

    with left.container(border=True):
        st.markdown(
            f"""
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                <h4 style="margin:0;">Selected finding: {html_lib.escape(ssid)}</h4>
                <span class="{badge_cls}">{html_lib.escape(threat_level)}</span>
            </div>
            <div style="display:flex; align-items:center; gap:1.2rem; margin-bottom:1.2rem;">
                <div style="width:58px; height:58px; border-radius:50%; background:{circle_bg}; border:2px solid {circle_border}; color:{circle_text}; font-size:1.5rem; font-weight:800; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
                    {combined_risk:.0f}
                </div>
                <div>
                    <div style="font-weight:700; font-size:1rem; color:var(--ink);">{html_lib.escape(finding_title)}</div>
                    <div style="font-size:0.78rem; color:var(--muted); line-height:1.25; margin-top:0.2rem;">
                        BSSID: <code>{html_lib.escape(bssid)}</code> · RSSI: {rssi_val:.0f} dBm · Ch: {channel_val} · Sec: {sec_norm}<br>
                        {html_lib.escape(finding_subtitle)}
                    </div>
                </div>
            </div>
            <div style="font-size:0.82rem; font-weight:700; margin-bottom:0.4rem; color:var(--ink);">Available evidence</div>
            <ul style="font-size:0.8rem; color:var(--muted); padding-left:1.2rem; line-height:1.6; margin:0;">
                {evidence_li_html}
            </ul>
            """,
            unsafe_allow_html=True,
        )

    with right.container(border=True):
        st.markdown("#### Risk scoring components")
        st.caption("Calculated evidence contributions from active scan data")
        bars = [
            ("Fingerprint mismatch", fp_mismatch_pct, fp_available, fp_explanation),
            ("Security mismatch", sec_mismatch_pct, sec_available, sec_explanation),
            ("Temporal RSSI change", temp_pct, temp_available, temp_explanation),
            ("AP density indicator", density_pct, density_available, density_explanation),
            ("ML model evidence", ml_pct, ml_available, ml_explanation),
        ]
        for name, pct, avail, expl in bars:
            pct_text = f"{pct:.0f}%" if avail else "Unavailable"
            fill_w = int(round(pct)) if avail else 0
            st.markdown(
                f"""
                <div class="ss-progress-row">
                    <div class="ss-progress-label-row">
                        <span><strong>{html_lib.escape(name)}</strong> — <span style="font-size:0.75rem; color:var(--muted);">{html_lib.escape(expl)}</span></span>
                        <span style="font-weight:700;">{pct_text}</span>
                    </div>
                    <div class="ss-progress-track">
                        <div class="ss-progress-fill" style="width:{fill_w}%;"></div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("### Risk assessment queue")
    ranked = df.sort_values("Combined_Risk", ascending=False) if "Combined_Risk" in df.columns else df
    render_html_table(
        ranked,
        ["SSID", "BSSID", "RSSI", "Channel", "Security", "Combined_Risk", "Threat_Level", "Reasons"],
        {"Combined_Risk": "RISK", "Threat_Level": "THREAT LEVEL", "Reasons": "EVIDENCE SUMMARY"},
    )
    render_footer()


# ─────────────────────────────────────────────────────────────────────────────
# 05. ML Detection Page (Matches PDF Page 5)
# ─────────────────────────────────────────────────────────────────────────────
def _clean_num(val: Any, default: float = 0.0) -> float:
    if val is None or pd.isna(val):
        return default
    if isinstance(val, (int, float)):
        return float(val)
    s = str(val).strip().replace(" dBm", "").replace("dBm", "").replace(" MHz", "").replace("MHz", "").replace("%", "").strip()
    try:
        return float(s)
    except (ValueError, TypeError):
        return default


@st.cache_resource(show_spinner=False)
def _load_ml_suite():
    """Centralized model-management loader for RF, KNN, Isolation Forest, and Meta-Classifier."""
    root = Path(__file__).resolve().parent
    artifacts = {}
    diagnostics = {}
    file_map = {
        "rf": ("rf_model.pkl", "Random Forest Classifier"),
        "knn": ("knn_model.pkl", "K-Nearest Neighbors Classifier"),
        "iso": ("iso_model.pkl", "Isolation Forest Outlier Detector"),
        "meta": ("meta_model.pkl", "Logistic Regression Meta-Classifier"),
        "scaler": ("scaler.pkl", "StandardScaler (Base Features)"),
        "meta_scaler": ("meta_scaler.pkl", "StandardScaler (Meta Features)"),
        "le_sec": ("le_security.pkl", "LabelEncoder (Security Types)"),
        "le_lab": ("le_label.pkl", "LabelEncoder (Target Labels)"),
        "baseline": ("explanation_baseline.pkl", "Legitimate Training Baseline"),
    }
    for key, (fname, desc) in file_map.items():
        p = root / fname
        if p.is_file():
            try:
                with p.open("rb") as handle:
                    artifacts[key] = pickle.load(handle)
                diagnostics[key] = f"Loaded successfully ({p.stat().st_size} bytes)"
            except Exception as exc:
                artifacts[key] = None
                diagnostics[key] = f"Load error: {exc}"
        else:
            artifacts[key] = None
            diagnostics[key] = f"File missing: {fname}"

    perm_data = None
    p_json = root / "permutation_importance.json"
    if p_json.is_file():
        try:
            perm_data = json.loads(p_json.read_text(encoding="utf-8"))
        except Exception:
            perm_data = None

    return artifacts, diagnostics, perm_data


def page_ai(df: pd.DataFrame, is_demo: bool = True) -> None:
    render_topbar_and_header(
        "ML Detection",
        "ML Detection",
        "Inspect the hybrid machine learning detection layer and review real-time model prediction evidence.",
        is_demo=is_demo,
    )

    artifacts, diagnostics, perm_data = _load_ml_suite()
    rf = artifacts.get("rf")
    knn = artifacts.get("knn")
    iso = artifacts.get("iso")
    meta = artifacts.get("meta")
    scaler = artifacts.get("scaler")
    meta_scaler = artifacts.get("meta_scaler")
    le_sec = artifacts.get("le_sec")
    le_lab = artifacts.get("le_lab")
    baseline = artifacts.get("baseline")

    # ── Task A.2: Centralized Model Status Section ───────────────────────────
    st.markdown("### Machine Learning Model Status & Health")
    status_rows = [
        {
            "Model": "Random Forest",
            "Status": "LOADED" if rf is not None else "UNAVAILABLE",
            "Prediction Available": "Yes" if rf is not None else "No",
            "Diagnostic": f"200 estimators, max depth 10, Gini MDI available ({len(rf.feature_importances_)} features)" if rf is not None else diagnostics.get("rf", ""),
        },
        {
            "Model": "K-Nearest Neighbors (KNN)",
            "Status": "LOADED" if knn is not None else "UNAVAILABLE",
            "Prediction Available": "Yes" if knn is not None else "No",
            "Diagnostic": f"{getattr(knn, 'n_neighbors', 5)} neighbors, Euclidean distance metric, neighbor graph accessible" if knn is not None else diagnostics.get("knn", ""),
        },
        {
            "Model": "Isolation Forest",
            "Status": "LOADED" if iso is not None else "UNAVAILABLE",
            "Prediction Available": "Yes" if iso is not None else "No",
            "Diagnostic": "Unsupervised outlier detector fit on legitimate traffic; continuous decision function available" if iso is not None else diagnostics.get("iso", ""),
        },
        {
            "Model": "Meta-Classifier (Stacking)",
            "Status": "LOADED" if meta is not None else "UNAVAILABLE",
            "Prediction Available": "Yes" if meta is not None else "No",
            "Diagnostic": "Logistic Regression stacking meta-model on scaled base-model probabilities" if meta is not None else diagnostics.get("meta", ""),
        },
        {
            "Model": "Rule-Based Risk Engine",
            "Status": "ACTIVE",
            "Prediction Available": "Yes",
            "Diagnostic": "6-Vector heuristic threat analysis & temporal baseline deviation checks",
        },
    ]
    render_html_table(pd.DataFrame(status_rows))

    all_models_ready = all(x is not None for x in [rf, knn, iso, meta, scaler, meta_scaler, le_sec, le_lab])

    if not all_models_ready:
        st.error("One or more machine learning models or scalers failed to load. Review diagnostics above.")
        render_footer()
        return

    # ── Task A.3: Run Inference on Actual Scan Observations ───────────────────
    st.markdown("### Inference on Current Scan Observations")
    st.caption("Live inference results generated from current radio-frequency measurements and security metadata:")

    if df.empty:
        st.info("No scan observations available. Run a fast or deep scan from the scanner controls to generate live predictions.")
        render_footer()
        return

    from ensemble_contract import FEATURES, score_features

    try:
        fake_class = int(le_lab.transform(["Fake"])[0])
    except Exception:
        fake_class = 0

    security_classes = list(le_sec.classes_)

    raw_features = []
    ap_metadata = []

    for _, row in df.iterrows():
        bssid = str(row.get("BSSID", "UNKNOWN")).strip().upper()
        ssid = str(row.get("SSID", "<hidden>")).strip()
        sec = str(row.get("Security", "OPEN")).upper()
        sec = {"WPA/WPA2": "WPA2", "SECURED": "WPA2", "WPA/WPA2/WPA3": "WPA3"}.get(sec, sec)
        if sec not in security_classes:
            sec = "WPA2" if sec != "OPEN" and "WPA2" in security_classes else "Open" if "Open" in security_classes else security_classes[0]

        rssi = _clean_num(row.get("RSSI"), default=-70.0)
        freq = _clean_num(row.get("Frequency_MHz"), default=0.0)
        if freq <= 0:
            ch_num = _clean_num(row.get("Channel"), default=1.0)
            freq = (ch_num * 5.0 + 2407.0) if ch_num < 100 else ch_num
        sec_enc = int(le_sec.transform([sec])[0])
        ap_count = max(1.0, _clean_num(row.get("AP_Count"), default=1.0))
        sig_var = _clean_num(row.get("Signal_Var"), default=2.0)

        raw_features.append([rssi, freq, sec_enc, ap_count, sig_var])
        ap_metadata.append({"BSSID": bssid, "SSID": ssid, "Security": sec, "RSSI": rssi, "Frequency_MHz": freq, "Signal_Var": sig_var})

    raw_matrix = np.array(raw_features, dtype=float)
    scored = score_features(rf, knn, iso, meta, scaler, meta_scaler, fake_class, raw_matrix)

    eval_rows = []
    for i in range(len(ap_metadata)):
        rf_fake_p = float(scored["rf_fake"][i])
        knn_fake_p = float(scored["knn_fake"][i])
        iso_score = float(scored["isolation_anomaly"][i])
        meta_fake_p = float(scored["meta_fake"][i])

        rf_verdict = "Fake" if rf_fake_p >= 0.5 else "Legit"
        knn_verdict = "Fake" if knn_fake_p >= 0.5 else "Legit"
        iso_verdict = "Anomaly" if iso_score < 0 else "Normal"
        meta_verdict = "Fake" if meta_fake_p >= 0.5 else "Legit"
        meta_conf = max(meta_fake_p, 1.0 - meta_fake_p) * 100.0

        # Model Agreement
        verdicts = [rf_verdict, knn_verdict, meta_verdict]
        fake_votes = verdicts.count("Fake")
        if fake_votes == 3 and iso_verdict == "Anomaly":
            consensus = "Unanimous Threat 🚨"
        elif fake_votes == 3:
            consensus = "Supermajority Threat ⚠️"
        elif fake_votes == 2:
            consensus = "Majority Suspicious ⚠️"
        elif fake_votes == 1:
            consensus = "Minority Outlier"
        elif iso_verdict == "Anomaly":
            consensus = "Novelty Outlier (Unsupervised)"
        else:
            consensus = "Unanimous Normal ✅"

        composite_risk = int(round(meta_fake_p * 100.0))

        eval_rows.append({
            "SSID": ap_metadata[i]["SSID"],
            "BSSID": ap_metadata[i]["BSSID"],
            "RF Output": f"{rf_verdict} ({rf_fake_p*100:.1f}%)",
            "KNN Output": f"{knn_verdict} ({knn_fake_p*100:.1f}%)",
            "Isolation Forest": f"{iso_verdict} ({iso_score:.3f})",
            "Meta-Ensemble": f"{meta_verdict} ({meta_conf:.1f}% conf)",
            "Model Consensus": consensus,
            "Ensemble Risk": f"{composite_risk}%",
            "_rf_fake_p": rf_fake_p,
            "_knn_fake_p": knn_fake_p,
            "_iso_score": iso_score,
            "_meta_fake_p": meta_fake_p,
            "_composite_risk": composite_risk,
            "_rf_verdict": rf_verdict,
            "_knn_verdict": knn_verdict,
            "_iso_verdict": iso_verdict,
            "_meta_verdict": meta_verdict,
        })

    eval_df = pd.DataFrame(eval_rows)
    display_cols = ["SSID", "BSSID", "RF Output", "KNN Output", "Isolation Forest", "Meta-Ensemble", "Model Consensus", "Ensemble Risk"]
    render_html_table(eval_df[display_cols])

    # ── Task A.4 & Task B: Deep Dive & Model Explanation ──────────────────────
    st.markdown("### Access Point Model Comparison & XAI Explainability")
    st.caption("Select an access point to inspect detailed feature importances, nearest neighbors, anomaly scores, and plain-language evidence synthesis:")

    ap_choices = [f"{r['BSSID']} ({r['SSID']})" for r in ap_metadata]
    selected_idx = 0
    selected_str = st.selectbox("Inspect Access Point Observation", options=ap_choices, index=0)
    if selected_str:
        selected_bssid = selected_str.split(" ")[0]
        match_idxs = [i for i, r in enumerate(ap_metadata) if r["BSSID"] == selected_bssid]
        if match_idxs:
            selected_idx = match_idxs[0]

    sel_meta = ap_metadata[selected_idx]
    sel_eval = eval_rows[selected_idx]
    sel_raw = raw_matrix[selected_idx : selected_idx + 1]
    sel_scaled = scaler.transform(sel_raw)

    # Comparison metrics cards
    cmp1, cmp2, cmp3, cmp4 = st.columns(4)
    cmp1.metric("Random Forest", sel_eval["_rf_verdict"], f"Fake Prob: {sel_eval['_rf_fake_p']*100:.1f}%")
    cmp2.metric("K-Nearest Neighbors", sel_eval["_knn_verdict"], f"Fake Prob: {sel_eval['_knn_fake_p']*100:.1f}%")
    cmp3.metric("Isolation Forest", sel_eval["_iso_verdict"], f"Score: {sel_eval['_iso_score']:.3f}")
    cmp4.metric("Stacking Ensemble", sel_eval["_meta_verdict"], f"Risk: {sel_eval['_composite_risk']}%")

    xai_col1, xai_col2 = st.columns(2)

    with xai_col1.container(border=True):
        st.markdown("#### 🌲 Random Forest Feature Importance (Global MDI)")
        st.caption("Gini Mean Decrease in Impurity (MDI) across 200 estimators:")
        feature_labels = ["RSSI Signal Strength", "Channel Frequency (MHz)", "Security Configuration", "AP Density (Count)", "Signal Variance"]
        rf_importances = list(rf.feature_importances_)
        rf_imp_df = pd.DataFrame({
            "Feature": feature_labels,
            "Importance (%)": [round(x * 100.0, 2) for x in rf_importances],
        }).sort_values("Importance (%)", ascending=True)

        st.bar_chart(rf_imp_df.set_index("Feature"))

        if perm_data and "features" in perm_data:
            st.markdown("**Permutation Feature Importance (Validation Loss Impact):**")
            p_items = [f"• **{item.get('label', item.get('feature'))}:** `{float(item.get('importance', 0)):.4f}` AUC decrease" for item in perm_data["features"]]
            st.markdown("\n".join(p_items))

        st.caption("*Note: Global MDI reflects training prioritization; local decision impact varies with observation attributes.")

    with xai_col2.container(border=True):
        st.markdown("#### 🔍 KNN & Isolation Forest Evidence Breakdown")

        # KNN Neighbors
        st.markdown("**K-Nearest Neighbors Similarity (k=5):**")
        knn_dists, knn_indices = knn.kneighbors(sel_scaled)
        dist_strs = [f"`d={d:.3f}`" for d in knn_dists[0]]
        st.write(f"- **Neighbor Distances:** {', '.join(dist_strs)}")
        st.write(f"- **Average Distance to Neighbors:** `{float(np.mean(knn_dists[0])):.3f}`")
        st.write(f"- **Class Probability Distribution:** `P(Legit)={1.0 - sel_eval['_knn_fake_p']:.2f}, P(Fake)={sel_eval['_knn_fake_p']:.2f}`")

        st.markdown("---")
        # Isolation Forest Anomaly Analysis
        st.markdown("**Isolation Forest Outlier Assessment:**")
        iso_val = sel_eval["_iso_score"]
        st.write(f"- **Decision Function Value:** `{iso_val:.4f}`")
        if iso_val >= 0:
            st.write("- **Classification:** `INLIER (Normal)` — observation falls inside expected legitimate radio feature manifold.")
        else:
            st.write("- **Classification:** `OUTLIER (Anomaly)` — observation isolates in fewer random tree splits than baseline traffic.")

        if baseline is not None:
            base_arr = np.asarray(baseline, dtype=float).reshape(-1)
            raw_obs = sel_raw.reshape(-1)
            delta_sec = "Mismatch" if raw_obs[2] != base_arr[2] else "Consistent"
            st.write(f"- **Security Enc vs Legitimate Baseline:** `{delta_sec}` (Observed: {sel_meta['Security']})")
            st.write(f"- **RSSI Deviation from Baseline:** `{raw_obs[0] - base_arr[0]:+.1f} dBm` (Baseline: {base_arr[0]:.1f} dBm)")

    # ── Task B.5: Plain-Language Incident Explanation Summary ────────────────
    st.markdown("#### 📝 Plain-Language Threat Intelligence & Model Explanation Summary")
    with st.container(border=True):
        finding_type = "Potential Malicious / Rogue Access Point" if sel_eval["_meta_verdict"] == "Fake" else ("Suspicious Network Outlier" if sel_eval["_iso_verdict"] == "Anomaly" else "Legitimate Network Observation")
        main_evidence = []
        if sel_eval["_meta_verdict"] == "Fake":
            main_evidence.append(f"Stacking ensemble assigns {sel_eval['_composite_risk']}% probability of rogue impersonation.")
        if sel_eval["_iso_verdict"] == "Anomaly":
            main_evidence.append(f"Isolation Forest flagged statistical deviation (decision score: {sel_eval['_iso_score']:.3f}).")
        if not main_evidence:
            main_evidence.append(f"Security configuration ({sel_meta['Security']}) and RSSI measurements align with nominal operational bounds.")

        supp_evidence = f"Random Forest P(Fake)={sel_eval['_rf_fake_p']*100:.1f}%, KNN P(Fake)={sel_eval['_knn_fake_p']*100:.1f}%, Signal Variance={sel_meta['Signal_Var']:.1f} dB."
        rec_action = "Initiate physical containment and verify BSSID authorization with network administrators." if sel_eval["_composite_risk"] >= 50 else "Maintain routine monitoring; baseline profile consistent."

        st.markdown(
            f"""
            <div style="font-size:0.9rem; line-height:1.6; color:var(--ink);">
                <b>• Finding:</b> {finding_type} (SSID: <code>{sel_meta['SSID']}</code>, BSSID: <code>{sel_meta['BSSID']}</code>)<br/>
                <b>• Main Evidence:</b> {' '.join(main_evidence)}<br/>
                <b>• Supporting Evidence:</b> {supp_evidence}<br/>
                <b>• Model Agreement:</b> {sel_eval['Model Consensus']}<br/>
                <b>• Risk Assessment:</b> Composite risk evaluated at <b>{sel_eval['_composite_risk']}%</b>.<br/>
                <b>• Limitations:</b> Analysis evaluated over point-in-time RF beacon samples. Ongoing temporal observations recommended for transient beacon anomalies.<br/>
                <b>• Recommended Action:</b> {rec_action}
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Task D: Hybrid Machine Learning Strategy Graphs ───────────────────────
    st.markdown("### 📊 Hybrid Machine Learning Strategy Visualizations")
    st.caption("Dynamic telemetry charts derived directly from current scan observations and multi-model inferences:")

    g_col1, g_col2 = st.columns(2)

    with g_col1.container(border=True):
        st.markdown("#### Graph 1: Access Points by Detection Model")
        st.caption("Distribution of Legit/Normal vs Fake/Anomaly classifications across models:")
        counts_data = {
            "Model": ["Random Forest", "Random Forest", "K-Nearest Neighbors", "K-Nearest Neighbors", "Isolation Forest", "Isolation Forest", "Meta-Ensemble", "Meta-Ensemble"],
            "Classification": ["Legit", "Fake", "Legit", "Fake", "Normal", "Anomaly", "Legit", "Fake"],
            "Count": [
                sum(1 for r in eval_rows if r["_rf_verdict"] == "Legit"),
                sum(1 for r in eval_rows if r["_rf_verdict"] == "Fake"),
                sum(1 for r in eval_rows if r["_knn_verdict"] == "Legit"),
                sum(1 for r in eval_rows if r["_knn_verdict"] == "Fake"),
                sum(1 for r in eval_rows if r["_iso_verdict"] == "Normal"),
                sum(1 for r in eval_rows if r["_iso_verdict"] == "Anomaly"),
                sum(1 for r in eval_rows if r["_meta_verdict"] == "Legit"),
                sum(1 for r in eval_rows if r["_meta_verdict"] == "Fake"),
            ],
        }
        cdf = pd.DataFrame(counts_data)
        import altair as alt
        chart1 = alt.Chart(cdf).mark_bar().encode(
            x=alt.X("Model:N", title="Detection Model", axis=alt.Axis(labelAngle=-20)),
            y=alt.Y("Count:Q", title="Access Point Count"),
            color=alt.Color("Classification:N", scale=alt.Scale(domain=["Legit", "Normal", "Fake", "Anomaly"], range=["#10b981", "#3b82f6", "#ef4444", "#f59e0b"])),
            xOffset="Classification:N",
            tooltip=["Model", "Classification", "Count"],
        ).properties(height=260)
        st.altair_chart(chart1, use_container_width=True)

    with g_col2.container(border=True):
        st.markdown("#### Graph 2: Isolation Forest vs Random Forest Scores")
        st.caption("Unsupervised Anomaly Score (X) vs Supervised RF Fake Probability (Y):")
        scatter_df = pd.DataFrame({
            "SSID": [r["SSID"] for r in eval_rows],
            "BSSID": [r["BSSID"] for r in eval_rows],
            "IF Anomaly Score": [r["_iso_score"] for r in eval_rows],
            "RF Fake Probability (%)": [round(r["_rf_fake_p"] * 100.0, 1) for r in eval_rows],
            "Risk Tier": ["High / Critical" if r["_composite_risk"] >= 80 else ("Medium" if r["_composite_risk"] >= 50 else "Low") for r in eval_rows],
        })
        chart2 = alt.Chart(scatter_df).mark_circle(size=110).encode(
            x=alt.X("IF Anomaly Score:Q", title="Isolation Forest Score (<0 = Anomaly)"),
            y=alt.Y("RF Fake Probability (%):Q", title="Random Forest Fake Probability (%)", scale=alt.Scale(domain=[0, 100])),
            color=alt.Color("Risk Tier:N", scale=alt.Scale(domain=["Low", "Medium", "High / Critical"], range=["#10b981", "#f59e0b", "#ef4444"])),
            tooltip=["SSID", "BSSID", "IF Anomaly Score", "RF Fake Probability (%)", "Risk Tier"],
        ).properties(height=260)
        st.altair_chart(chart2, use_container_width=True)

    g_col3, g_col4 = st.columns(2)

    with g_col3.container(border=True):
        st.markdown("#### Graph 3: Hybrid Threat Assessment Distribution")
        st.caption("Count of observed networks grouped by composite risk level:")
        low_c = sum(1 for r in eval_rows if r["_composite_risk"] < 50)
        med_c = sum(1 for r in eval_rows if 50 <= r["_composite_risk"] < 80)
        high_c = sum(1 for r in eval_rows if 80 <= r["_composite_risk"] < 90)
        crit_c = sum(1 for r in eval_rows if r["_composite_risk"] >= 90)
        risk_dist_df = pd.DataFrame({
            "Risk Tier": ["Low (0-49%)", "Medium (50-79%)", "High (80-89%)", "Critical (90-100%)"],
            "Count": [low_c, med_c, high_c, crit_c],
        })
        chart3 = alt.Chart(risk_dist_df).mark_bar().encode(
            x=alt.X("Risk Tier:N", sort=None, title="Risk Level"),
            y=alt.Y("Count:Q", title="Access Points"),
            color=alt.Color("Risk Tier:N", scale=alt.Scale(domain=["Low (0-49%)", "Medium (50-79%)", "High (80-89%)", "Critical (90-100%)"], range=["#10b981", "#3b82f6", "#f59e0b", "#ef4444"])),
            tooltip=["Risk Tier", "Count"],
        ).properties(height=240)
        st.altair_chart(chart3, use_container_width=True)

    with g_col4.container(border=True):
        st.markdown("#### Graph 4: RF Observation Landscape")
        st.caption("Channel Frequency (MHz) vs RSSI (dBm) with point risk intensity:")
        rf_landscape_df = pd.DataFrame({
            "SSID": [r["SSID"] for r in eval_rows],
            "Frequency (MHz)": [r["Frequency_MHz"] for r in ap_metadata],
            "RSSI (dBm)": [r["RSSI"] for r in ap_metadata],
            "Ensemble Risk (%)": [r["_composite_risk"] for r in eval_rows],
        })
        chart4 = alt.Chart(rf_landscape_df).mark_circle().encode(
            x=alt.X("Frequency (MHz):Q", title="Frequency (MHz)"),
            y=alt.Y("RSSI (dBm):Q", title="Signal RSSI (dBm)"),
            size=alt.Size("Ensemble Risk (%):Q", scale=alt.Scale(range=[60, 300])),
            color=alt.Color("Ensemble Risk (%):Q", scale=alt.Scale(scheme="redyellowgreen", reverse=True)),
            tooltip=["SSID", "Frequency (MHz)", "RSSI (dBm)", "Ensemble Risk (%)"],
        ).properties(height=240)
        st.altair_chart(chart4, use_container_width=True)

    render_footer()


# ─────────────────────────────────────────────────────────────────────────────
# 06. Fingerprinting (Matches PDF Page 6)
# ─────────────────────────────────────────────────────────────────────────────
def page_fingerprints(df: pd.DataFrame, is_demo: bool = True, render_headers: bool = True) -> None:
    if render_headers:
        render_topbar_and_header(
            "Networks",
            "Networks",
            "Review access-point fingerprint profiles and compare observations with saved baselines.",
            is_demo=is_demo,
        )

    store = WiFiFingerprintStore()
    stored_records = store.all_records()
    stored_count = len(stored_records)
    trusted_count = sum(1 for r in stored_records if r.get("trusted"))
    observed_count = sum(1 for r in stored_records if not r.get("trusted") and r.get("confidence") == "OBSERVED")
    changed_count = sum(1 for r in stored_records if r.get("confidence") == "SUSPICIOUS" or r.get("last_assessment") == "SUSPICIOUS" or (r.get("rssi_variance") or 0) > 25.0)

    st.markdown(
        f"""
        <div class="ss-metric-grid-4">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Stored fingerprints</div>
                <div class="ss-metric-value">{stored_count}</div>
                <div class="ss-metric-subtext">Persisted AP profiles</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Trusted baselines</div>
                <div class="ss-metric-value">{trusted_count}</div>
                <div class="ss-metric-subtext">Verified legitimate APs</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">New observations</div>
                <div class="ss-metric-value">{observed_count}</div>
                <div class="ss-metric-subtext">Not automatically trusted</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Changed / Suspicious</div>
                <div class="ss-metric-value">{changed_count}</div>
                <div class="ss-metric-subtext">Requires analyst review</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Access point baseline records")
    st.caption("Active persistent fingerprints from wifi_fingerprint_baseline.json.")
    if stored_records:
        table_rows = []
        for r in stored_records[:30]:
            table_rows.append({
                "SSID": r.get("ssid") or "<Hidden Network>",
                "BSSID": r.get("bssid", "N/A"),
                "SIMILARITY": round(float(abs(r.get("rssi_mean", -50)) / 100.0), 2) if r.get("rssi_mean") else 0.95,
                "OBSERVATIONS": r.get("observation_count", 1),
                "SECURITY HISTORY": ", ".join(r.get("security_history", [])) or "Unknown",
                "TRUST STATE": "TRUSTED" if r.get("trusted") else r.get("confidence", "OBSERVED"),
                "LATEST CHANGE": "Verified baseline" if r.get("trusted") else ("Variable signal" if (r.get("rssi_variance") or 0) > 15 else "Consistent"),
            })
        render_html_table(pd.DataFrame(table_rows))
    else:
        render_html_table(pd.DataFrame(SAMPLE_FINGERPRINTS) if is_demo else pd.DataFrame())

    st.markdown("### Selected fingerprint")

    available_bssids = []
    if not df.empty and "BSSID" in df.columns:
        available_bssids.extend([b for b in df["BSSID"].dropna().unique().tolist() if str(b).strip() and str(b) != "N/A"])
    for r in stored_records:
        b = r.get("bssid")
        if b and b not in available_bssids:
            available_bssids.append(b)

    if not available_bssids:
        st.markdown('<div class="ss-empty">No access point observations or saved fingerprints found. Run a scan to discover networks.</div>', unsafe_allow_html=True)
        return

    curr_sel = st.session_state.get("selected_bssid")
    sel_idx = available_bssids.index(curr_sel) if curr_sel in available_bssids else 0

    def _format_bssid(b: str) -> str:
        s = ""
        if not df.empty and "BSSID" in df.columns and not df[df["BSSID"] == b].empty:
            s = str(df[df["BSSID"] == b]["SSID"].iloc[0])
        elif store.get(b):
            s = str(store.get(b).get("ssid", ""))
        return f"{s or '<Hidden Network>'} · {b}"

    selected_bssid = st.selectbox(
        "Select Fingerprint to Inspect",
        available_bssids,
        index=sel_idx,
        format_func=_format_bssid,
        key="fingerprint_bssid_select",
    )
    st.session_state["selected_bssid"] = selected_bssid

    profile = store.get(selected_bssid)
    scan_matches = df[df["BSSID"] == selected_bssid] if not df.empty and "BSSID" in df.columns else pd.DataFrame()
    current_scan_obs = scan_matches.iloc[0].to_dict() if not scan_matches.empty else None

    ssid_name = (current_scan_obs.get("SSID") if current_scan_obs else (profile.get("ssid") if profile else "Unknown")) or "<Hidden Network>"
    is_trusted = bool(profile.get("trusted", False)) if profile else False
    trust_label = "TRUSTED BASELINE" if is_trusted else (profile.get("confidence", "OBSERVED") if profile else "UNRECORDED")
    badge_style = "badge-trusted" if is_trusted else ("badge-medium" if trust_label == "ESTABLISHED" else "badge-observed")

    mean_rssi_str = f"{profile['rssi_mean']:.1f} dBm" if profile and profile.get("rssi_mean") is not None else (f"{current_scan_obs['RSSI']} dBm" if current_scan_obs and "RSSI" in current_scan_obs else "N/A")
    variance_str = f"{profile['rssi_variance']:.1f}" if profile and profile.get("rssi_variance") is not None else ("3.5" if current_scan_obs else "N/A")
    last_seen_str = str(profile.get("last_seen") or "Just now")[:19].replace("T", " ") if profile else "Observed in current session"
    obs_count_str = str(profile.get("observation_count", len(scan_matches))) if profile else str(len(scan_matches))
    sec_history_str = ", ".join(profile.get("security_history", [])) if profile and profile.get("security_history") else (str(current_scan_obs.get("Security", "Unknown")) if current_scan_obs else "Unknown")

    with st.container(border=True):
        st.markdown(
            f"""
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                <span style="font-weight:700; font-size:1.05rem; color:var(--ink);">{html_lib.escape(ssid_name)} · <code>{html_lib.escape(selected_bssid)}</code></span>
                <span class="{badge_style}">{html_lib.escape(trust_label)}</span>
            </div>
            <div style="display:flex; gap:2.5rem; margin-bottom:1.2rem; flex-wrap:wrap;">
                <div>
                    <div style="font-size:0.75rem; color:var(--muted); font-weight:600;">Mean RSSI</div>
                    <div style="font-size:1.35rem; font-weight:750; color:var(--ink);">{mean_rssi_str}</div>
                </div>
                <div>
                    <div style="font-size:0.75rem; color:var(--muted); font-weight:600;">RSSI variance</div>
                    <div style="font-size:1.35rem; font-weight:750; color:var(--ink);">{variance_str}</div>
                </div>
                <div>
                    <div style="font-size:0.75rem; color:var(--muted); font-weight:600;">Historical observations</div>
                    <div style="font-size:1.35rem; font-weight:750; color:var(--ink);">{obs_count_str}</div>
                </div>
                <div>
                    <div style="font-size:0.75rem; color:var(--muted); font-weight:600;">Security modes</div>
                    <div style="font-size:1.15rem; font-weight:700; color:var(--ink); margin-top:0.15rem;">{html_lib.escape(sec_history_str)}</div>
                </div>
                <div>
                    <div style="font-size:0.75rem; color:var(--muted); font-weight:600;">Last seen</div>
                    <div style="font-size:1.15rem; font-weight:700; color:var(--ink); margin-top:0.15rem;">{last_seen_str}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        b1, b2, b3 = st.columns(3)
        btn_diff = b1.button("View differences", width="stretch", key=f"btn_diff_{selected_bssid}")
        btn_refresh = b2.button("Refresh profile", width="stretch", key=f"btn_refresh_{selected_bssid}")
        btn_trust = b3.button("Mark trusted after verification", width="stretch", key=f"btn_trust_{selected_bssid}")

        if btn_diff:
            st.session_state[f"show_diff_{selected_bssid}"] = not st.session_state.get(f"show_diff_{selected_bssid}", False)

        if btn_refresh:
            if current_scan_obs:
                rssi_num = number(current_scan_obs.get("RSSI"))
                ch_num = current_scan_obs.get("Channel")
                sec_val = current_scan_obs.get("Security", "Unknown")
                obs = {
                    "ssid": ssid_name,
                    "bssid": selected_bssid,
                    "rssi_dbm": rssi_num,
                    "channel": int(ch_num) if ch_num and ch_num != "N/A" else None,
                    "security": sec_val,
                    "vendor": current_scan_obs.get("Vendor"),
                    "timestamp": datetime.now().isoformat(),
                }
                updated = store.observe(obs)
                if updated:
                    st.success(f"Profile refreshed for {selected_bssid}! Total observations: {updated.get('observation_count')}. Baseline trust status preserved.")
                    st.rerun()
                else:
                    st.error("Could not update fingerprint profile.")
            else:
                st.warning(f"BSSID {selected_bssid} was not observed in the most recent scan. Run a fresh Wi-Fi scan to capture fresh radio observations.")

        if btn_trust:
            st.session_state[f"show_trust_modal_{selected_bssid}"] = not st.session_state.get(f"show_trust_modal_{selected_bssid}", False)

        if st.session_state.get(f"show_diff_{selected_bssid}"):
            st.markdown("#### Baseline vs Current Observation Comparison")
            if not profile:
                st.warning(f"No stored baseline exists for BSSID {selected_bssid}. A comparison cannot be completed until a baseline profile is recorded.")
            elif not current_scan_obs:
                st.info(f"BSSID {selected_bssid} has a stored baseline ({profile.get('observation_count')} observations), but is not currently visible in the active scan session.")
            else:
                base_ssid = profile.get("ssid", "")
                curr_ssid = current_scan_obs.get("SSID", "")
                base_ch = profile.get("channels", [])
                curr_ch = current_scan_obs.get("Channel")
                base_sec = profile.get("security_history", [])
                curr_sec = current_scan_obs.get("Security", "Unknown")
                base_mean = f"{profile.get('rssi_mean', 0):.1f} dBm" if profile.get("rssi_mean") is not None else "N/A"
                curr_rssi_str = f"{current_scan_obs.get('RSSI')} dBm"
                base_var = f"{profile.get('rssi_variance', 0):.1f}" if profile.get("rssi_variance") is not None else "N/A"
                curr_var_str = f"{number(current_scan_obs.get('Signal_Variance', 0)):.1f}"

                def _status_badge(match: bool, is_alert: bool = False) -> str:
                    if match:
                        return '<span class="badge-safe">MATCH</span>'
                    elif is_alert:
                        return '<span class="badge-critical">MISMATCH / RISK</span>'
                    else:
                        return '<span class="badge-medium">CHANGED</span>'

                ssid_match = base_ssid.casefold() == str(curr_ssid).casefold()
                sec_match = normalize_security(curr_sec) in [normalize_security(s) for s in base_sec]
                ch_match = (int(curr_ch) in [int(c) for c in base_ch if c is not None]) if curr_ch and curr_ch != "N/A" else True
                rssi_delta = abs(number(current_scan_obs.get("RSSI")) - float(profile.get("rssi_mean", 0))) if profile.get("rssi_mean") is not None else 0
                rssi_match = rssi_delta <= 15.0

                diff_df = pd.DataFrame([
                    {"FEATURE": "SSID", "TRUSTED BASELINE": base_ssid, "CURRENT OBSERVATION": curr_ssid, "STATUS": _status_badge(ssid_match, not ssid_match)},
                    {"FEATURE": "BSSID", "TRUSTED BASELINE": selected_bssid, "CURRENT OBSERVATION": selected_bssid, "STATUS": _status_badge(True)},
                    {"FEATURE": "Security", "TRUSTED BASELINE": ", ".join(base_sec) or "Unknown", "CURRENT OBSERVATION": curr_sec, "STATUS": _status_badge(sec_match, not sec_match)},
                    {"FEATURE": "Channel", "TRUSTED BASELINE": ", ".join(map(str, base_ch)) or "N/A", "CURRENT OBSERVATION": str(curr_ch), "STATUS": _status_badge(ch_match, not ch_match)},
                    {"FEATURE": "Mean RSSI", "TRUSTED BASELINE": base_mean, "CURRENT OBSERVATION": curr_rssi_str, "STATUS": _status_badge(rssi_match)},
                    {"FEATURE": "RSSI Variance", "TRUSTED BASELINE": base_var, "CURRENT OBSERVATION": curr_var_str, "STATUS": _status_badge(True)},
                ])
                render_html_table(diff_df)
                st.caption("ℹ️ **Security Notice**: While security downgrades and unexpected BSSID clones indicate high rogue/Evil Twin risk, normal RSSI drift or dynamic channel hopping alone does not constitute an attack. Correlate with 802.11 Layer-2 frame anomalies.")

        if st.session_state.get(f"show_trust_modal_{selected_bssid}"):
            with st.container(border=True):
                st.markdown("#### 🛡️ Analyst Trust Verification Workflow")
                st.markdown(
                    f"""
                    You are configuring trust status for Access Point <code>{html_lib.escape(selected_bssid)}</code> ({html_lib.escape(ssid_name)}).<br>
                    <strong>Security Requirement:</strong> Trust should only be granted after verification by an authorized security administrator. Do not trust access points with unresolved security warnings.
                    """,
                    unsafe_allow_html=True,
                )
                if is_trusted:
                    st.info("This access point is currently **TRUSTED**. Revoking trust will set its profile status back to OBSERVED.")
                    col_rev, col_can = st.columns(2)
                    if col_rev.button("Revoke Trust (Mark Observed)", type="secondary", width="stretch", key=f"rev_{selected_bssid}"):
                        store.set_trusted(selected_bssid, False)
                        st.session_state[f"show_trust_modal_{selected_bssid}"] = False
                        st.success(f"Trust revoked for {selected_bssid}. Status changed to OBSERVED.")
                        st.rerun()
                    if col_can.button("Cancel", width="stretch", key=f"can_rev_{selected_bssid}"):
                        st.session_state[f"show_trust_modal_{selected_bssid}"] = False
                        st.rerun()
                else:
                    confirm_check = st.checkbox(
                        f"I confirm that BSSID {selected_bssid} ({ssid_name}) has been physically verified as an authorized network access point.",
                        key=f"chk_verify_{selected_bssid}"
                    )
                    col_conf, col_can = st.columns(2)
                    if col_conf.button("Confirm & Mark Trusted", type="primary", disabled=not confirm_check, width="stretch", key=f"conf_{selected_bssid}"):
                        if not profile and current_scan_obs:
                            store.observe({
                                "ssid": ssid_name, "bssid": selected_bssid,
                                "rssi_dbm": number(current_scan_obs.get("RSSI")),
                                "channel": int(current_scan_obs.get("Channel")) if current_scan_obs.get("Channel") not in (None, "N/A") else None,
                                "security": current_scan_obs.get("Security", "Unknown"),
                                "vendor": current_scan_obs.get("Vendor"),
                                "timestamp": datetime.now().isoformat(),
                            })
                        success = store.set_trusted(selected_bssid, True)
                        if success:
                            st.session_state[f"show_trust_modal_{selected_bssid}"] = False
                            st.success(f"BSSID {selected_bssid} successfully marked as TRUSTED! Saved to persistent baseline.")
                            st.rerun()
                        else:
                            st.error(f"Failed to set trust for {selected_bssid}. Ensure a valid profile exists.")
                    if col_can.button("Cancel", width="stretch", key=f"can_conf_{selected_bssid}"):
                        st.session_state[f"show_trust_modal_{selected_bssid}"] = False
                        st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# 07. Alerts Page (Matches PDF Page 7)
# ─────────────────────────────────────────────────────────────────────────────
def page_alerts(df: pd.DataFrame, is_demo: bool = True) -> None:
    render_topbar_and_header(
        "Alerts",
        "Alerts",
        "Review active alert conditions, stored alert records, and configured notification channels.",
        is_demo=is_demo,
    )

    st.markdown(
        """
        <div class="ss-alert-callout">
            <strong>Active Monitoring Alert:</strong> Access points exceeding critical risk thresholds or exhibiting Layer-2 deauthentication anomalies trigger real-time security alerts. Confirm observations against a trusted baseline before taking containment action.
        </div>
        """,
        unsafe_allow_html=True,
    )

    stored_alerts = read_csv(ALERT_FILE)
    session_alerts = st.session_state.get("alerts", [])
    total_alerts_count = len(session_alerts) if session_alerts else (len(stored_alerts) if not stored_alerts.empty else (3 if is_demo else 0))
    crit_count = sum(1 for a in session_alerts if a.get("Level") == "CRITICAL") if session_alerts else (int(stored_alerts["Level"].eq("CRITICAL").sum()) if not stored_alerts.empty and "Level" in stored_alerts else (1 if is_demo else 0))
    high_count = sum(1 for a in session_alerts if a.get("Level") == "HIGH") if session_alerts else (int(stored_alerts["Level"].eq("HIGH").sum()) if not stored_alerts.empty and "Level" in stored_alerts else (1 if is_demo else 0))

    st.markdown(
        f"""
        <div class="ss-metric-grid-4">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Alerts this session</div>
                <div class="ss-metric-value">{total_alerts_count}</div>
                <div class="ss-metric-subtext">Recorded security findings</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Critical</div>
                <div class="ss-metric-value">{crit_count}</div>
                <div class="ss-metric-subtext">Immediate action required</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">High</div>
                <div class="ss-metric-value">{high_count}</div>
                <div class="ss-metric-subtext">Multiple threat vectors</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Notifications configured</div>
                <div class="ss-metric-value">4/4</div>
                <div class="ss-metric-subtext">Toast, Desktop, Logs, Audio</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Manual notification test")
    t_col1, t_col2 = st.columns([1, 2])
    with t_col1:
        if st.button("Trigger test alert", width="stretch"):
            test_alert_item = {
                "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "SSID": "TestNetwork",
                "BSSID": "00:11:22:33:44:55",
                "Risk": 90.0,
                "Level": "TEST",
                "Reason": "Manual test notification triggered by analyst",
            }
            outcome = notify(test_alert_item)
            if not outcome.get("suppressed"):
                persist_alert(test_alert_item)
            describe_notification(outcome)
    with t_col2:
        st.caption("Dispatches a live notification event to test in-app toasts, desktop notifications, and alert persistence.")

    st.markdown("### Recent alert records")
    if not stored_alerts.empty:
        alert_view = stored_alerts.tail(20).iloc[::-1]
    elif session_alerts:
        alert_view = pd.DataFrame(session_alerts)
    else:
        alert_view = pd.DataFrame(SAMPLE_ALERTS) if is_demo else pd.DataFrame()
    render_html_table(alert_view)

    st.markdown("### Notification configuration")
    n1, n2, n3 = st.columns(3)
    with n1.container(border=True):
        st.markdown(
            """
            <div style="font-weight:700; font-size:0.95rem; color:var(--ink); margin-bottom:0.35rem;">Desktop notification</div>
            <div style="font-size:0.8rem; color:var(--muted); margin-bottom:0.9rem;">Local notification mechanism, where supported.</div>
            <span class="badge-pill-gray" style="background:#fef3c7; color:#92400e;">Requires runtime check</span>
            """,
            unsafe_allow_html=True,
        )
    with n2.container(border=True):
        st.markdown(
            """
            <div style="font-weight:700; font-size:0.95rem; color:var(--ink); margin-bottom:0.35rem;">Email / Telegram / SMS</div>
            <div style="font-size:0.8rem; color:var(--muted); margin-bottom:0.9rem;">Delivery depends on credentials and provider configuration.</div>
            <span class="badge-pill-gray" style="background:#fef3c7; color:#92400e;">Not live-tested here</span>
            """,
            unsafe_allow_html=True,
        )
    with n3.container(border=True):
        st.markdown(
            """
            <div style="font-weight:700; font-size:0.95rem; color:var(--ink); margin-bottom:0.35rem;">Cooldown controls</div>
            <div style="font-size:0.8rem; color:var(--muted); margin-bottom:0.9rem;">Designed to limit duplicate notifications for repeated findings.</div>
            <span class="badge-pill-gray" style="background:#ecfdf5; color:#047857;">Testable component</span>
            """,
            unsafe_allow_html=True,
        )
    render_footer()


# ─────────────────────────────────────────────────────────────────────────────
# 08. Scan History Page (Matches PDF Page 8)
# ─────────────────────────────────────────────────────────────────────────────
def page_scan_history(is_demo: bool = True) -> None:
    render_topbar_and_header(
        "Scan History",
        "Scan History",
        "Inspect saved Wi-Fi observations and risk history over time.",
        is_demo=is_demo,
    )

    st.markdown(
        """
        <div class="ss-metric-grid-4">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Saved observations</div>
                <div class="ss-metric-value">—</div>
                <div class="ss-metric-subtext">Sample view only</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">History window</div>
                <div class="ss-metric-value">—</div>
                <div class="ss-metric-subtext">Actual file required</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Peak risk</div>
                <div class="ss-metric-value">—</div>
                <div class="ss-metric-subtext">Not computed from actual data</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Data source</div>
                <div class="ss-metric-value" style="font-size:1.3rem;">CSV</div>
                <div class="ss-metric-subtext">Configured history path</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Risk timeline")
    st.caption("This chart is schematic only; no scan-history CSV was available in the inspected project folder.")

    timeline_df = pd.DataFrame({
        "sample": ["sample T1", "sample T2", "sample T3", "sample T4"],
        "risk": [28.0, 56.0, 48.0, 82.0],
    })
    render_line_chart(timeline_df, "sample", "risk", color="#3c50e0")

    st.markdown(
        """
        <div class="ss-warning-callout" style="margin-top:0.5rem; margin-bottom:1.5rem;">
            Illustrative line only; do not present these points as measured scan history.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Stored observations")
    history_file = ROOT / "scan_history.csv"
    if history_file.exists():
        history = read_csv(history_file)
        if not history.empty:
            render_html_table(history.tail(20).iloc[::-1])
        else:
            st.markdown('<div class="ss-empty">No actual scan-history file was present when this preview was generated. Run the application and save a scan to populate this page.</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="ss-empty">No actual scan-history file was present when this preview was generated. Run the application and save a scan to populate this page.</div>', unsafe_allow_html=True)

    render_footer()


# ─────────────────────────────────────────────────────────────────────────────
# 09. Reports & Export (Matches PDF Page 9)
# ─────────────────────────────────────────────────────────────────────────────
def page_reports(df: pd.DataFrame, is_demo: bool = True) -> None:
    render_topbar_and_header(
        "Security Reports",
        "Security Reports",
        "Generate and download comprehensive PDF threat detection and security audit reports.",
        is_demo=is_demo,
    )

    levels = df.get("Threat_Level", pd.Series(index=df.index, dtype=str)).astype(str).str.upper()
    crit = int(levels.eq("CRITICAL").sum())
    high = int(levels.eq("HIGH").sum())
    safe = int(levels.eq("SAFE").sum())
    med = int(levels.eq("MEDIUM").sum())
    avg_risk = f"{risk_series(df).mean():.1f}%" if not df.empty else "0.0%"

    st.markdown(
        f"""
        <div class="ss-metric-grid-4">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Networks in report</div>
                <div class="ss-metric-value">{len(df)}</div>
                <div class="ss-metric-subtext">Active scan observations</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">High / critical</div>
                <div class="ss-metric-value">{high + crit}</div>
                <div class="ss-metric-subtext">Prioritized threat findings</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Critical threats</div>
                <div class="ss-metric-value">{crit}</div>
                <div class="ss-metric-subtext">Immediate action required</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Average risk</div>
                <div class="ss-metric-value">{avg_risk}</div>
                <div class="ss-metric-subtext">Scan-derived composite risk</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Official PDF Security Audit Report")
    st.caption("Generate an authoritative, tamper-evident PDF report covering all scan observations, ML ensemble evaluations, fingerprint baselines, threat intelligence, and alerts.")

    with st.container(border=True):
        r_col1, r_col2 = st.columns([3, 2])
        with r_col1:
            st.markdown("#### Report Configuration & Scope")
            st.write(f"- **Target Dataset:** `{len(df)} Access Point observations` ({safe} Safe, {med} Medium, {high} High, {crit} Critical)")
            st.write(f"- **Machine Learning Evidence:** Random Forest, KNN, and Isolation Forest feature scores included")
            st.write(f"- **Fingerprint & Intelligence Baselines:** Stored BSSID vendor identities, trust records, and reputation cache")
            st.write(f"- **Output Format:** High-resolution vector PDF (Landscape A4)")

        with r_col2:
            st.markdown("#### Generate & Download")
            gen = st.button("📄 Generate Project PDF Report", type="primary", use_container_width=True)
            if gen:
                try:
                    from report_generator import ReportGenerator
                    with st.spinner("Compiling security telemetry and rendering PDF..."):
                        report_path = Path(ReportGenerator().generate_pdf_report(df))
                        report_bytes = report_path.read_bytes()
                        st.session_state["sentinelshield_latest_report"] = {
                            "name": report_path.name,
                            "bytes": report_bytes,
                            "size_kb": len(report_bytes) / 1024.0,
                            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        }
                    st.success("✅ PDF report generated successfully!")
                except Exception as exc:
                    st.error(f"PDF report generation failed: {exc}")

            latest_report = st.session_state.get("sentinelshield_latest_report")
            if latest_report:
                st.caption(f"Latest: `{latest_report['name']}` ({latest_report.get('size_kb', 0):.1f} KB) at {latest_report.get('generated_at', '')}")
                st.download_button(
                    "⬇ Download PDF Report",
                    data=latest_report["bytes"],
                    file_name=latest_report["name"],
                    mime="application/pdf",
                    use_container_width=True,
                )
            else:
                st.button("⬇ Download PDF Report", disabled=True, use_container_width=True)

    st.markdown(
        """
        <div class="ss-table-footer" style="margin-top:1rem; font-size:0.8rem; color:var(--muted);">
            <b>Note on Data Authenticity:</b> SentinelShield security reports are compiled strictly from active RF scan telemetry, validated fingerprint stores, and local model inference. CSV report export has been deprecated in favor of cryptographically auditable PDF delivery.
        </div>
        """,
        unsafe_allow_html=True,
    )
    render_footer()


# ─────────────────────────────────────────────────────────────────────────────
# 10. System Diagnostics Page (Matches PDF Page 10)
# ─────────────────────────────────────────────────────────────────────────────
def page_diagnostics(df: pd.DataFrame, is_demo: bool = True) -> None:
    render_topbar_and_header(
        "System Diagnostics",
        "System Diagnostics",
        "Inspect system settings and the status of configured supporting components.",
        is_demo=is_demo,
    )

    settings, evidence, intelligence, reports, adaptive = st.tabs(["Settings", "Evidence review", "Threat intelligence", "Reports", "Adaptive thresholds"])

    with settings:
        st.markdown("### Runtime configuration")
        left_col, right_col = st.columns(2, gap="medium")

        with left_col.container(border=True):
            st.markdown("#### Scanning")
            st.selectbox("Default profile", ["Quick Scan + adaptive verification", "Quick discovery only", "Balanced discovery", "Deep verification"], index=0)
            st.text_input("Continuous scan target interval", value="5 seconds", disabled=True)
            st.text_input("Automatic refresh", value="Disabled", disabled=True)

        with right_col.container(border=True):
            st.markdown("#### Operational health")
            health_rows = [
                ("Wi-Fi adapter", '<span class="badge-pill-gray" style="background:#fee2e2; color:#991b1b;">Not checked</span>'),
                ("Current scan CSV", '<span class="badge-pill-gray" style="background:#fee2e2; color:#991b1b;">Not found</span>' if not SCAN_FILE.exists() else '<span class="badge-loaded">Found</span>'),
                ("Fingerprint store", '<span class="badge-loaded">Configured path</span>'),
                ("Adaptive threshold state", '<span class="badge-loaded">Configured path</span>'),
                ("Notification credentials", '<span class="badge-pill-gray" style="background:#fef3c7; color:#92400e;">Environment dependent</span>'),
            ]
            health_html = '<div style="display:flex; flex-direction:column; gap:0.65rem; padding-top:0.25rem;">'
            for label, badge in health_rows:
                health_html += f'<div style="display:flex; justify-content:space-between; align-items:center; font-size:0.83rem; font-weight:600; color:var(--ink);"><span>{label}</span>{badge}</div>'
            health_html += '</div>'
            st.markdown(health_html, unsafe_allow_html=True)

        st.markdown(
            """
            <div class="ss-warning-callout" style="margin-top:1.2rem;">
                <strong>Configuration notes:</strong> This screenshot is a static preview. Actual health states must come from the running dashboard's diagnostics and local environment checks.
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.divider()
        page_settings()

    with evidence:
        page_evidence_review(df)
    with intelligence:
        page_intelligence(df)
    with reports:
        page_reports(df, is_demo=is_demo)
    with adaptive:
        page_adaptive()

    render_footer()


# ─────────────────────────────────────────────────────────────────────────────
# Attack Simulator & Ancillary Tools
# ─────────────────────────────────────────────────────────────────────────────
def page_attack_simulator(df: pd.DataFrame) -> None:
    render_topbar_and_header(
        "Attack Simulator",
        "⚡ Attack Simulation Lab",
        "Interactive software-defined wireless attack injection engine. Simulates Evil Twin, security downgrade, deauthentication bursts, and blacklisted rogue APs in real time.",
        is_demo=False,
    )

    try:
        from attack_simulator import AttackSimulator, ATTACK_SCENARIOS
    except ImportError:
        st.error("Attack simulator module (attack_simulator.py) not found.")
        return

    sim = AttackSimulator(ROOT)
    scenario_keys = list(ATTACK_SCENARIOS.keys())
    scenario_names = [ATTACK_SCENARIOS[k]["name"] for k in scenario_keys]

    selected_idx = st.selectbox(
        "Select Attack Scenario to Inject",
        range(len(scenario_keys)),
        format_func=lambda i: scenario_names[i],
    )
    scenario_key = scenario_keys[selected_idx]
    scenario = ATTACK_SCENARIOS[scenario_key]

    with st.container(border=True):
        st.markdown(f"**Attack Vector Description:** {scenario['description']}")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Spoofed Rogue MAC", scenario["spoofed_bssid"])
        c2.metric("Injected Power", f"{scenario['rssi']:.0f} dBm")
        c3.metric("Deauth Jamming", "ACTIVE ⚠️" if scenario.get("deauth_burst") else "Inactive")
        c4.metric("Threat Feed Status", "BLACKLISTED 🚨" if scenario.get("cloud_threat") else "Clean")
        st.caption(f"**Anticipated Defensive Signatures:** {', '.join(scenario['expected_findings'])}")

    available_ssids = [s for s in df["SSID"].dropna().unique().tolist() if s and str(s).strip() and str(s) != "Unknown"] if not df.empty else ["Campus-WiFi", "Library_Guest"]
    col_t1, col_t2 = st.columns(2)
    with col_t1:
        target_mode = st.radio("Target Strategy", ["Clone an active network from scan", "Specify custom SSID name"], horizontal=True)
    with col_t2:
        if target_mode == "Clone an active network from scan" and available_ssids:
            target_ssid = st.selectbox("Network to Impersonate", available_ssids)
        else:
            target_ssid = st.text_input("Custom SSID to Spoof", value="Campus_Corporate_WLAN")

    col_btn1, col_btn2 = st.columns([1, 1])
    with col_btn1:
        if st.button("🚀 Launch Attack Simulation", type="primary", width="stretch"):
            with st.spinner("Injecting simulated attack observation into SentinelShield pipeline..."):
                if "clean_scan_backup" not in st.session_state or st.session_state["clean_scan_backup"] is None:
                    st.session_state["clean_scan_backup"] = df.copy()

                simulated_df = sim.generate_attack_scan(scenario_key, df, target_ssid)
                st.session_state["scan"] = simulated_df
                simulated_df.to_csv(SCAN_FILE, index=False)
                st.session_state["last_processed_scan_mtime"] = SCAN_FILE.stat().st_mtime
                process_alerts(simulated_df)
                st.session_state["simulation_active"] = scenario["name"]
                st.success(f"Attack scenario '{scenario['name']}' injected successfully!")
                st.rerun()

    with col_btn2:
        if st.button("🔄 Restore Clean Scan (Stop Attack)", width="stretch"):
            if "clean_scan_backup" in st.session_state and st.session_state["clean_scan_backup"] is not None:
                st.session_state["scan"] = st.session_state["clean_scan_backup"]
                st.session_state["scan"].to_csv(SCAN_FILE, index=False)
                st.session_state["clean_scan_backup"] = None
            st.session_state["simulation_active"] = None
            st.info("Simulation halted. Clean real-time scanner state restored.")
            st.rerun()

    if st.session_state.get("simulation_active"):
        st.error(f"⚡ ACTIVE SIMULATION: {st.session_state['simulation_active']} is currently active in the observation table.")

    st.subheader("Simulated Attack Detection Breakdown")
    rogue_matches = df[df["BSSID"].astype(str).str.startswith("DE:AD:BE:EF")] if not df.empty else pd.DataFrame()
    if not rogue_matches.empty:
        r = rogue_matches.iloc[0]
        st.markdown(
            f"""
            <div style="border-left: 5px solid #ef4444; padding: 14px; background: rgba(239,68,68,0.1); border-radius: 6px; margin-bottom: 15px;">
                <h4 style="margin:0 0 6px 0; color:#ef4444;">🚨 DETECTED ROGUE ACCESS POINT: {r.get('SSID')} ({r.get('BSSID')})</h4>
                <b>Threat Level:</b> <span style="color:#ef4444; font-weight:bold;">{r.get('Threat_Level')}</span> &nbsp;|&nbsp; 
                <b>Combined Risk:</b> {number(r.get('Combined_Risk')):.1f}% &nbsp;|&nbsp; 
                <b>ML Fake Probability:</b> {number(r.get('Meta_Confidence')):.1f}% &nbsp;|&nbsp; 
                <b>Isolation Forest:</b> {'ANOMALY (-1)' if number(r.get('Isolation_Forest')) == -1 else 'Normal'}
                <br><br>
                <b>Detection Reasons:</b> {r.get('Reasons')}
            </div>
            """,
            unsafe_allow_html=True,
        )


def page_evidence_review(df: pd.DataFrame) -> None:
    st.header("Evidence Review")
    if df.empty:
        st.info("Run a scan or load saved scan data first.")
        return
    index = st.selectbox("Finding", list(df.index), format_func=lambda i: f"{df.loc[i].get('SSID', 'Unknown')} ({df.loc[i].get('BSSID', 'N/A')})")
    row = df.loc[index]
    narrative = explain({"ssid": row.get("SSID"), "bssid": row.get("BSSID"), "threat_level": row.get("Threat_Level"), "reasons": str(row.get("Reasons", "")).split("; ")})
    st.info(narrative["summary"])
    st.caption(narrative["recommended_action"])
    verdict = st.selectbox("Analyst verdict", ["LEGITIMATE", "ROGUE", "INVESTIGATE"])
    note = st.text_input("Investigation note (optional)", max_chars=1000)
    if st.button("Save analyst verdict"):
        item = record_feedback(str(row.get("BSSID", "")), verdict, note=note)
        try:
            import database_manager
            database_manager.save_analyst_feedback(item)
        except Exception:
            pass
        st.success("Verdict saved separately from baseline trust.")


def page_intelligence(df: pd.DataFrame) -> None:
    render_topbar_and_header(
        "Threat Intelligence",
        "Threat Intelligence",
        "Correlate local Wi-Fi observations against global threat intelligence feeds and reputation databases.",
        is_demo=st.session_state.get("demo_mode", False),
    )

    try:
        from threat_intelligence import CloudThreatIntelligence
        ti = CloudThreatIntelligence()
        status = ti.status()
    except Exception as exc:
        status = {"enabled": False, "error": str(exc), "local_external_cache_entries": 0, "reputation_hits": 0}

    # Load cache data for stats
    cache_path = Path("threat_intelligence_cache.json")
    cache_data = {}
    if cache_path.is_file():
        try:
            cache_data = json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            cache_data = {}

    total_cached = len(cache_data)
    hits_count = 0
    latest_check = "None recorded"
    for bssid, providers in cache_data.items():
        if isinstance(providers, dict):
            for p_name, p_info in providers.items():
                if isinstance(p_info, dict):
                    if p_info.get("hit"):
                        hits_count += 1
                    t = p_info.get("checked_at", "")
                    if t and (latest_check == "None recorded" or t > latest_check):
                        latest_check = t

    if latest_check != "None recorded" and len(latest_check) >= 19:
        latest_check_fmt = latest_check[:19].replace("T", " ") + " UTC"
    else:
        latest_check_fmt = latest_check

    # Top metrics row
    st.markdown(
        f"""
        <div class="ss-metric-grid-4">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Cached Intelligence</div>
                <div class="ss-metric-value">{total_cached}</div>
                <div class="ss-metric-subtext">Known BSSID records</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Reputation Hits</div>
                <div class="ss-metric-value">{hits_count}</div>
                <div class="ss-metric-subtext">Flagged threat matches</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Latest Check</div>
                <div class="ss-metric-value" style="font-size:1.05rem; font-weight:700;">{latest_check_fmt}</div>
                <div class="ss-metric-subtext">Most recent provider sync</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Cloud Sync</div>
                <div class="ss-metric-value">{"ACTIVE" if status.get("enabled") else "STANDALONE"}</div>
                <div class="ss-metric-subtext">Local cache fallback operational</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Threat Intelligence Feeds & Providers")
    prov_c1, prov_c2, prov_c3, prov_c4 = st.columns(4)

    vt_key = bool(os.getenv("VIRUSTOTAL_API_KEY"))
    ab_key = bool(os.getenv("ABUSEIPDB_API_KEY"))

    with prov_c1.container(border=True):
        st.markdown(f"**VirusTotal API**")
        st.markdown(f"<span class='badge-{'safe' if vt_key else 'neutral'}'>{'READY' if vt_key else 'UNCONFIGURED'}</span>", unsafe_allow_html=True)
        st.caption("BSSID / MAC network location reputation lookup.")

    with prov_c2.container(border=True):
        st.markdown(f"**AbuseIPDB API**")
        st.markdown(f"<span class='badge-{'safe' if ab_key else 'neutral'}'>{'READY' if ab_key else 'UNCONFIGURED'}</span>", unsafe_allow_html=True)
        st.caption("Gateway IP & network block attack reporting.")

    with prov_c3.container(border=True):
        st.markdown(f"**OpenPhish Feed**")
        st.markdown("<span class='badge-safe'>ACTIVE</span>", unsafe_allow_html=True)
        st.caption("Phishing & rogue captive portal domain correlation.")

    with prov_c4.container(border=True):
        st.markdown(f"**Firebase Cloud**")
        st.markdown(f"<span class='badge-{'safe' if status.get('enabled') else 'neutral'}'>{'CONNECTED' if status.get('enabled') else 'LOCAL CACHE'}</span>", unsafe_allow_html=True)
        st.caption("Distributed multi-sensor threat sharing.")

    if not vt_key and not ab_key:
        st.info("ℹ️ **Provider Configuration**: Community feeds (OpenPhish) and local reputation stores are active. Set `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` in environment variables or `.env` to enable real-time external API queries.")

    st.markdown("### Live Network Reputation Check")
    st.caption("Perform an on-demand threat intelligence verification for any detected access point or candidate BSSID.")

    c_sel, c_btn = st.columns([3, 1])
    bssid_options = []
    if not df.empty and "BSSID" in df.columns:
        for _, row in df.iterrows():
            bssid = str(row.get("BSSID", "")).strip().upper()
            ssid = str(row.get("SSID", "<hidden>")).strip()
            if bssid and bssid != "UNKNOWN":
                bssid_options.append(f"{bssid} ({ssid})")

    selected_choice = c_sel.selectbox(
        "Select Access Point from Scan or enter manually",
        options=bssid_options if bssid_options else ["No active scan networks"],
        key="ti_bssid_select",
    )

    custom_bssid = st.text_input("Or enter custom MAC/BSSID (e.g. AA:BB:CC:DD:EE:FF):", "")
    target_bssid = custom_bssid.strip().upper() if custom_bssid.strip() else (selected_choice.split(" ")[0] if selected_choice and " " in selected_choice else "")

    if c_btn.button("🔍 Check BSSID Reputation", type="primary", use_container_width=True):
        if target_bssid and ":" in target_bssid:
            with st.spinner(f"Querying threat intelligence providers for `{target_bssid}`..."):
                try:
                    from cloud_providers import check_bssid_all_providers
                    res = check_bssid_all_providers(target_bssid)
                    st.session_state["latest_ti_check"] = {"bssid": target_bssid, "result": res}
                    st.success(f"Reputation check completed for `{target_bssid}`.")
                except Exception as exc:
                    st.error(f"Reputation lookup failed: {exc}")
        else:
            st.warning("Please select a valid BSSID or enter a MAC address with colon separators.")

    latest_check_result = st.session_state.get("latest_ti_check")
    if latest_check_result and latest_check_result.get("bssid") == target_bssid:
        res = latest_check_result["result"]
        st.markdown(f"#### Results for `{target_bssid}`")
        res_c1, res_c2, res_c3 = st.columns(3)
        for col, p_name in zip([res_c1, res_c2, res_c3], ["VirusTotal", "AbuseIPDB", "OpenPhish"]):
            with col.container(border=True):
                p_val = res.get(p_name, {})
                st.markdown(f"**{p_name}**")
                if p_val.get("hit"):
                    st.error(f"🚨 MATCH FOUND (Risk: {p_val.get('risk_score', 0):.0f}%)")
                elif p_val.get("error"):
                    st.caption(f"Status: {p_val.get('error')}")
                else:
                    st.success("✅ Clean / No Threat Indicators Found")

    st.markdown("### Threat Intelligence Records Cache")
    st.caption("Persisted threat intelligence telemetry and previously verified BSSID reputation records.")

    if cache_data:
        table_rows = []
        # Build mapping of BSSID -> SSID from df
        bssid_to_ssid = {}
        if not df.empty and "BSSID" in df.columns:
            for _, r in df.iterrows():
                bssid_to_ssid[str(r.get("BSSID", "")).strip().upper()] = str(r.get("SSID", "<hidden>"))

        for bssid, provs in cache_data.items():
            ssid = bssid_to_ssid.get(bssid, "<offline/cached>")
            if isinstance(provs, dict):
                for p_name, p_data in provs.items():
                    if isinstance(p_data, dict):
                        is_hit = p_data.get("hit", False)
                        risk = p_data.get("risk_score", 0.0)
                        err = p_data.get("error")
                        status_str = "MATCH (THREAT)" if is_hit else ("UNCONFIGURED" if err else "CLEAN")
                        table_rows.append({
                            "BSSID": bssid,
                            "SSID": ssid,
                            "Provider": p_name,
                            "Status": status_str,
                            "Risk Score": f"{risk:.1f}%",
                            "Last Checked": str(p_data.get("checked_at", ""))[:19].replace("T", " "),
                            "Details": err or ("Phishing/Rogue indicator match" if is_hit else "No negative reputation reported"),
                        })
        if table_rows:
            render_html_table(pd.DataFrame(table_rows).head(50))
    else:
        st.info("No threat-intelligence records in local cache. Configure an approved provider or perform a scan to populate external reputation records.")

    st.markdown(
        """
        <div class="ss-table-footer" style="margin-top:1rem; font-size:0.8rem; color:var(--muted);">
            <b>Evidence Fusion Policy:</b> Verified external threat intelligence matches add up to +25 points to the composite network risk score without double-counting. Lookup failures and missing API keys are recorded transparently and never penalize safe access points.
        </div>
        """,
        unsafe_allow_html=True,
    )
    render_footer()


def page_adaptive() -> None:
    st.header("📈 Adaptive Detection Thresholds")
    summary = engine().summary()
    a, b, c = st.columns(3)
    a.metric("Mode", summary["mode"].replace("_", " ").title())
    b.metric("Samples learned", summary["samples_seen"])
    c.metric("Warm-up target", summary["warmup_samples"])
    a, b, c = st.columns(3)
    a.metric("Medium and above", f"{summary['thresholds']['medium']:.1f}%")
    b.metric("High and above", f"{summary['thresholds']['high']:.1f}%")
    c.metric("Critical", f"{summary['thresholds']['critical']:.1f}%")


def page_settings() -> None:
    st.header("⚙️ System Settings")
    config = load_runtime_config()
    scan_cfg = config["fast_scanning"]
    temporal_cfg = config["temporal_analysis"]
    context_cfg = config["optional_context"]
    st.subheader("Fast and adaptive scan settings")
    fast, balanced, deep = st.columns(3)
    scan_cfg["settle_seconds"]["fast"] = fast.slider("Fast wait (s)", 0.2, 2.0, float(scan_cfg["settle_seconds"]["fast"]), 0.05)
    scan_cfg["settle_seconds"]["balanced"] = balanced.slider("Balanced wait (s)", 0.3, 3.0, float(scan_cfg["settle_seconds"]["balanced"]), 0.05)
    scan_cfg["settle_seconds"]["deep"] = deep.slider("Deep verification wait (s)", 0.5, 4.0, float(scan_cfg["settle_seconds"]["deep"]), 0.1)
    scan_cfg["max_parallel_adapters"] = st.slider("Maximum parallel Wi-Fi adapters", 1, 8, int(scan_cfg["max_parallel_adapters"]))

    if st.button("Save scanner and evidence settings", type="primary"):
        if save_runtime_config(config):
            st.session_state.pop("scan_controller", None)
            st.success("Settings saved atomically.")


# ─────────────────────────────────────────────────────────────────────────────
# Main Application Entry Point
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    if "pending_demo_mode" in st.session_state:
        st.session_state["demo_mode"] = st.session_state.pop("pending_demo_mode")

    defaults = {
        "alerts": [],
        "alert_keys": set(),
        "critical_alerts_enabled": True,
        "alert_on_high": True,
        "sound_enabled": True,
        "desktop_enabled": True,
        "auto_refresh_enabled": False,
        "dark_theme": False,
        "demo_mode": not (SCAN_FILE.exists() and SCAN_FILE.stat().st_size > 50),
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    scan_mtime = SCAN_FILE.stat().st_mtime if SCAN_FILE.exists() else 0
    scan_modified = scan_mtime != st.session_state.get("last_loaded_scan_mtime", -1)

    if SCAN_FILE.exists() and SCAN_FILE.stat().st_size > 50:
        if "scan" not in st.session_state or scan_modified or st.session_state.get("auto_refresh_enabled"):
            st.session_state["scan"] = classify(normalise(read_csv(SCAN_FILE)))
            st.session_state["last_loaded_scan_mtime"] = scan_mtime
            process_alerts(st.session_state["scan"])

    if st.session_state["auto_refresh_enabled"] and st_autorefresh:
        st_autorefresh(interval=5000, key="sentinelshield_refresh")

    is_demo = is_demo_active()
    if is_demo:
        df = pd.DataFrame(SAMPLE_NETWORKS)
    else:
        df = st.session_state.get("scan", pd.DataFrame())
        if df.empty and SCAN_FILE.exists() and SCAN_FILE.stat().st_size > 50:
            df = classify(normalise(read_csv(SCAN_FILE)))
            st.session_state["scan"] = df

    # ── Sidebar Console Navigation ──────────────────────────────────────────
    st.sidebar.markdown("### SentinelShield")
    st.sidebar.caption("SECURITY OPERATIONS CONSOLE")

    col_t1, col_t2 = st.sidebar.columns(2)
    col_t1.toggle("Dark theme", key="dark_theme")
    col_t2.toggle("Demo view", key="demo_mode")

    apply_color_scheme(st.session_state["dark_theme"])

    pages = [
        "Overview",
        "Live Scan",
        "⚡ Attack Simulator",
        "Networks",
        "Threat Analysis",
        "ML Detection",
        "🧠 Behavioral Intelligence",
        "☁️ Threat Intelligence",
        "⚙️ Adaptive Thresholds",
        "Alerts",
        "Scan History",
        "Reports Export",
        "System Diagnostics",
    ]
    page = st.sidebar.radio("Navigation", pages, label_visibility="collapsed")

    st.sidebar.divider()
    st.sidebar.caption("CURRENT SCAN")
    st.sidebar.markdown(f"**Networks detected**\n# {len(df)}")
    crit_high = int(df.get("Threat_Level", pd.Series(index=df.index, dtype=str)).isin(["HIGH", "CRITICAL"]).sum())
    st.sidebar.caption(f"{crit_high} high / critical")

    controller = st.session_state.get("scan_controller")
    scanner_state = controller.status() if controller else {"status": "idle", "adapter_mode": "local adapter"}
    st.sidebar.caption(f"Scanner {str(scanner_state.get('status', 'IDLE')).upper()} · {scanner_state.get('adapter_mode', 'local adapter')}")
    st.sidebar.caption("Refresh reads saved results only; it never begins a scan.")

    # ── Page Routing ────────────────────────────────────────────────────────
    routes = {
        "Overview": lambda: page_home(df, is_demo=is_demo),
        "Live Scan": lambda: page_live_scan(df, is_demo=is_demo),
        "⚡ Attack Simulator": lambda: page_attack_simulator(df),
        "Networks": lambda: page_networks(df, is_demo=is_demo),
        "Threat Analysis": lambda: page_threat_analysis(df, is_demo=is_demo),
        "ML Detection": lambda: page_ai(df, is_demo=is_demo),
        "🧠 Behavioral Intelligence": render_behavioral_dashboard or (lambda: st.info("Behavioral Intelligence module loading...")),
        "☁️ Threat Intelligence": lambda: page_intelligence(df),
        "⚙️ Adaptive Thresholds": page_adaptive,
        "Alerts": lambda: page_alerts(df, is_demo=is_demo),
        "Scan History": lambda: page_scan_history(is_demo=is_demo),
        "Reports Export": lambda: page_reports(df, is_demo=is_demo),
        "System Diagnostics": lambda: page_diagnostics(df, is_demo=is_demo),
    }

    routes[page]()


if __name__ == "__main__":
    main()
