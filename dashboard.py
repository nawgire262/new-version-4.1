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

import altair as alt
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
        if search_query:
            mask = view.astype(str).apply(lambda col: col.str.contains(search_query, case=False, regex=False)).any(axis=1)
            view = view[mask]
        if threat_filter != "All threat levels":
            view = view[view["Threat_Level"].astype(str).str.upper() == threat_filter]
        if sec_filter != "All security types":
            view = view[view["Security"].astype(str).str.contains(sec_filter, case=False, na=False)]

        st.markdown("#### Detected access points")
        st.caption("Sample observations with network identifiers and risk classifications.")
        render_html_table(
            view,
            ["SSID", "BSSID", "RSSI", "Channel", "Frequency", "Security", "Vendor", "Combined_Risk", "Threat_Level"],
            {"Combined_Risk": "RISK", "Threat_Level": "THREAT LEVEL"},
        )

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

    levels = df.get("Threat_Level", pd.Series(index=df.index, dtype=str)).astype(str).str.upper()
    crit_count = int(levels.eq("CRITICAL").sum())
    high_count = int(levels.eq("HIGH").sum())
    med_count = int(levels.eq("MEDIUM").sum())
    total = len(df)

    st.markdown(
        f"""
        <div class="ss-metric-grid-4">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Findings analyzed</div>
                <div class="ss-metric-value">{total}</div>
                <div class="ss-metric-subtext">Demo observations</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Medium risk</div>
                <div class="ss-metric-value">{med_count}</div>
                <div class="ss-metric-subtext">Review indicators</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">High risk</div>
                <div class="ss-metric-value">{high_count}</div>
                <div class="ss-metric-subtext">Multiple indicators</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Critical risk</div>
                <div class="ss-metric-value">{crit_count}</div>
                <div class="ss-metric-subtext">Illustrative only</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Risk & evidence review")
    left, right = st.columns(2, gap="medium")

    with left.container(border=True):
        st.markdown(
            """
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                <h4 style="margin:0;">Selected finding: Campus-WiFi</h4>
                <span class="badge-critical">CRITICAL</span>
            </div>
            <div style="display:flex; align-items:center; gap:1.2rem; margin-bottom:1.2rem;">
                <div style="width:58px; height:58px; border-radius:50%; background:#fef2f2; border:2px solid #ef4444; color:#b91c1c; font-size:1.5rem; font-weight:800; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
                    88
                </div>
                <div>
                    <div style="font-weight:700; font-size:1rem; color:var(--ink);">Potential SSID clone</div>
                    <div style="font-size:0.78rem; color:var(--muted); line-height:1.25; margin-top:0.2rem;">
                        Sample risk score: not validated attack evidence.<br>Investigate identity and security differences against a trusted baseline.
                    </div>
                </div>
            </div>
            <div style="font-size:0.82rem; font-weight:700; margin-bottom:0.4rem; color:var(--ink);">Available evidence</div>
            <ul style="font-size:0.8rem; color:var(--muted); padding-left:1.2rem; line-height:1.6; margin:0;">
                <li>SSID resembles a previously observed network</li>
                <li>Security type differs from the baseline</li>
                <li>Fingerprint comparison requires analyst review</li>
                <li>RSSI observations vary across sample readings</li>
            </ul>
            """,
            unsafe_allow_html=True,
        )

    with right.container(border=True):
        st.markdown("#### Risk scoring components")
        st.caption("Illustrative evidence contributions")
        bars = [
            ("Fingerprint mismatch", 78),
            ("Security mismatch", 70),
            ("Temporal RSSI change", 46),
            ("AP density indicator", 31),
            ("ML model evidence", 61),
        ]
        for name, pct in bars:
            st.markdown(
                f"""
                <div class="ss-progress-row">
                    <div class="ss-progress-label-row">
                        <span>{name}</span>
                        <span>{pct}%</span>
                    </div>
                    <div class="ss-progress-track">
                        <div class="ss-progress-fill" style="width:{pct}%;"></div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("### Risk assessment queue")
    render_html_table(
        df,
        ["SSID", "BSSID", "Combined_Risk", "Threat_Level", "Evidence_Summary"],
        {"Combined_Risk": "RISK", "Threat_Level": "THREAT LEVEL", "Evidence_Summary": "EVIDENCE SUMMARY"},
    )
    render_footer()


# ─────────────────────────────────────────────────────────────────────────────
# 05. ML Detection Page (Matches PDF Page 5)
# ─────────────────────────────────────────────────────────────────────────────
def page_ai(df: pd.DataFrame, is_demo: bool = True) -> None:
    render_topbar_and_header(
        "ML Detection",
        "ML Detection",
        "Inspect the hybrid detection layer and review available model prediction evidence.",
        is_demo=is_demo,
    )

    c1, c2, c3 = st.columns(3)
    with c1.container(border=True):
        st.markdown(
            """
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-weight:700; font-size:0.95rem; color:var(--ink);">Random Forest</span>
                <span class="badge-loaded">LOADED+</span>
            </div>
            <div style="font-size:1.15rem; font-weight:700; margin:0.35rem 0 0.15rem; color:var(--accent);">Classifier</div>
            <div style="font-size:0.78rem; color:var(--muted); line-height:1.3;">Produces a class prediction from the supplied network feature vector.</div>
            <div style="font-size:0.7rem; color:#94a3b8; margin-top:0.4rem;">*Illustrative interface label; live loading not verified here.</div>
            """,
            unsafe_allow_html=True,
        )

    with c2.container(border=True):
        st.markdown(
            """
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-weight:700; font-size:0.95rem; color:var(--ink);">K-Nearest Neighbors</span>
                <span class="badge-loaded">LOADED+</span>
            </div>
            <div style="font-size:1.15rem; font-weight:700; margin:0.35rem 0 0.15rem; color:var(--accent);">Classifier</div>
            <div style="font-size:0.78rem; color:var(--muted); line-height:1.3;">Compares observations with learned examples in feature space.</div>
            <div style="font-size:0.7rem; color:#94a3b8; margin-top:0.4rem;">*Illustrative interface label; live loading not verified here.</div>
            """,
            unsafe_allow_html=True,
        )

    with c3.container(border=True):
        st.markdown(
            """
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-weight:700; font-size:0.95rem; color:var(--ink);">Isolation Forest</span>
                <span class="badge-anomaly">ANOMALY</span>
            </div>
            <div style="font-size:1.15rem; font-weight:700; margin:0.35rem 0 0.15rem; color:#d97706;">Outlier score</div>
            <div style="font-size:0.78rem; color:var(--muted); line-height:1.3;">Flags observations that differ from learned normal patterns.</div>
            <div style="font-size:0.7rem; color:#94a3b8; margin-top:0.4rem;">*Not the same as a confirmed malicious label.</div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### Model outputs by access point")
    st.caption("Illustrative examples only; scores below are not model test results.")

    ml_rows = [
        {"SSID": "Campus-WiFi", "RF OUTPUT": "Legitimate", "KNN OUTPUT": "Legitimate", "IF OUTPUT": "Normal", "ENSEMBLE EVIDENCE": "Low risk evidence", "REVIEW STATUS": "Review baseline"},
        {"SSID": "Library_Guest", "RF OUTPUT": "Legitimate", "KNN OUTPUT": "Uncertain", "IF OUTPUT": "Anomaly", "ENSEMBLE EVIDENCE": "Mixed indicators", "REVIEW STATUS": "Investigate"},
        {"SSID": "Campus-WiFi (new BSSID)", "RF OUTPUT": "Fake-like", "KNN OUTPUT": "Fake-like", "IF OUTPUT": "Anomaly", "ENSEMBLE EVIDENCE": "Multiple indicators", "REVIEW STATUS": "Investigate"},
        {"SSID": "CoffeeGuest", "RF OUTPUT": "Legitimate", "KNN OUTPUT": "Legitimate", "IF OUTPUT": "Normal", "ENSEMBLE EVIDENCE": "Fingerprint consistent", "REVIEW STATUS": "Low priority"},
    ]
    render_html_table(pd.DataFrame(ml_rows))

    st.markdown("### Model explanation")
    with st.container(border=True):
        st.markdown(
            """
            <div style="font-weight:700; font-size:0.95rem; margin-bottom:0.4rem; color:var(--ink);">Explanation summary</div>
            <div style="font-size:0.84rem; color:var(--muted); line-height:1.45; margin-bottom:0.8rem;">
                Example reasoning: Security-type mismatch and fingerprint differences contribute to the displayed risk. This is an illustrative explanation, not a measured feature-attribution result.
            </div>
            <div class="ss-warning-callout" style="margin-top:0;">
                Model accuracy, precision, recall, F1-score, and false-positive rate must be calculated using a valid held-out dataset with verified labels.
            </div>
            """,
            unsafe_allow_html=True,
        )
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

    st.markdown(
        """
        <div class="ss-metric-grid-4">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Stored fingerprints</div>
                <div class="ss-metric-value">18</div>
                <div class="ss-metric-subtext">Illustrative count</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Trusted baselines</div>
                <div class="ss-metric-value">12</div>
                <div class="ss-metric-subtext">Example profiles</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">New observations</div>
                <div class="ss-metric-value">4</div>
                <div class="ss-metric-subtext">Not automatically trusted</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Changed fingerprints</div>
                <div class="ss-metric-value">2</div>
                <div class="ss-metric-subtext">Illustrative review queue</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Access point baseline records")
    st.caption("Representative view of fingerprint fields visible in the application code.")
    render_html_table(pd.DataFrame(SAMPLE_FINGERPRINTS))

    st.markdown("### Selected fingerprint")
    with st.container(border=True):
        st.markdown(
            """
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                <span style="font-weight:700; font-size:1.05rem; color:var(--ink);">Campus-WiFi · A4:5E:60:2A:11:90</span>
                <span class="badge-trusted">TRUSTED EXAMPLE</span>
            </div>
            <div style="display:flex; gap:2.5rem; margin-bottom:1.2rem; flex-wrap:wrap;">
                <div>
                    <div style="font-size:0.75rem; color:var(--muted); font-weight:600;">Mean RSSI</div>
                    <div style="font-size:1.35rem; font-weight:750; color:var(--ink);">-49 dBm</div>
                </div>
                <div>
                    <div style="font-size:0.75rem; color:var(--muted); font-weight:600;">RSSI variance</div>
                    <div style="font-size:1.35rem; font-weight:750; color:var(--ink);">3.8</div>
                </div>
                <div>
                    <div style="font-size:0.75rem; color:var(--muted); font-weight:600;">Last seen</div>
                    <div style="font-size:1.15rem; font-weight:700; color:var(--ink); margin-top:0.15rem;">Today 10:42</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        b1, b2, b3 = st.columns(3)
        b1.button("View differences", width="stretch")
        b2.button("Refresh profile", width="stretch")
        b3.button("Mark trusted after verification", width="stretch")


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
            <strong>Illustrative alert:</strong> A sample access point exceeds the example critical-risk threshold. Confirm the observation against a trusted baseline before taking action.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="ss-metric-grid-4">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Alerts this session</div>
                <div class="ss-metric-value">3</div>
                <div class="ss-metric-subtext">Demo only</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Critical</div>
                <div class="ss-metric-value">1</div>
                <div class="ss-metric-subtext">Needs review</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">High</div>
                <div class="ss-metric-value">1</div>
                <div class="ss-metric-subtext">Needs review</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Notifications configured</div>
                <div class="ss-metric-value">2/4</div>
                <div class="ss-metric-subtext">Illustrative status</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Recent alert records")
    render_html_table(pd.DataFrame(SAMPLE_ALERTS))

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
        "System Diagnostics",
        "System Diagnostics",
        "Access reports and export options from available scan data.",
        is_demo=is_demo,
    )

    levels = df.get("Threat_Level", pd.Series(index=df.index, dtype=str)).astype(str).str.upper()
    crit = int(levels.eq("CRITICAL").sum())
    high = int(levels.eq("HIGH").sum())
    avg_risk = f"{risk_series(df).mean():.1f}%" if not df.empty else "39.3%"

    st.markdown(
        f"""
        <div class="ss-metric-grid-4">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Networks in report</div>
                <div class="ss-metric-value">{len(df)}</div>
                <div class="ss-metric-subtext">Illustrative summary</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">High / critical</div>
                <div class="ss-metric-value">{high + crit}</div>
                <div class="ss-metric-subtext">Sample values</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Critical</div>
                <div class="ss-metric-value">{crit}</div>
                <div class="ss-metric-subtext">Sample values</div>
            </div>
            <div class="ss-metric-card">
                <div class="ss-metric-label">Average risk</div>
                <div class="ss-metric-value">{avg_risk}</div>
                <div class="ss-metric-subtext">Calculated only from sample entries</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Reports & export")
    c1, c2 = st.columns(2)
    with c1.container(border=True):
        st.markdown("#### Scan export")
        st.caption("Export the current scan observations for external analysis and record keeping.")
        st.download_button("⬇ Download scan CSV", df.to_csv(index=False).encode(), "sentinelshield_scan.csv", "text/csv", width="stretch")

    with c2.container(border=True):
        st.markdown("#### Summary export")
        st.caption("Export a compact summary containing network counts and risk metrics.")
        summary_df = pd.DataFrame({
            "Metric": ["Networks", "Safe", "Medium", "High", "Critical", "Average risk"],
            "Value": [len(df), int(levels.eq("SAFE").sum()), int(levels.eq("MEDIUM").sum()), high, crit, avg_risk],
        })
        st.download_button("⬇ Download summary CSV", summary_df.to_csv(index=False).encode(), "sentinelshield_summary.csv", "text/csv", width="stretch")

    st.markdown("### PDF report")
    st.caption("Generate a report from current scan and threat-assessment records.")
    p1, p2 = st.columns(2)
    gen = p1.button("Generate project PDF report", type="primary", width="stretch")
    if gen:
        try:
            from report_generator import ReportGenerator
            report_path = Path(ReportGenerator().generate_pdf_report(df))
            report_bytes = report_path.read_bytes()
            st.session_state["sentinelshield_latest_report"] = {"name": report_path.name, "bytes": report_bytes}
            st.success("PDF report generated successfully.")
        except Exception as exc:
            st.error(f"PDF report generation failed: {exc}")

    latest_report = st.session_state.get("sentinelshield_latest_report")
    if latest_report:
        p2.download_button("⬇ Download PDF report", data=latest_report["bytes"], file_name=latest_report["name"], mime="application/pdf", width="stretch")
    else:
        p2.button("Download PDF report", disabled=True, width="stretch")

    st.markdown(
        """
        <div class="ss-warning-callout">
            No report was generated by these static screenshots; use the running application to create and verify the PDF.
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
    st.header("☁️ Threat Intelligence")
    st.caption("Reputation checks are run automatically per-AP at the end of each live scan when API keys are configured.")
    try:
        status = get_threat_intelligence().status() if get_threat_intelligence else {"enabled": False, "error": "Module unavailable"}
    except Exception as exc:
        status = {"enabled": False, "error": str(exc)}
    a, b, c = st.columns(3)
    a.metric("Firebase cloud", "YES" if status.get("enabled") else "NO")
    b.metric("Cloud threats (Firestore)", status.get("total_cloud_threats", 0))
    c.metric("Reputation hits", status.get("reputation_hits", 0))


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
