#!/usr/bin/env python3
"""
SmartTriage Dashboard (Streamlit)

Views:
- 📊 Overview      → based on final_scored.csv (risky files)
- 📁 Artifacts     → detailed risk view (final_scored.csv)
- 🧳 Quarantine    → quarantined files (quarantine folder)
- 🌐 Network / IP  → remote IP + abuse score (from final_scored.csv)
- 📜 Logs          → incident & remediation logs
- 📑 Report & Email→ PDF report + SMTP email (env-based, no user input)
- 📂 Raw Artifacts → all collected artifacts (preprocessed.csv)
- 🧮 Anomalies     → all artifacts with risk labels (anomalies.csv)
"""

import os
import pathlib
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from datetime import datetime

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

# PDF generation
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm

# -------------------------------------------------------------------
# Paths & config
# -------------------------------------------------------------------
ROOT = pathlib.Path.cwd()
PROCESSED_DIR = ROOT / "processed_data"

FINAL_CSV = PROCESSED_DIR / "final_scored.csv"         # risk-focused output
PREPROCESSED_CSV = PROCESSED_DIR / "preprocessed.csv"  # all collected artifacts
ANOMALIES_CSV = PROCESSED_DIR / "anomalies.csv"        # all artifacts + risk labels

QUARANTINE_DIR = PROCESSED_DIR / "quarantine"
LOG_INCIDENT = ROOT / "incident_logs.txt"
LOG_REMEDIATION = ROOT / "remediation_logs.txt"

REPORTS_DIR = ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Load environment variables
load_dotenv(ROOT / ".env")

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECIPIENT_DEFAULT = os.getenv("EMAIL_RECIPIENT", "")

# -------------------------------------------------------------------
# Data loading helpers
# -------------------------------------------------------------------
@st.cache_data
def load_final_df():
    """Risk-focused artifacts: final_scored.csv (suspicious/malicious + some others)."""
    if not FINAL_CSV.exists():
        return pd.DataFrame()
    df = pd.read_csv(FINAL_CSV)

    # Normalize risk
    if "risk" in df.columns:
        df["risk"] = df["risk"].astype(str).str.lower()
    else:
        df["risk"] = "unknown"

    # Ensure some useful columns exist
    for col in ["file_name", "file_path"]:
        if col not in df.columns:
            df[col] = ""

    for col in ["vt_score", "abuse_score"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

    if "remote_ip" not in df.columns:
        df["remote_ip"] = ""

    return df


@st.cache_data
def load_preprocessed_df():
    """All collected artifacts from the first step (data acquisition → preprocess)."""
    if not PREPROCESSED_CSV.exists():
        return pd.DataFrame()
    df = pd.read_csv(PREPROCESSED_CSV)

    for col in ["file_name", "file_path"]:
        if col not in df.columns:
            df[col] = ""

    return df


@st.cache_data
def load_anomalies_df():
    """All artifacts with heuristic risk labels (clean / suspicious / malicious)."""
    if not ANOMALIES_CSV.exists():
        return pd.DataFrame()
    df = pd.read_csv(ANOMALIES_CSV)

    for col in ["file_name", "file_path"]:
        if col not in df.columns:
            df[col] = ""

    if "risk" in df.columns:
        df["risk"] = df["risk"].astype(str).str.lower()
    else:
        df["risk"] = "clean"

    return df


@st.cache_data
def load_quarantine_df():
    """Quarantined file info from processed_data/quarantine."""
    rows = []
    if QUARANTINE_DIR.exists():
        for p in sorted(QUARANTINE_DIR.iterdir()):
            if not p.is_file():
                continue
            fname = p.name
            parts = fname.split("_", 1)
            ts = None
            if len(parts) == 2 and parts[0].isdigit():
                try:
                    ts = datetime.fromtimestamp(int(parts[0]))
                except Exception:
                    ts = None
                original_name = parts[1]
            else:
                original_name = fname
            rows.append(
                {
                    "quarantined_path": str(p.resolve()),
                    "original_name": original_name,
                    "quarantined_at": ts.isoformat() if ts else "",
                }
            )
    return pd.DataFrame(rows)


@st.cache_data
def read_tail(path: pathlib.Path, max_lines: int = 200):
    if not path.exists():
        return ""
    try:
        with path.open(encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        return "".join(lines[-max_lines:])
    except Exception as e:
        return f"Failed to read {path.name}: {e}"

# -------------------------------------------------------------------
# PDF report helpers
# -------------------------------------------------------------------
def generate_pdf_report(df: pd.DataFrame, quarantine_df: pd.DataFrame) -> pathlib.Path:
    """
    Create an A4 PDF report summarizing risk stats and top suspicious/malicious entries.
    Uses final_scored-based dataframe (df).
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = REPORTS_DIR / f"cyber_triage_report_{timestamp}.pdf"

    c = canvas.Canvas(str(pdf_path), pagesize=A4)
    width, height = A4

    margin_left = 2 * cm
    margin_top = height - 2 * cm
    line_height = 14

    def draw_line(text, x, y, style="normal"):
        if style == "title":
            c.setFont("Helvetica-Bold", 18)
        elif style == "subtitle":
            c.setFont("Helvetica-Bold", 12)
        else:
            c.setFont("Helvetica", 10)
        c.drawString(x, y, text)

    y = margin_top

    # Title
    draw_line("SmartTriage System Report", margin_left, y, style="title")
    y -= 2 * line_height
    draw_line(f"Generated at: {datetime.now().isoformat(sep=' ', timespec='seconds')}", margin_left, y)
    y -= 2 * line_height

    if df.empty:
        draw_line("No data available in final_scored.csv", margin_left, y)
        c.showPage()
        c.save()
        return pdf_path

    # Overview stats
    total_files = len(df)
    risk_counts = df["risk"].value_counts().to_dict()
    clean_count = risk_counts.get("clean", 0)
    suspicious_count = risk_counts.get("suspicious", 0)
    malicious_count = risk_counts.get("malicious", 0)
    unknown_count = risk_counts.get("unknown", 0)

    draw_line("Overview (risk-focused files)", margin_left, y, style="subtitle")
    y -= 1.5 * line_height
    draw_line(f"Total files in final_scored: {total_files}", margin_left, y)
    y -= line_height
    draw_line(f"Clean: {clean_count}", margin_left, y)
    y -= line_height
    draw_line(f"Suspicious: {suspicious_count}", margin_left, y)
    y -= line_height
    draw_line(f"Malicious: {malicious_count}", margin_left, y)
    y -= line_height
    draw_line(f"Unknown: {unknown_count}", margin_left, y)
    y -= 2 * line_height

    if not quarantine_df.empty:
        draw_line("Quarantine Summary", margin_left, y, style="subtitle")
        y -= 1.5 * line_height
        draw_line(f"Total quarantined files: {len(quarantine_df)}", margin_left, y)
        y -= 2 * line_height

    # Top suspicious/malicious entries
    dangerous = df[df["risk"].isin(["suspicious", "malicious"])].copy()
    if not dangerous.empty:
        dangerous = dangerous.sort_values(
            by=["risk", "vt_score", "abuse_score"],
            ascending=[False, False, False],
        ).head(25)

        draw_line("Top Suspicious / Malicious Files", margin_left, y, style="subtitle")
        y -= 1.5 * line_height

        c.setFont("Helvetica-Bold", 9)
        headers = ["Risk", "File Name", "VT Score", "Abuse Score"]
        col_widths = [2.0 * cm, 7.0 * cm, 2.5 * cm, 2.5 * cm]
        x_positions = [margin_left]
        for w in col_widths[:-1]:
            x_positions.append(x_positions[-1] + w)

        for h, x in zip(headers, x_positions):
            c.drawString(x, y, h)
        y -= line_height
        c.setFont("Helvetica", 8)

        for _, row in dangerous.iterrows():
            if y < 2 * cm:
                c.showPage()
                y = margin_top

            risk = str(row.get("risk", ""))
            fname = str(row.get("file_name", ""))[:40]
            vt = str(row.get("vt_score", ""))
            abuse = str(row.get("abuse_score", ""))

            values = [risk, fname, vt, abuse]
            for val, x in zip(values, x_positions):
                c.drawString(x, y, val)
            y -= line_height

    c.showPage()
    c.save()
    return pdf_path


def send_email_with_attachment(
    smtp_host: str,
    smtp_port: int,
    sender: str,
    password: str,
    recipient: str,
    subject: str,
    body: str,
    attachment_path: pathlib.Path,
):
    if not attachment_path.exists():
        raise FileNotFoundError(f"Attachment not found: {attachment_path}")

    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    with open(attachment_path, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
    encoders.encode_base64(part)
    part.add_header(
        "Content-Disposition",
        f'attachment; filename="{attachment_path.name}"',
    )
    msg.attach(part)

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)

# -------------------------------------------------------------------
# Streamlit UI
# -------------------------------------------------------------------
st.set_page_config(
    page_title="SmartTriage Dashboard",
    layout="wide",
)

st.title("🛡️ SmartTriage – Cyber Triage Dashboard")

df_risk = load_final_df()
qdf = load_quarantine_df()

if df_risk.empty:
    st.warning(
        "No data found in processed_data/final_scored.csv.\n\n"
        "Run your pipeline first (preprocess → anomaly_detector → VT/Abuse, etc.)."
    )

tabs = st.tabs(
    [
        "📊 Overview",
        "📁 Artifacts (Risk View)",
        "🧳 Quarantine",
        "🌐 Network / IP",
        "📜 Logs",
        "📑 Report & Email",
        "📂 Raw Artifacts (Preprocess)",
        "🧮 Anomalies View",
    ]
)

# -------------------------------------------------------------------
# 📊 Overview (based on final_scored.csv)
# -------------------------------------------------------------------
with tabs[0]:
    st.subheader("Overall Risk Summary (final_scored.csv)")

    if not df_risk.empty:
        total_files = len(df_risk)
        risk_counts = df_risk["risk"].value_counts().to_dict()
        clean_count = risk_counts.get("clean", 0)
        suspicious_count = risk_counts.get("suspicious", 0)
        malicious_count = risk_counts.get("malicious", 0)
        unknown_count = risk_counts.get("unknown", 0)

        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Total files in final_scored", total_files)
        col2.metric("Clean", clean_count)
        col3.metric("Suspicious", suspicious_count)
        col4.metric("Malicious", malicious_count)
        col5.metric("Unknown", unknown_count)

        st.markdown("---")
        st.subheader("Risk Distribution")

        chart_data = (
            df_risk["risk"]
            .value_counts()
            .rename_axis("risk")
            .reset_index(name="count")
            .sort_values("risk")
        )
        chart_data = chart_data.set_index("risk")
        st.bar_chart(chart_data)
    else:
        st.info("No risk-focused data available yet.")

# -------------------------------------------------------------------
# 📁 Artifacts (Risk View)
# -------------------------------------------------------------------
with tabs[1]:
    st.subheader("Artifacts – Risk-Focused View (from final_scored.csv)")

    if df_risk.empty:
        st.info("No artifacts to display.")
    else:
        with st.expander("Filters", expanded=True):
            col_f1, col_f2, col_f3 = st.columns([2, 1, 1])

            with col_f1:
                search = st.text_input(
                    "Search by file name / path / risk (e.g., clean, suspicious, malicious)",
                    key="risk_view_search",  # UNIQUE KEY
                ).strip().lower()

            with col_f2:
                risk_options = sorted(df_risk["risk"].dropna().unique().tolist())
                selected_risks = st.multiselect(
                    "Risk level",
                    options=risk_options,
                    default=risk_options,
                    key="risk_view_risk_levels",  # UNIQUE KEY
                )

            with col_f3:
                if "vt_score" in df_risk.columns and df_risk["vt_score"].notna().any():
                    vt_min = int(df_risk["vt_score"].min())
                    vt_max = int(df_risk["vt_score"].max())
                    if vt_min == vt_max:
                        # Only one value present; avoid slider error
                        vt_range = None
                        st.caption(f"All VT scores = {vt_min}, VT filter disabled.")
                    else:
                        vt_range = st.slider(
                            "VT score range",
                            min_value=vt_min,
                            max_value=vt_max,
                            value=(vt_min, vt_max),
                        )
                else:
                    vt_range = None
                    st.caption("No VT scores available in data.")

        filtered = df_risk.copy()

        if selected_risks:
            filtered = filtered[filtered["risk"].isin(selected_risks)]

        if vt_range is not None and "vt_score" in filtered.columns:
            filtered = filtered[
                (filtered["vt_score"] >= vt_range[0])
                & (filtered["vt_score"] <= vt_range[1])
            ]

        if search:
            s = search
            mask = (
                filtered["file_name"].astype(str).str.lower().str.contains(s)
                | filtered["file_path"].astype(str).str.lower().str.contains(s)
                | filtered["risk"].astype(str).str.lower().str.contains(s)
            )
            filtered = filtered[mask]

        st.write(f"Showing **{len(filtered)}** / {len(df_risk)} records")
        st.dataframe(
            filtered.sort_values(
                by=["risk", "vt_score", "abuse_score"],
                ascending=[True, False, False],
            ),
            use_container_width=True,
            hide_index=True,
        )

# -------------------------------------------------------------------
# 🧳 Quarantine
# -------------------------------------------------------------------
with tabs[2]:
    st.subheader("Quarantined Files")

    if qdf.empty:
        st.info("No files found in the quarantine directory yet.")
    else:
        st.write(f"Total quarantined files: **{len(qdf)}**")
        st.dataframe(qdf, use_container_width=True, hide_index=True)

# -------------------------------------------------------------------
# 🌐 Network / IP
# -------------------------------------------------------------------
with tabs[3]:
    st.subheader("Remote IP & AbuseIPDB View (from final_scored.csv)")

    if df_risk.empty or "remote_ip" not in df_risk.columns:
        st.info("No remote IP information available.")
    else:
        ip_df = df_risk.copy()
        ip_df["remote_ip"] = ip_df["remote_ip"].fillna("").astype(str)
        ip_df = ip_df[ip_df["remote_ip"] != ""]
        if ip_df.empty:
            st.info("No remote IPs recorded in the data.")
        else:
            if "abuse_score" in ip_df.columns:
                agg = (
                    ip_df.groupby("remote_ip", as_index=False)
                    .agg(
                        hits=("remote_ip", "count"),
                        max_abuse=("abuse_score", "max"),
                    )
                    .sort_values(by=["max_abuse", "hits"], ascending=[False, False])
                )
            else:
                agg = (
                    ip_df.groupby("remote_ip", as_index=False)
                    .agg(hits=("remote_ip", "count"))
                    .sort_values(by="hits", ascending=False)
                )

            st.write("Summary by remote IP:")
            st.dataframe(agg, use_container_width=True, hide_index=True)

            st.markdown("---")
            st.write("Underlying rows:")
            st.dataframe(
                ip_df.sort_values(by=["abuse_score"], ascending=False),
                use_container_width=True,
                hide_index=True,
            )

# -------------------------------------------------------------------
# 📜 Logs
# -------------------------------------------------------------------
with tabs[4]:
    st.subheader("System Logs")

    col_l1, col_l2 = st.columns(2)

    with col_l1:
        st.markdown("**Incident Logs (live_monitor.py)**")
        st.caption(str(LOG_INCIDENT))
        text_inc = read_tail(LOG_INCIDENT)
        if text_inc:
            st.text_area("incident_logs.txt", text_inc, height=400)
        else:
            st.info("No incident logs found.")

    with col_l2:
        st.markdown("**Remediation Logs (remediation.py)**")
        st.caption(str(LOG_REMEDIATION))
        text_rem = read_tail(LOG_REMEDIATION)
        if text_rem:
            st.text_area("remediation_logs.txt", text_rem, height=400)
        else:
            st.info("No remediation logs found.")

# -------------------------------------------------------------------
# 📑 Report & Email (auto recipient from .env)
# -------------------------------------------------------------------
with tabs[5]:
    st.subheader("PDF Report & Email Delivery")

    if "last_report_path" not in st.session_state:
        st.session_state["last_report_path"] = ""

    st.markdown("### 1️⃣ Generate PDF Report")

    if st.button("Generate PDF report", type="primary"):
        if df_risk.empty:
            st.error("Cannot generate report: final_scored.csv is empty or missing.")
        else:
            pdf_path = generate_pdf_report(df_risk, qdf)
            st.session_state["last_report_path"] = str(pdf_path)
            st.success(f"Report generated: {pdf_path.name}")

    if st.session_state.get("last_report_path"):
        pdf_path = pathlib.Path(st.session_state["last_report_path"])
        if pdf_path.exists():
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="⬇️ Download last generated report",
                    data=f,
                    file_name=pdf_path.name,
                    mime="application/pdf",
                )

    st.markdown("---")
    st.markdown("### 2️⃣ Send Report to Default Recipient (from .env)")

    st.info(f"Report will be sent to: **{EMAIL_RECIPIENT_DEFAULT or '⛔ Not configured'}**")

    if st.button("Send Report Email"):
        if not st.session_state.get("last_report_path"):
            if df_risk.empty:
                st.error("Cannot generate or send report because final_scored.csv is empty.")
            else:
                pdf_path = generate_pdf_report(df_risk, qdf)
                st.session_state["last_report_path"] = str(pdf_path)
        pdf_path = pathlib.Path(st.session_state.get("last_report_path", ""))

        if not EMAIL_SENDER or not EMAIL_PASSWORD or not EMAIL_RECIPIENT_DEFAULT:
            st.error(
                "Email not configured properly in .env.\n"
                "Please set EMAIL_SENDER, EMAIL_PASSWORD and EMAIL_RECIPIENT."
            )
        elif not pdf_path.exists():
            st.error("Report file not found. Please generate the report again.")
        else:
            try:
                send_email_with_attachment(
                    smtp_host=SMTP_HOST,
                    smtp_port=SMTP_PORT,
                    sender=EMAIL_SENDER,
                    password=EMAIL_PASSWORD,
                    recipient=EMAIL_RECIPIENT_DEFAULT,
                    subject="SmartTriage – Cyber Triage Report",
                    body="Please find attached the latest SmartTriage cyber triage report.",
                    attachment_path=pdf_path,
                )
                st.success(f"Email successfully sent to {EMAIL_RECIPIENT_DEFAULT}.")
            except Exception as e:
                st.error(f"Failed to send email: {e}")

# -------------------------------------------------------------------
# 📂 Raw Artifacts (Preprocess)
# -------------------------------------------------------------------
with tabs[6]:
    st.subheader("Raw Collected Artifacts – Preprocess Output (preprocessed.csv)")

    pre_df = load_preprocessed_df()

    if pre_df.empty:
        st.info(
            "No preprocessed.csv found or it is empty.\n"
            "Run the data acquisition + preprocess step first."
        )
    else:
        st.write(f"Total artifacts collected in preprocess step: **{len(pre_df)}**")
        st.dataframe(pre_df, use_container_width=True, hide_index=True)

# -------------------------------------------------------------------
# 🧮 Anomalies View
# -------------------------------------------------------------------
with tabs[7]:
    st.subheader("Anomaly Detector Output – All Artifacts with Risk (anomalies.csv)")

    anom_df = load_anomalies_df()

    if anom_df.empty:
        st.info(
            "No anomalies.csv found or it is empty.\n"
            "Run anomaly_detector.py first."
        )
    else:
        with st.expander("Filters", expanded=True):
            col1, col2 = st.columns([2, 1])

            with col1:
                search_anom = st.text_input(
                    "Search by file name / path / risk (e.g., clean, suspicious, malicious)",
                    key="anomalies_view_search",  # UNIQUE KEY
                ).strip().lower()

            with col2:
                risk_options_anom = sorted(anom_df["risk"].dropna().unique().tolist())
                selected_risks_anom = st.multiselect(
                    "Risk level",
                    options=risk_options_anom,
                    default=risk_options_anom,
                    key="anomalies_view_risk_levels",  # UNIQUE KEY
                )

        filtered_anom = anom_df.copy()

        if selected_risks_anom:
            filtered_anom = filtered_anom[filtered_anom["risk"].isin(selected_risks_anom)]

        if search_anom:
            s = search_anom
            mask = (
                filtered_anom["file_name"].astype(str).str.lower().str.contains(s)
                | filtered_anom["file_path"].astype(str).str.lower().str.contains(s)
                | filtered_anom["risk"].astype(str).str.lower().str.contains(s)
            )
            filtered_anom = filtered_anom[mask]

        st.write(f"Showing **{len(filtered_anom)}** / {len(anom_df)} artifacts")
        st.dataframe(filtered_anom, use_container_width=True, hide_index=True)
