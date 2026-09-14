"""
SafeType - Defensive Windows Security
Publication & Research Edition Streamlit Web Application
Integrated with Process Quarantine, HTML/PDF Incident Reports, and Network Telemetry.
"""

import json
import logging
from datetime import datetime, timezone
import sys
from pathlib import Path

# Ensure repository root is on sys.path for Streamlit Cloud deployment
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from safetype.config import DEFAULT_DB_PATH, SEVERITY_COLORS
from safetype.db.database import Database
from safetype.db.models import ProcessRecord
from safetype.collectors.process_collector import ProcessCollector
from safetype.collectors.behavior_collector import BehaviorCollector
from safetype.collectors.persistence_collector import PersistenceCollector
from safetype.collectors.network_collector import NetworkCollector
from safetype.engine.risk_engine import RiskEngine
from safetype.utils.report_generator import generate_html_report, generate_json_report

logger = logging.getLogger("SafeType.Dashboard")


def inject_custom_css():
    st.markdown("""
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

            html, body, [class*="css"] {
                font-family: 'Inter', sans-serif;
            }

            .main {
                background-color: #080C14;
                color: #F1F5F9;
            }

            .stApp {
                background: radial-gradient(circle at 50% 0%, #0F172A 0%, #080C14 100%);
            }

            /* Metric Cards */
            div[data-testid="metric-container"] {
                background: rgba(15, 23, 42, 0.75);
                border: 1px solid rgba(56, 189, 248, 0.12);
                border-radius: 12px;
                padding: 18px 22px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
                backdrop-filter: blur(12px);
                transition: transform 0.25s ease, border-color 0.25s ease;
            }

            div[data-testid="metric-container"]:hover {
                border-color: rgba(56, 189, 248, 0.4);
                transform: translateY(-3px);
            }

            /* Sidebar Styling */
            section[data-testid="stSidebar"] {
                background-color: #05080E;
                border-right: 1px solid rgba(255, 255, 255, 0.08);
            }

            /* Header Title */
            .safetype-title {
                font-size: 2.3rem;
                font-weight: 800;
                background: linear-gradient(90deg, #38BDF8 0%, #818CF8 50%, #C084FC 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 0.2rem;
                letter-spacing: -0.5px;
            }

            .safetype-subtitle {
                font-size: 0.95rem;
                color: #94A3B8;
                margin-bottom: 1.6rem;
            }

            /* Badges */
            .badge-low {
                background-color: rgba(0, 230, 118, 0.15);
                color: #00E676;
                padding: 4px 10px;
                border-radius: 6px;
                font-weight: 600;
                border: 1px solid rgba(0, 230, 118, 0.3);
            }
            .badge-medium {
                background-color: rgba(255, 193, 7, 0.15);
                color: #FFC107;
                padding: 4px 10px;
                border-radius: 6px;
                font-weight: 600;
                border: 1px solid rgba(255, 193, 7, 0.3);
            }
            .badge-high {
                background-color: rgba(255, 145, 0, 0.15);
                color: #FF9100;
                padding: 4px 10px;
                border-radius: 6px;
                font-weight: 600;
                border: 1px solid rgba(255, 145, 0, 0.3);
            }
            .badge-critical {
                background-color: rgba(255, 23, 68, 0.15);
                color: #FF1744;
                padding: 4px 10px;
                border-radius: 7px;
                font-weight: 700;
                border: 1px solid rgba(255, 23, 68, 0.4);
            }

            /* Safety Alert Banner */
            .safety-banner {
                background: rgba(56, 189, 248, 0.06);
                border: 1px solid rgba(56, 189, 248, 0.25);
                border-radius: 10px;
                padding: 14px 20px;
                margin-bottom: 22px;
                font-size: 0.9rem;
                color: #38BDF8;
                box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            }
        </style>
    """, unsafe_allow_html=True)


def run_live_scan(db: Database):
    """Run live telemetry scanning on the host system."""
    with st.spinner("Scanning active system processes, network sockets, behavior telemetry, and startup persistence..."):
        p_collector = ProcessCollector()
        b_collector = BehaviorCollector()
        pers_collector = PersistenceCollector()
        net_collector = NetworkCollector()
        risk_engine = RiskEngine()

        procs = p_collector.collect_processes()
        pers_records = pers_collector.collect_persistence()
        net_conns = net_collector.collect_network_connections()

        for p in pers_records:
            db.add_persistence(p)

        for proc in procs:
            db.upsert_process(proc)
            events = b_collector.analyze_process(proc, procs, net_conns)
            for e in events:
                db.add_event(e)

            detection = risk_engine.evaluate_process(proc, events, pers_records)
            db.add_detection(detection)

    st.success(f"Successfully evaluated live system telemetry for {len(procs)} active processes.")


def handle_quarantine(pid: int, process_name: str, exe_path: str, db: Database):
    """Execute process quarantine, binary file deletion, and database score reset."""
    p_collector = ProcessCollector()
    try:
        success = p_collector.kill_process(pid, exe_path)
    except TypeError:
        try:
            success = p_collector.kill_process(pid)
        except Exception as e:
            logger.error(f"Quarantine error for PID {pid}: {e}")
            success = False
    except Exception as e:
        logger.error(f"Quarantine error for PID {pid}: {e}")
        success = False

    # Update risk score to 0 (LOW) and remove process record in database
    db.quarantine_detection(pid)

    if success:
        st.success(f"🛑 Process PID {pid} ('{process_name}') terminated and binary file quarantined. Risk score updated to 0 (LOW).")
    else:
        st.warning(f"Process PID {pid} updated to 0 (LOW) in database. Binary file quarantine attempted.")

    st.info("💡 **Recommendation**: Please click '**⚡ Scan Live System Telemetry**' in the sidebar to run a scan again and refresh your active inventory.")


def render_dashboard_page(db: Database):
    st.markdown('<div class="safetype-title">SafeType Overview</div>', unsafe_allow_html=True)
    st.markdown('<div class="safetype-subtitle">Defensive process telemetry, input monitoring detection, and risk analytics</div>', unsafe_allow_html=True)

    processes = db.get_processes()
    detections = db.get_detections()
    persistence = db.get_persistence_records()

    if not detections:
        st.info("Initializing first live system telemetry scan...")
        run_live_scan(db)
        st.rerun()
        return

    total_procs = len(processes) if processes else len(set(d["pid"] for d in detections))
    active_alerts = sum(1 for d in detections if d["severity_level"] in ["HIGH", "CRITICAL"])
    high_risk_count = sum(1 for d in detections if d["risk_score"] >= 60)
    susp_persistence_count = sum(1 for p in persistence if p["is_suspicious"])

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Processes Scanned", total_procs)
    with col2:
        st.metric("Active Threat Alerts", active_alerts, delta="Threats Found" if active_alerts > 0 else "System Clean", delta_color="inverse")
    with col3:
        st.metric("High-Risk Processes", high_risk_count)
    with col4:
        st.metric("Suspicious Persistence", susp_persistence_count)

    st.markdown("<br>", unsafe_allow_html=True)

    c1, c2 = st.columns([1, 1.3])

    with c1:
        st.subheader("Risk Distribution Spectrum")
        df_det = pd.DataFrame(detections)
        if not df_det.empty and "severity_level" in df_det.columns:
            sev_counts = df_det["severity_level"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]

            fig = px.pie(
                sev_counts,
                values="Count",
                names="Severity",
                hole=0.55,
                color="Severity",
                color_discrete_map=SEVERITY_COLORS,
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#F1F5F9"),
                showlegend=True,
                margin=dict(t=20, b=20, l=20, r=20),
            )
            st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.subheader("Recent Evaluated Detections")
        if not df_det.empty:
            display_cols = ["pid", "process_name", "risk_score", "severity_level"]
            df_disp = df_det[display_cols].copy()
            df_disp.columns = ["PID", "Process Name", "Risk Score", "Severity"]
            st.dataframe(
                df_disp,
                use_container_width=True,
                hide_index=True,
                height=300,
            )


def render_processes_page(db: Database):
    st.markdown('<div class="safetype-title">Process Telemetry Inventory</div>', unsafe_allow_html=True)
    st.markdown('<div class="safetype-subtitle">Complete list of system processes and evaluated behavioral risk parameters</div>', unsafe_allow_html=True)

    processes = db.get_processes()
    detections = db.get_detections()
    det_map = {d["pid"]: d for d in detections}

    records = []
    if processes:
        for p in processes:
            det = det_map.get(p["pid"], {})
            records.append({
                "PID": p["pid"],
                "Process Name": p["name"],
                "Executable Path": p["exe_path"],
                "Risk Score": det.get("risk_score", 0),
                "Severity": det.get("severity_level", "LOW"),
                "User Context": p.get("username", "Unknown"),
                "Status": p.get("status", "running"),
            })
    else:
        for d in detections:
            records.append({
                "PID": d["pid"],
                "Process Name": d["process_name"],
                "Executable Path": d["exe_path"],
                "Risk Score": d["risk_score"],
                "Severity": d["severity_level"],
                "User Context": "N/A",
                "Status": "active",
            })

    df = pd.DataFrame(records)

    if df.empty:
        st.info("No processes currently logged. Run a live scan.")
        return

    f1, f2 = st.columns([2, 1])
    with f1:
        search_query = st.text_input("🔍 Search process by Name or PID", "")
    with f2:
        sev_filter = st.multiselect("Severity Filter", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=["LOW", "MEDIUM", "HIGH", "CRITICAL"])

    filtered_df = df[df["Severity"].isin(sev_filter)]

    if search_query:
        filtered_df = filtered_df[
            filtered_df["Process Name"].str.contains(search_query, case=False, na=False)
            | filtered_df["PID"].astype(str).str.contains(search_query)
        ]

    st.dataframe(filtered_df, use_container_width=True, hide_index=True, height=450)


def render_alerts_page(db: Database):
    st.markdown('<div class="safetype-title">Active Threat Alerts</div>', unsafe_allow_html=True)
    st.markdown('<div class="safetype-subtitle">Filtered view of HIGH and CRITICAL risk process behavior and mitigation playbooks</div>', unsafe_allow_html=True)

    detections = db.get_detections()
    alerts = [d for d in detections if d["severity_level"] in ["HIGH", "CRITICAL", "MEDIUM"]]

    if not alerts:
        st.success("No active HIGH or CRITICAL threat alerts detected. SafeType status clean!")
        return

    for alert in alerts:
        sev = alert["severity_level"]
        badge_class = f"badge-{sev.lower()}"
        reasons = json.loads(alert["detection_reasons_json"])
        actions = json.loads(alert["recommended_actions_json"])

        with st.expander(f"[{sev}] PID {alert['pid']} - {alert['process_name']} (Risk Score: {alert['risk_score']}/100)", expanded=(sev in ["HIGH", "CRITICAL"])):
            st.markdown(f"**Executable Path**: `{alert['exe_path']}`")
            st.markdown(f"**Severity Level**: <span class='{badge_class}'>{sev}</span>", unsafe_allow_html=True)

            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Detection Reasons & Behavioral Telemetry:**")
                for r in reasons:
                    st.markdown(f"- {r}")

            with c2:
                st.markdown("**Recommended Defensive Playbook:**")
                for a in actions:
                    st.markdown(f"- 🛡️ {a}")

            # 1-Click Quarantine Button
            if st.button(f"🛑 Terminate & Quarantine PID {alert['pid']}", key=f"q_alert_{alert['pid']}"):
                handle_quarantine(alert["pid"], alert["process_name"], alert["exe_path"], db)
                st.rerun()


def render_investigation_page(db: Database):
    st.markdown('<div class="safetype-title">Process Investigation & Threat Report</div>', unsafe_allow_html=True)
    st.markdown('<div class="safetype-subtitle">In-depth behavioral analysis, telemetry timeline, active quarantine, and downloadable incident reports</div>', unsafe_allow_html=True)

    detections = db.get_detections()

    if not detections:
        st.info("No process telemetry records available to investigate.")
        return

    proc_options = {f"PID {d['pid']} - {d['process_name']} [{d['severity_level']}]": d['pid'] for d in detections}
    selected_label = st.selectbox("Select Process to Investigate:", list(proc_options.keys()))
    selected_pid = proc_options[selected_label]

    det = db.get_latest_detection_for_process(selected_pid)
    proc_info = db.get_process_by_pid(selected_pid) or {}
    events = db.get_events_for_process(selected_pid)

    if not det:
        st.error("Could not fetch detection record for selected PID.")
        return

    col1, col2 = st.columns([1.2, 1])

    with col1:
        st.subheader("Process Metadata Card")
        st.markdown(f"**Process Name**: `{det['process_name']}`")
        st.markdown(f"**PID**: `{det['pid']}`")
        st.markdown(f"**Executable Path**: `{det['exe_path']}`")
        if proc_info:
            st.markdown(f"**Parent PID**: `{proc_info.get('ppid', 'N/A')}`")
            st.markdown(f"**User Context**: `{proc_info.get('username', 'N/A')}`")
            st.markdown(f"**Status**: `{proc_info.get('status', 'N/A')}`")
            st.markdown(f"**Command Line**: `{proc_info.get('cmdline', 'N/A')}`")

        st.markdown("<br>", unsafe_allow_html=True)
        # 1-Click Quarantine Action
        if st.button(f"🛑 Terminate & Quarantine Process (PID {det['pid']})", key=f"q_inv_{det['pid']}"):
            handle_quarantine(det["pid"], det["process_name"], det["exe_path"], db)
            st.rerun()

        st.markdown("---")

        # Report Downloads
        r1, r2 = st.columns(2)
        with r1:
            json_report = generate_json_report(det, proc_info, events)
            st.download_button(
                label="📄 Download JSON Threat Report",
                data=json_report,
                file_name=f"safetype_report_pid_{det['pid']}.json",
                mime="application/json",
                use_container_width=True,
            )
        with r2:
            html_report = generate_html_report(det, proc_info, events)
            st.download_button(
                label="📊 Download Executive HTML Report",
                data=html_report,
                file_name=f"safetype_audit_report_pid_{det['pid']}.html",
                mime="text/html",
                use_container_width=True,
            )

    with col2:
        st.subheader("Explainable Risk Score Gauge")
        score = det["risk_score"]
        sev = det["severity_level"]
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            title={'text': f"Severity: {sev}"},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': SEVERITY_COLORS.get(sev, "#00E676")},
                'steps': [
                    {'range': [0, 29], 'color': "rgba(0, 230, 118, 0.1)"},
                    {'range': [30, 59], 'color': "rgba(255, 193, 7, 0.1)"},
                    {'range': [60, 79], 'color': "rgba(255, 145, 0, 0.1)"},
                    {'range': [80, 100], 'color': "rgba(255, 23, 68, 0.1)"},
                ],
            }
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#F1F5F9"),
            height=250,
            margin=dict(t=30, b=10, l=30, r=30),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    c_left, c_right = st.columns(2)

    with c_left:
        st.subheader("Triggered Detection Indicators")
        indicators = json.loads(det["indicators_json"])
        reasons = json.loads(det["detection_reasons_json"])

        if not indicators:
            st.write("No suspicious behavior indicators triggered.")
        else:
            for ind, reason in zip(indicators, reasons):
                st.warning(f"**{ind}**: {reason}")

    with c_right:
        st.subheader("Recommended Defensive Actions")
        actions = json.loads(det["recommended_actions_json"])
        for act in actions:
            st.info(f"🛡️ {act}")

    st.markdown("---")
    st.subheader("Telemetry Event Timeline")

    if events:
        df_events = pd.DataFrame(events)
        fig_tl = px.scatter(
            df_events,
            x="timestamp",
            y="event_type",
            color="severity",
            hover_data=["description"],
            color_discrete_map=SEVERITY_COLORS,
            title="Telemetry Event Sequence Timeline",
        )
        fig_tl.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#F1F5F9"),
            height=280,
        )
        st.plotly_chart(fig_tl, use_container_width=True)
    else:
        st.write("No sub-events logged for this process.")


def render_about_page():
    st.markdown('<div class="safetype-title">About SafeType Framework</div>', unsafe_allow_html=True)
    st.markdown('<div class="safetype-subtitle">Publication-Grade Defensive Windows Security Framework for Detecting Unauthorized Input Monitoring</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="safety-banner">
        🛡️ <strong>Zero-Trust Privacy & Safety Guarantee</strong>: SafeType NEVER records, transmits, logs, or inspects raw keystrokes, typed text, passwords, or user credentials. SafeType operates strictly on live process metadata, execution paths, loaded system modules, network telemetry, static YARA signatures, and persistence configurations.
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs([
        "🏛️ Architectural Pillars",
        "⚖️ Threat Detection Matrix",
        "🔒 Zero-Trust Safety Theorem",
        "🛡️ SOC Incident Playbook",
    ])

    with tab1:
        st.subheader("Core Architectural Layering")
        st.markdown("""
        SafeType employs a 6-layer decoupled pipeline designed for enterprise endpoint resilience:

        1. **Process Collector**: Enumerates live Windows processes (`psutil`), retrieving PIDs, executable paths, parent PIDs, user contexts, and launch parameters while gracefully handling protected system tasks.
        2. **Network Telemetry Collector**: Inspects active TCP/UDP sockets (`psutil.net_connections`), flagging untrusted binaries establishing outbound connections (`OUTBOUND_NETWORK_EXFILTRATION`).
        3. **YARA & Binary Hash Engine**: Computes cryptographic hashes (SHA-256 / MD5) and performs static heuristic scans for keylogging API strings (`SetWindowsHookEx`, `GetAsyncKeyState`, `GetForegroundWindow`).
        4. **Persistence Inspector**: Audits Windows autorun registries (`HKCU`/`HKLM` Run keys) and Start Menu startup folders for unauthorized launch configurations.
        5. **Explainable Risk Engine**: Computes an explainable 0–100 score governed by the **Multi-Indicator Safety Theorem** (capping single-indicator processes at max score 55).
        6. **Active Quarantine & Report Exporter**: Provides 1-click process termination (`psutil.kill`), binary file deletion, score resets to 0 (LOW), and executive JSON/HTML audit reports.
        """)

    with tab2:
        st.subheader("Explainable Risk Engine Weight Matrix")
        st.markdown("""
        | Indicator ID | Description | Score Weight ($w_i$) | Playbook Action |
        | :--- | :--- | :---: | :--- |
        | `INPUT_MONITORING_BEHAVIOR` | Untrusted binary referencing input/windowing hooks | **+35** | Inspect window hooks & terminate process |
        | `YARA_SIGNATURE_MATCH` | Heuristic match for keylogging API strings | **+25** | Quarantine binary executable file |
        | `SUSPICIOUS_PERSISTENCE` | Startup Run key / Startup folder entry targeting Temp/AppData | **+25** | Remove Registry Run key / Startup entry |
        | `OUTBOUND_NETWORK_EXFILTRATION` | Active outbound socket connection from untrusted binary | **+20** | Block remote IP at host firewall |
        | `UNUSUAL_EXE_LOCATION` | Binary executing from Temp, Public, or Downloads folder | **+20** | Relocate binary out of temporary path |
        | `UNUSUAL_PROCESS_CONTEXT` | SYSTEM privilege execution from user directory | **+15** | Audit account privileges & tokens |
        | `MISSING_SIGNATURE` | Executable metadata/version signature missing in user folder | **+15** | Perform code signature verification |
        | `SUSPICIOUS_ANCESTRY` | Binary spawned by background script interpreter (cmd/powershell) | **+15** | Trace parent process tree for attack vector |
        """)

    with tab3:
        st.subheader("Mathematical Safety Formulation")
        st.markdown("""
        ### Risk Score Accumulation
        $$S_{\\text{raw}}(p) = \\sum_{i \\in \\mathcal{T}(p)} w_i$$

        ### Multi-Indicator Safety Theorem
        To eliminate false positives on benign background tools, a process **must trigger at least 2 distinct indicators** to reach `HIGH` (≥60) or `CRITICAL` (≥80) severity:

        $$S_{\\text{final}}(p) = \\begin{cases} \\min(S_{\\text{raw}}(p), 55), & \\text{if } |\\mathcal{T}(p)| \\le 1 \\\\ \\min(S_{\\text{raw}}(p), 100), & \\text{if } |\\mathcal{T}(p)| \\ge 2 \\end{cases}$$

        ### Severity Bands
        - **0 – 29 (`LOW`)**: Standard system operation.
        - **30 – 59 (`MEDIUM`)**: Behavioral anomaly detected; monitor process.
        - **60 – 79 (`HIGH`)**: Suspicious process; audit lineage & sockets.
        - **80 – 100 (`CRITICAL`)**: Immediate process termination & file quarantine required.
        """)

    with tab4:
        st.subheader("SOC Incident Response Protocol")
        st.markdown("""
        When SafeType detects a `HIGH` or `CRITICAL` process threat:

        1. **1-Click Quarantine**: Click `[ 🛑 Terminate & Quarantine Process ]` on the Alerts or Investigation page to kill the running PID and attempt binary deletion.
        2. **Database Reset**: SafeType automatically sets the process risk score to `0` (`LOW`) and removes the PID from active inventory.
        3. **Executive Audit Export**: Download the structured **JSON Threat Report** or **Executive HTML Report** for compliance logging.
        4. **Live Re-Scan**: Click `[ ⚡ Scan Live System Telemetry ]` in the sidebar to refresh host endpoint inventory.
        """)


def main():
    st.set_page_config(
        page_title="SafeType - Defensive Security",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    inject_custom_css()
    db = Database(DEFAULT_DB_PATH)

    st.sidebar.markdown("## 🛡️ SafeType")
    st.sidebar.markdown("*SafeType Defensive Security*")
    st.sidebar.markdown("---")

    nav_selection = st.sidebar.radio(
        "Navigation",
        ["Dashboard", "Processes", "Alerts", "Investigation", "About"],
        index=0,
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Telemetry Controls")

    if st.sidebar.button("⚡ Scan Live System Telemetry", use_container_width=True):
        run_live_scan(db)
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.caption("SafeType Defensive Security")

    if nav_selection == "Dashboard":
        render_dashboard_page(db)
    elif nav_selection == "Processes":
        render_processes_page(db)
    elif nav_selection == "Alerts":
        render_alerts_page(db)
    elif nav_selection == "Investigation":
        render_investigation_page(db)
    elif nav_selection == "About":
        render_about_page()


if __name__ == "__main__":
    main()
