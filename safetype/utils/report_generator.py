"""
SafeType Threat Report Generator Utility
Generates Executive HTML security incident reports and JSON reports.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List


def generate_json_report(det: Dict[str, Any], proc_info: Dict[str, Any], events: List[Dict[str, Any]]) -> str:
    """Generate structured JSON incident report."""
    report = {
        "framework": "SafeType Defensive Security",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_process": {
            "pid": det.get("pid"),
            "process_name": det.get("process_name"),
            "exe_path": det.get("exe_path"),
            "risk_score": det.get("risk_score"),
            "severity_level": det.get("severity_level"),
            "user_context": proc_info.get("username", "N/A"),
            "parent_pid": proc_info.get("ppid", "N/A"),
            "cmdline": proc_info.get("cmdline", "N/A"),
        },
        "triggered_indicators": json.loads(det.get("indicators_json", "[]")),
        "detection_reasons": json.loads(det.get("detection_reasons_json", "[]")),
        "recommended_defensive_actions": json.loads(det.get("recommended_actions_json", "[]")),
        "events_timeline": events,
    }
    return json.dumps(report, indent=2)


def generate_html_report(det: Dict[str, Any], proc_info: Dict[str, Any], events: List[Dict[str, Any]]) -> str:
    """Generate executive HTML security audit report."""
    pid = det.get("pid")
    name = det.get("process_name")
    exe_path = det.get("exe_path")
    score = det.get("risk_score")
    sev = det.get("severity_level")
    reasons = json.loads(det.get("detection_reasons_json", "[]"))
    actions = json.loads(det.get("recommended_actions_json", "[]"))

    sev_color = {
        "LOW": "#00E676",
        "MEDIUM": "#FFC107",
        "HIGH": "#FF9100",
        "CRITICAL": "#FF1744",
    }.get(sev, "#00E676")

    reasons_html = "".join([f"<li>{r}</li>" for r in reasons]) or "<li>No critical indicators triggered.</li>"
    actions_html = "".join([f"<li>🛡️ {a}</li>" for a in actions]) or "<li>No immediate remediation required.</li>"

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SafeType Incident Audit Report - PID {pid}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0A0E17; color: #E2E8F0; padding: 30px; }}
        .header {{ border-bottom: 2px solid #38BDF8; padding-bottom: 10px; margin-bottom: 20px; }}
        .title {{ font-size: 24px; font-weight: bold; color: #38BDF8; }}
        .badge {{ background-color: {sev_color}; color: #000; padding: 6px 12px; font-weight: bold; border-radius: 4px; font-size: 14px; display: inline-block; }}
        .card {{ background: #1E293B; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
        h3 {{ color: #94A3B8; margin-top: 0; }}
        code {{ background: #0F172A; padding: 3px 6px; border-radius: 4px; color: #38BDF8; font-family: monospace; }}
        ul {{ padding-left: 20px; }}
        li {{ margin-bottom: 8px; }}
        .footer {{ font-size: 12px; color: #64748B; margin-top: 30px; border-top: 1px solid #334155; padding-top: 10px; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">🛡️ SafeType Executive Security Incident Report</div>
        <div>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
    </div>

    <div class="card">
        <h3>Process Identification</h3>
        <p><strong>Process Name:</strong> <code>{name}</code></p>
        <p><strong>PID:</strong> <code>{pid}</code></p>
        <p><strong>Executable Path:</strong> <code>{exe_path}</code></p>
        <p><strong>User Context:</strong> <code>{proc_info.get("username", "N/A")}</code></p>
        <p><strong>Parent PID:</strong> <code>{proc_info.get("ppid", "N/A")}</code></p>
    </div>

    <div class="card">
        <h3>Evaluated Risk Score & Severity</h3>
        <p><strong>Risk Score:</strong> <span style="font-size:20px; font-weight:bold; color:{sev_color};">{score} / 100</span></p>
        <p><strong>Severity Classification:</strong> <span class="badge">{sev}</span></p>
    </div>

    <div class="card">
        <h3>Triggered Detection Reasons</h3>
        <ul>{reasons_html}</ul>
    </div>

    <div class="card">
        <h3>Recommended Defensive Actions</h3>
        <ul>{actions_html}</ul>
    </div>

    <div class="footer">
        Confidential Security Report | SafeType Defensive Security
    </div>
</body>
</html>"""
    return html
