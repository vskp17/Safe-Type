"""
Unit Tests for SafeType Executive Threat Report Generator
"""

import json
import pytest
from safetype.utils.report_generator import generate_json_report, generate_html_report


def test_report_generation():
    det = {
        "pid": 8888,
        "process_name": "test_threat.exe",
        "exe_path": "C:\\Temp\\test_threat.exe",
        "risk_score": 85,
        "severity_level": "CRITICAL",
        "indicators_json": '["INPUT_MONITORING_BEHAVIOR", "UNUSUAL_EXE_LOCATION"]',
        "detection_reasons_json": '["Input hook reference", "Temp execution"]',
        "recommended_actions_json": '["Terminate process PID 8888"]',
    }

    proc_info = {
        "username": "TestUser",
        "ppid": 1000,
        "cmdline": "test_threat.exe",
    }

    events = [{"event_type": "INPUT_MONITORING_BEHAVIOR", "severity": "HIGH"}]

    json_rep = generate_json_report(det, proc_info, events)
    assert "SafeType" in json_rep
    assert "8888" in json_rep

    html_rep = generate_html_report(det, proc_info, events)
    assert "<!DOCTYPE html>" in html_rep
    assert "CRITICAL" in html_rep
    assert "test_threat.exe" in html_rep
