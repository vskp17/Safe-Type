"""
Unit Tests for SafeType Risk Engine Scoring & Severity
"""

import json
import pytest
from safetype.db.models import EventRecord, PersistenceRecord, ProcessRecord
from safetype.engine.risk_engine import RiskEngine


def test_severity_level_mapping():
    re = RiskEngine()
    assert re.calculate_severity(0) == "LOW"
    assert re.calculate_severity(29) == "LOW"
    assert re.calculate_severity(30) == "MEDIUM"
    assert re.calculate_severity(59) == "MEDIUM"
    assert re.calculate_severity(60) == "HIGH"
    assert re.calculate_severity(79) == "HIGH"
    assert re.calculate_severity(80) == "CRITICAL"
    assert re.calculate_severity(100) == "CRITICAL"


def test_single_indicator_safety_policy():
    """Verify a process with only 1 indicator is NEVER classified as HIGH or CRITICAL."""
    re = RiskEngine()
    proc = ProcessRecord(pid=1001, name="single_rule.exe", exe_path="C:\\Temp\\single_rule.exe")
    events = [
        EventRecord(
            pid=1001,
            event_type="INPUT_MONITORING_BEHAVIOR",
            description="Input hook detected in non-standard location",
            severity="HIGH",
        )
    ]

    det = re.evaluate_process(proc, events, [])
    assert det.risk_score <= 55
    assert det.severity_level in ["LOW", "MEDIUM"]
    assert det.severity_level not in ["HIGH", "CRITICAL"]


def test_multi_indicator_critical_risk():
    """Verify combining multiple indicators elevates risk score up to CRITICAL."""
    re = RiskEngine()
    proc = ProcessRecord(pid=2002, name="malicious_mock.exe", exe_path="C:\\Users\\Public\\malicious_mock.exe")

    events = [
        EventRecord(pid=2002, event_type="INPUT_MONITORING_BEHAVIOR", description="Hook reference"),
        EventRecord(pid=2002, event_type="UNUSUAL_EXE_LOCATION", description="Public folder"),
        EventRecord(pid=2002, event_type="SUSPICIOUS_ANCESTRY", description="Spawned by cmd"),
    ]

    p_rec = PersistenceRecord(
        pid=2002,
        name="MockRunKey",
        type="HKCU Run Key",
        location="HKCU\\Run\\MockRunKey",
        details="C:\\Users\\Public\\malicious_mock.exe",
        is_suspicious=True,
    )

    det = re.evaluate_process(proc, events, [p_rec])
    assert det.risk_score >= 80
    assert det.severity_level == "CRITICAL"
    indicators = json.loads(det.indicators_json)
    assert len(indicators) >= 3
