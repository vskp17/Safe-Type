"""
Unit Tests for SafeType Detection Rules Evaluation
"""

import pytest
from safetype.db.models import EventRecord, PersistenceRecord, ProcessRecord
from safetype.engine.detection_rules import DetectionRules


def test_input_monitoring_rule():
    evt = EventRecord(
        pid=111,
        event_type="INPUT_MONITORING_BEHAVIOR",
        description="user32 reference in untrusted folder",
    )
    res = DetectionRules.evaluate_input_monitoring([evt])
    assert res is not None
    assert res.score_contrib == 35
    assert res.rule_id == "INPUT_MONITORING_BEHAVIOR"


def test_persistence_rule():
    proc = ProcessRecord(pid=222, name="bad.exe", exe_path="C:\\Temp\\bad.exe")
    p = PersistenceRecord(
        pid=222,
        name="BadStart",
        type="Startup Folder",
        location="Startup\\bad.exe",
        details="C:\\Temp\\bad.exe",
        is_suspicious=True,
    )
    res = DetectionRules.evaluate_persistence(proc, [p])
    assert res is not None
    assert res.score_contrib == 25


def test_unusual_location_rule():
    evt = EventRecord(
        pid=333,
        event_type="UNUSUAL_EXE_LOCATION",
        description="Executing from AppData Temp",
    )
    res = DetectionRules.evaluate_unusual_location([evt])
    assert res is not None
    assert res.score_contrib == 20


def test_ancestry_rule():
    evt = EventRecord(
        pid=444,
        event_type="SUSPICIOUS_ANCESTRY",
        description="Spawned by powershell.exe",
    )
    res = DetectionRules.evaluate_ancestry([evt])
    assert res is not None
    assert res.score_contrib == 15
