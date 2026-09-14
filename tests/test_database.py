"""
Unit Tests for SafeType Database Module
"""

import os
import tempfile
import pytest
from safetype.db.database import Database
from safetype.db.models import (
    ProcessRecord,
    EventRecord,
    PersistenceRecord,
    DetectionRecord,
)


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = Database(db_path=path)
    yield db
    if os.path.exists(path):
        os.remove(path)


def test_db_initialization(temp_db):
    processes = temp_db.get_processes()
    detections = temp_db.get_detections()
    assert processes == []
    assert detections == []


def test_process_upsert_and_retrieve(temp_db):
    proc = ProcessRecord(
        pid=1234,
        name="test_proc.exe",
        exe_path="C:\\Test\\test_proc.exe",
        ppid=1000,
        username="TestUser",
        create_time=1700000000.0,
        cmdline="test_proc.exe --run",
        status="running",
    )
    temp_db.upsert_process(proc)

    stored = temp_db.get_process_by_pid(1234)
    assert stored is not None
    assert stored["name"] == "test_proc.exe"
    assert stored["exe_path"] == "C:\\Test\\test_proc.exe"

    proc.status = "stopped"
    temp_db.upsert_process(proc)
    updated = temp_db.get_process_by_pid(1234)
    assert updated["status"] == "stopped"


def test_event_logging(temp_db):
    proc = ProcessRecord(
        pid=5678,
        name="target.exe",
        exe_path="C:\\Apps\\target.exe",
    )
    temp_db.upsert_process(proc)

    evt = EventRecord(
        pid=5678,
        event_type="UNUSUAL_LOCATION",
        description="Process running from temporary directory",
        severity="MEDIUM",
        metadata_json='{"path": "C:\\\\Apps\\\\target.exe"}',
    )
    evt_id = temp_db.add_event(evt)
    assert evt_id > 0

    events = temp_db.get_events_for_process(5678)
    assert len(events) == 1
    assert events[0]["event_type"] == "UNUSUAL_LOCATION"


def test_persistence_logging(temp_db):
    p = PersistenceRecord(
        pid=1234,
        name="TestStartup",
        type="Registry Run Key",
        location="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        details="C:\\AppData\\Temp\\bad.exe",
        is_suspicious=True,
    )
    p_id = temp_db.add_persistence(p)
    assert p_id > 0

    records = temp_db.get_persistence_records()
    assert len(records) == 1
    assert records[0]["is_suspicious"] == 1


def test_detection_storage_and_quarantine(temp_db):
    proc = ProcessRecord(
        pid=9999,
        name="suspicious.exe",
        exe_path="C:\\Temp\\suspicious.exe",
    )
    temp_db.upsert_process(proc)

    det = DetectionRecord(
        pid=9999,
        process_name="suspicious.exe",
        exe_path="C:\\Temp\\suspicious.exe",
        risk_score=85,
        severity_level="CRITICAL",
        indicators_json='["INPUT_MONITORING_BEHAVIOR", "UNUSUAL_EXE_LOCATION"]',
        detection_reasons_json='["Input hook DLL referenced", "Running from temp"]',
        recommended_actions_json='["Terminate process", "Investigate persistence"]',
    )
    det_id = temp_db.add_detection(det)
    assert det_id > 0

    detections = temp_db.get_detections()
    assert len(detections) == 1
    assert detections[0]["risk_score"] == 85
    assert detections[0]["severity_level"] == "CRITICAL"

    # Perform quarantine
    temp_db.quarantine_detection(9999)
    q_det = temp_db.get_latest_detection_for_process(9999)
    assert q_det["risk_score"] == 0
    assert q_det["severity_level"] == "LOW"

    # Process record removed
    assert temp_db.get_process_by_pid(9999) is None
