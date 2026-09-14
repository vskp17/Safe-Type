"""
Unit Tests for SafeType Telemetry Collectors
"""

import pytest
from safetype.collectors.process_collector import ProcessCollector
from safetype.collectors.behavior_collector import BehaviorCollector
from safetype.collectors.persistence_collector import PersistenceCollector
from safetype.db.models import ProcessRecord


def test_process_collector_runs_safely():
    collector = ProcessCollector()
    processes = collector.collect_processes()
    assert isinstance(processes, list)
    assert len(processes) > 0

    first = processes[0]
    assert isinstance(first.pid, int)
    assert isinstance(first.name, str)


def test_behavior_collector_location_checks():
    bc = BehaviorCollector()

    assert bc.is_trusted_location("C:\\Windows\\System32\\svchost.exe") is True
    assert bc.is_suspicious_location("C:\\Windows\\System32\\svchost.exe") is False

    susp_path = "C:\\Users\\Test\\AppData\\Local\\Temp\\key_updater.exe"
    assert bc.is_suspicious_location(susp_path) is True
    assert bc.is_trusted_location(susp_path) is False


def test_behavior_collector_analysis():
    bc = BehaviorCollector()

    parent = ProcessRecord(
        pid=100,
        name="cmd.exe",
        exe_path="C:\\Windows\\System32\\cmd.exe",
    )

    susp_proc = ProcessRecord(
        pid=200,
        name="untrusted_payload.exe",
        exe_path="C:\\Users\\Test\\AppData\\Local\\Temp\\untrusted_payload.exe",
        ppid=100,
    )

    all_procs = [parent, susp_proc]
    events = bc.analyze_process(susp_proc, all_procs)

    assert len(events) >= 2
    event_types = [e.event_type for e in events]
    assert "UNUSUAL_EXE_LOCATION" in event_types
    assert "SUSPICIOUS_ANCESTRY" in event_types


def test_persistence_collector_runs_safely():
    pc = PersistenceCollector()
    records = pc.collect_persistence()
    assert isinstance(records, list)
