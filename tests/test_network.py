"""
Unit Tests for SafeType Network Telemetry Collector
"""

import pytest
from safetype.collectors.network_collector import NetworkCollector
from safetype.db.models import ProcessRecord


def test_network_collector_runs_safely():
    nc = NetworkCollector()
    conns = nc.collect_network_connections()
    assert isinstance(conns, dict)


def test_network_exfiltration_detection():
    nc = NetworkCollector()
    proc = ProcessRecord(
        pid=5050,
        name="exfil_test.exe",
        exe_path="C:\\Users\\Test\\AppData\\Local\\Temp\\exfil_test.exe",
    )

    mock_conns = [
        {
            "fd": "3",
            "family": "AddressFamily.AF_INET",
            "type": "SocketKind.SOCK_STREAM",
            "local_address": "192.168.1.50:52000",
            "remote_address": "198.51.100.25:443",
            "status": "ESTABLISHED",
        }
    ]

    evt = nc.analyze_process_network_exfiltration(proc, is_suspicious_location=True, connections=mock_conns)
    assert evt is not None
    assert evt.event_type == "OUTBOUND_NETWORK_EXFILTRATION"
    assert evt.severity == "HIGH"
