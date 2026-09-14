"""
SafeType Network Telemetry Collector
Inspects active TCP/UDP socket connections using psutil to detect outbound exfiltration attempts.
"""

import json
import logging
from typing import Dict, List, Optional
import psutil

from safetype.db.models import EventRecord, ProcessRecord

logger = logging.getLogger("SafeType.NetworkCollector")


class NetworkCollector:
    def __init__(self):
        pass

    def collect_network_connections(self) -> Dict[int, List[Dict[str, str]]]:
        """
        Enumerate active network connections grouped by PID.
        """
        connections_by_pid: Dict[int, List[Dict[str, str]]] = {}

        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                if not c.pid:
                    continue

                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"

                conn_info = {
                    "fd": str(c.fd),
                    "family": str(c.family),
                    "type": str(c.type),
                    "local_address": laddr,
                    "remote_address": raddr,
                    "status": str(c.status),
                }

                if c.pid not in connections_by_pid:
                    connections_by_pid[c.pid] = []
                connections_by_pid[c.pid].append(conn_info)

        except (psutil.AccessDenied, Exception) as e:
            logger.debug(f"Network connection enumeration partial skip: {e}")

        return connections_by_pid

    def analyze_process_network_exfiltration(
        self, proc: ProcessRecord, is_suspicious_location: bool, connections: List[Dict[str, str]]
    ) -> Optional[EventRecord]:
        """
        Detect if a process running from an untrusted location holds active outbound ESTABLISHED connections.
        """
        if not connections or not is_suspicious_location:
            return None

        established_conns = [
            c for c in connections
            if c.get("status") == "ESTABLISHED" and c.get("remote_address") != "N/A"
        ]

        if established_conns:
            first_remote = established_conns[0]["remote_address"]
            return EventRecord(
                pid=proc.pid,
                event_type="OUTBOUND_NETWORK_EXFILTRATION",
                description=f"Process '{proc.name}' in untrusted location maintains active outbound socket connection to remote endpoint '{first_remote}'.",
                severity="HIGH",
                metadata_json=json.dumps({"connections": established_conns}),
            )

        return None
