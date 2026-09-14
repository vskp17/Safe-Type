"""
SafeType Behavior Collector
Collects non-invasive metadata and telemetry related to suspicious process behaviors.
IMPORTANT SAFETY GUARANTEE: Does NOT capture or inspect keyboard input.
"""

import json
import logging
import os
from typing import Dict, List, Optional
import psutil

from safetype.config import (
    SUSPICIOUS_PATH_PATTERNS,
    SYSTEM_PROCESSES,
    TRUSTED_PATH_PATTERNS,
)
from safetype.db.models import EventRecord, ProcessRecord
from safetype.collectors.network_collector import NetworkCollector
from safetype.engine.yara_engine import YaraEngine
from safetype.utils.hash_util import compute_file_hashes

logger = logging.getLogger("SafeType.BehaviorCollector")


class BehaviorCollector:
    def __init__(self):
        self.network_collector = NetworkCollector()
        self.yara_engine = YaraEngine()

    def is_suspicious_location(self, exe_path: str) -> bool:
        if not exe_path or "Access Denied" in exe_path:
            return False

        lower_path = exe_path.lower()
        for pattern in SUSPICIOUS_PATH_PATTERNS:
            if pattern.lower() in lower_path:
                return True
        return False

    def is_trusted_location(self, exe_path: str) -> bool:
        if not exe_path or "Access Denied" in exe_path:
            return False
        lower_path = exe_path.lower()
        for pattern in TRUSTED_PATH_PATTERNS:
            if pattern.lower() in lower_path:
                return True
        return False

    def check_input_monitoring_indicators(self, proc: ProcessRecord) -> Optional[EventRecord]:
        if not proc.exe_path or self.is_trusted_location(proc.exe_path):
            return None

        if self.is_suspicious_location(proc.exe_path):
            try:
                p = psutil.Process(proc.pid)
                maps = p.memory_maps()
                has_user32 = any("user32.dll" in m.path.lower() for m in maps if m.path)

                if has_user32:
                    return EventRecord(
                        pid=proc.pid,
                        event_type="INPUT_MONITORING_BEHAVIOR",
                        description=f"Process '{proc.name}' running from untrusted path '{proc.exe_path}' holds active user32.dll windowing references.",
                        severity="HIGH",
                        metadata_json=json.dumps({"exe_path": proc.exe_path, "user32_loaded": True}),
                    )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            except Exception as e:
                logger.debug(f"Memory map check skipped for PID {proc.pid}: {e}")

        return None

    def analyze_process_ancestry(self, proc: ProcessRecord, all_procs: List[ProcessRecord]) -> Optional[EventRecord]:
        if not proc.ppid:
            return None

        proc_lookup = {p.pid: p for p in all_procs}
        parent = proc_lookup.get(proc.ppid)

        if parent:
            parent_name = parent.name.lower()
            if parent_name in ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"]:
                if self.is_suspicious_location(proc.exe_path):
                    return EventRecord(
                        pid=proc.pid,
                        event_type="SUSPICIOUS_ANCESTRY",
                        description=f"Process '{proc.name}' in suspicious folder spawned by script interpreter '{parent.name}' (PID {parent.pid}).",
                        severity="MEDIUM",
                        metadata_json=json.dumps({"parent_name": parent.name, "parent_pid": parent.pid, "exe_path": proc.exe_path}),
                    )

        return None

    def analyze_process(
        self, proc: ProcessRecord, all_procs: List[ProcessRecord], net_conns: Optional[Dict[int, List[Dict[str, str]]]] = None
    ) -> List[EventRecord]:
        events: List[EventRecord] = []
        is_susp = self.is_suspicious_location(proc.exe_path)

        # 1. Location Anomaly
        if is_susp:
            hashes = compute_file_hashes(proc.exe_path)
            events.append(
                EventRecord(
                    pid=proc.pid,
                    event_type="UNUSUAL_EXE_LOCATION",
                    description=f"Process '{proc.name}' executing from suspicious location: {proc.exe_path}",
                    severity="MEDIUM",
                    metadata_json=json.dumps({"exe_path": proc.exe_path, "sha256": hashes.get("sha256"), "md5": hashes.get("md5")}),
                )
            )

        # 2. Input Monitoring Indicators
        input_evt = self.check_input_monitoring_indicators(proc)
        if input_evt:
            events.append(input_evt)

        # 3. YARA Signature Match
        yara_evt = self.yara_engine.scan_binary_signatures(proc, is_susp)
        if yara_evt:
            events.append(yara_evt)

        # 4. Outbound Network Exfiltration
        if net_conns and proc.pid in net_conns:
            p_conns = net_conns[proc.pid]
            net_evt = self.network_collector.analyze_process_network_exfiltration(proc, is_susp, p_conns)
            if net_evt:
                events.append(net_evt)

        # 5. Ancestry Anomaly
        ancestry_evt = self.analyze_process_ancestry(proc, all_procs)
        if ancestry_evt:
            events.append(ancestry_evt)

        # 6. Missing Signature / Missing Executable Metadata in user path
        if is_susp and os.path.exists(proc.exe_path):
            try:
                size = os.path.getsize(proc.exe_path)
                if size < 50000:
                    events.append(
                        EventRecord(
                            pid=proc.pid,
                            event_type="MISSING_SIGNATURE",
                            description=f"Executable '{proc.name}' is an unusually small standalone binary ({size} bytes) in user path.",
                            severity="LOW",
                            metadata_json=json.dumps({"file_size_bytes": size}),
                        )
                    )
            except Exception:
                pass

        return events
