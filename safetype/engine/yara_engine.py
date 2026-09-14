"""
SafeType YARA & Heuristic Pattern Signature Engine
Evaluates static binary string patterns and keylogger API signatures safely.
"""

import os
import json
import logging
from typing import List, Optional
from safetype.db.models import EventRecord, ProcessRecord

logger = logging.getLogger("SafeType.YaraEngine")

# Keylogger API String Signatures
INPUT_HOOK_API_SIGNATURES = [
    b"SetWindowsHookEx",
    b"GetAsyncKeyState",
    b"GetForegroundWindow",
    b"WH_KEYBOARD_LL",
    b"WH_KEYBOARD",
    b"RegisterRawInputDevices",
]

PERSISTENCE_API_SIGNATURES = [
    b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"CreateRemoteThread",
    b"VirtualAllocEx",
]


class YaraEngine:
    def __init__(self):
        pass

    def scan_binary_signatures(self, proc: ProcessRecord, is_suspicious_location: bool) -> Optional[EventRecord]:
        """
        Scan executable binary on disk for static keylogging API pattern signatures.
        """
        if not is_suspicious_location or not proc.exe_path or not os.path.isfile(proc.exe_path):
            return None

        try:
            matched_hooks: List[str] = []
            with open(proc.exe_path, "rb") as f:
                content = f.read(5 * 1024 * 1024)  # Read up to first 5 MB safely

                for sig in INPUT_HOOK_API_SIGNATURES:
                    if sig in content:
                        matched_hooks.append(sig.decode("utf-8", errors="ignore"))

            if matched_hooks:
                hooks_str = ", ".join(matched_hooks)
                return EventRecord(
                    pid=proc.pid,
                    event_type="YARA_SIGNATURE_MATCH",
                    description=f"Static binary heuristic engine matched input-monitoring API signatures [{hooks_str}] in file '{proc.exe_path}'.",
                    severity="HIGH",
                    metadata_json=json.dumps({"matched_signatures": matched_hooks, "path": proc.exe_path}),
                )
        except Exception as e:
            logger.debug(f"YARA signature scan skipped for PID {proc.pid}: {e}")

        return None
