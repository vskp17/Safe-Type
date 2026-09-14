"""
SafeType Configuration & Risk Threshold Definitions
Publication & Research Edition
"""

import os
from pathlib import Path
from typing import Dict, List, Tuple

# Base Project Path
BASE_DIR = Path(__file__).resolve().parent.parent

# Database Configuration
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "safetype.db")

# Risk Level Ranges & Definitions
RISK_LEVELS: Dict[str, Tuple[int, int]] = {
    "LOW": (0, 29),
    "MEDIUM": (30, 59),
    "HIGH": (60, 79),
    "CRITICAL": (80, 100),
}

SEVERITY_COLORS: Dict[str, str] = {
    "LOW": "#00E676",      # Vivid Emerald Green
    "MEDIUM": "#FFC107",   # Vibrant Amber
    "HIGH": "#FF9100",     # Neon Orange
    "CRITICAL": "#FF1744", # High-Contrast Crimson
}

# Indicator Weight Contributions (Explainable Scoring Matrix)
RULE_WEIGHTS = {
    "INPUT_MONITORING_BEHAVIOR": 35,  # Untrusted binary referencing input/windowing hooks
    "YARA_SIGNATURE_MATCH": 25,       # Heuristic match for keylogger API strings in binary
    "SUSPICIOUS_PERSISTENCE": 25,     # Startup run key / startup folder entry targeting temp/untrusted directory
    "OUTBOUND_NETWORK_EXFILTRATION": 20, # Outbound socket connection from untrusted binary
    "UNUSUAL_EXE_LOCATION": 20,       # Execution from Temp, Downloads, Public, hidden paths
    "UNUSUAL_PROCESS_CONTEXT": 15,    # Non-standard privilege escalation or unusual parent context
    "MISSING_SIGNATURE": 15,          # Missing executable metadata/version info in user directory
    "SUSPICIOUS_ANCESTRY": 15,        # Spawned by script interpreter (cmd/powershell) in user directory
}

# Suspicious Directory Patterns (Case-insensitive matching)
SUSPICIOUS_PATH_PATTERNS: List[str] = [
    "\\appdata\\local\\temp",
    "\\temp\\",
    "\\users\\public",
    "\\downloads\\",
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
]

# Trusted System Folders (Lower suspicion baseline)
TRUSTED_PATH_PATTERNS: List[str] = [
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
]

# Common Standard System Process Names
SYSTEM_PROCESSES: List[str] = [
    "svchost.exe",
    "explorer.exe",
    "csrss.exe",
    "lsass.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "taskhostw.exe",
    "ctfmon.exe",
    "searchhost.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "runtimebroker.exe"
]
