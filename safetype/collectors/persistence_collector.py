"""
SafeType Persistence Collector
Inspects safe Windows persistence locations (Registry Run Keys, Startup Folders)
without creating or modifying any persistence entries.
"""

import logging
import os
import sys
from typing import List
from safetype.config import SUSPICIOUS_PATH_PATTERNS
from safetype.db.models import PersistenceRecord

logger = logging.getLogger("SafeType.PersistenceCollector")


class PersistenceCollector:
    def __init__(self):
        pass

    def collect_persistence(self) -> List[PersistenceRecord]:
        records: List[PersistenceRecord] = []

        if sys.platform == "win32":
            try:
                import winreg

                hive_keys = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run Key"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run Key"),
                ]

                for hive, subkey_path, label in hive_keys:
                    try:
                        key = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ)
                        index = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, index)
                                val_str = str(value).lower()
                                is_susp = any(p.lower() in val_str for p in SUSPICIOUS_PATH_PATTERNS)

                                records.append(
                                    PersistenceRecord(
                                        pid=None,
                                        name=name,
                                        type=label,
                                        location=f"{label}\\{name}",
                                        details=str(value),
                                        is_suspicious=is_susp,
                                    )
                                )
                                index += 1
                            except OSError:
                                break
                        winreg.CloseKey(key)
                    except Exception as e:
                        logger.debug(f"Could not open registry path {label}: {e}")
            except ImportError:
                logger.debug("winreg module not available.")

        user_profile = os.environ.get("USERPROFILE") or os.environ.get("HOME")
        if user_profile:
            startup_dir = os.path.join(
                user_profile,
                "AppData",
                "Roaming",
                "Microsoft",
                "Windows",
                "Start Menu",
                "Programs",
                "Startup",
            )
            if os.path.exists(startup_dir):
                try:
                    for item in os.listdir(startup_dir):
                        item_path = os.path.join(startup_dir, item)
                        val_str = item_path.lower()
                        is_susp = any(p.lower() in val_str for p in SUSPICIOUS_PATH_PATTERNS) or item.endswith(".bat") or item.endswith(".vbs")

                        records.append(
                            PersistenceRecord(
                                pid=None,
                                name=item,
                                type="Startup Folder",
                                location=item_path,
                                details=item_path,
                                is_suspicious=is_susp,
                            )
                        )
                except Exception as e:
                    logger.debug(f"Error inspecting Startup folder: {e}")

        logger.info(f"Collected {len(records)} persistence items ({sum(1 for r in records if r.is_suspicious)} suspicious).")
        return records
