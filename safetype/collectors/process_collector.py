"""
SafeType Process Collector
Enumerates running system processes and extracts safe metadata using psutil.
Handles access denied and protected system processes gracefully.
Supports active process termination and binary executable deletion.
"""

import os
import logging
from typing import List, Optional
import psutil

from safetype.db.models import ProcessRecord

logger = logging.getLogger("SafeType.ProcessCollector")


class ProcessCollector:
    def __init__(self):
        pass

    def collect_processes(self) -> List[ProcessRecord]:
        """
        Enumerate running processes on the system safely.
        """
        records: List[ProcessRecord] = []

        for proc in psutil.process_iter(
            attrs=["pid", "name", "exe", "ppid", "username", "create_time", "cmdline", "status"]
        ):
            try:
                info = proc.info
                pid = info.get("pid")
                if pid is None:
                    continue

                name = info.get("name") or "Unknown"
                exe_path = info.get("exe") or "Access Denied / System"
                ppid = info.get("ppid")
                username = info.get("username") or "Unknown"
                create_time = info.get("create_time")

                cmdline_list = info.get("cmdline")
                cmdline = " ".join(cmdline_list) if cmdline_list else ""

                status = info.get("status") or "unknown"

                records.append(
                    ProcessRecord(
                        pid=pid,
                        name=name,
                        exe_path=exe_path,
                        ppid=ppid,
                        username=username,
                        create_time=create_time,
                        cmdline=cmdline,
                        status=status,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logger.debug(f"Gracefully skipped process during collection: {e}")
                continue
            except Exception as e:
                logger.warning(f"Unexpected error enumerating process: {e}")
                continue

        logger.info(f"Successfully collected telemetry for {len(records)} processes.")
        return records

    def get_process_by_pid(self, pid: int) -> Optional[ProcessRecord]:
        try:
            p = psutil.Process(pid)
            info = p.as_dict(
                attrs=["pid", "name", "exe", "ppid", "username", "create_time", "cmdline", "status"]
            )
            cmdline_list = info.get("cmdline")
            cmdline = " ".join(cmdline_list) if cmdline_list else ""
            return ProcessRecord(
                pid=info["pid"],
                name=info.get("name") or "Unknown",
                exe_path=info.get("exe") or "Access Denied / System",
                ppid=info.get("ppid"),
                username=info.get("username") or "Unknown",
                create_time=info.get("create_time"),
                cmdline=cmdline,
                status=info.get("status") or "unknown",
            )
        except Exception:
            return None

    def kill_process(self, pid: int, exe_path: Optional[str] = None, *args, **kwargs) -> bool:
        """
        Terminate process safely by PID and attempt binary executable file deletion.
        Returns True if process was successfully killed or already stopped.
        """
        killed = False
        try:
            p = psutil.Process(pid)
            if not exe_path:
                try:
                    exe_path = p.exe()
                except Exception:
                    pass
            p.kill()
            logger.info(f"Quarantined/Terminated process PID {pid}.")
            killed = True
        except psutil.NoSuchProcess:
            logger.info(f"Process PID {pid} already stopped.")
            killed = True
        except (psutil.AccessDenied, Exception) as e:
            logger.error(f"Failed to terminate process PID {pid}: {e}")
            killed = False

        # Attempt to delete binary from disk if in user path
        if exe_path and os.path.isfile(exe_path):
            lower_path = exe_path.lower()
            if "system32" not in lower_path and "syswow64" not in lower_path and "windows" not in lower_path:
                try:
                    os.remove(exe_path)
                    logger.info(f"Deleted quarantined executable file at {exe_path}")
                except Exception as e:
                    logger.warning(f"Could not delete binary at {exe_path}: {e}")

        return killed
