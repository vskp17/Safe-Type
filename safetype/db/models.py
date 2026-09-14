"""
SafeType Database Models & Data Transfer Objects
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class ProcessRecord:
    pid: int
    name: str
    exe_path: str
    ppid: Optional[int] = None
    username: Optional[str] = None
    create_time: Optional[float] = None
    cmdline: Optional[str] = None
    status: Optional[str] = None
    last_scanned_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "exe_path": self.exe_path,
            "ppid": self.ppid,
            "username": self.username,
            "create_time": self.create_time,
            "cmdline": self.cmdline,
            "status": self.status,
            "last_scanned_at": self.last_scanned_at or datetime.now(timezone.utc).isoformat(),
        }


@dataclass
class EventRecord:
    pid: int
    event_type: str
    description: str
    severity: str = "LOW"
    metadata_json: str = "{}"
    event_id: Optional[int] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "pid": self.pid,
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity,
            "metadata_json": self.metadata_json,
            "timestamp": self.timestamp or datetime.now(timezone.utc).isoformat(),
        }


@dataclass
class PersistenceRecord:
    pid: Optional[int]
    name: str
    type: str  # e.g., 'Registry Run Key', 'Startup Folder', 'Scheduled Task'
    location: str
    details: str
    is_suspicious: bool = False
    persistence_id: Optional[int] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "persistence_id": self.persistence_id,
            "pid": self.pid,
            "name": self.name,
            "type": self.type,
            "location": self.location,
            "details": self.details,
            "is_suspicious": self.is_suspicious,
            "timestamp": self.timestamp or datetime.now(timezone.utc).isoformat(),
        }


@dataclass
class DetectionRecord:
    pid: int
    process_name: str
    exe_path: str
    risk_score: int
    severity_level: str
    indicators_json: str = "[]"
    detection_reasons_json: str = "[]"
    recommended_actions_json: str = "[]"
    detection_id: Optional[int] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "pid": self.pid,
            "process_name": self.process_name,
            "exe_path": self.exe_path,
            "risk_score": self.risk_score,
            "severity_level": self.severity_level,
            "indicators_json": self.indicators_json,
            "detection_reasons_json": self.detection_reasons_json,
            "recommended_actions_json": self.recommended_actions_json,
            "timestamp": self.timestamp or datetime.now(timezone.utc).isoformat(),
        }
