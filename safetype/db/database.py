"""
SafeType SQLite Database Management & Operations
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from safetype.config import DEFAULT_DB_PATH
from safetype.db.models import (
    DetectionRecord,
    EventRecord,
    PersistenceRecord,
    ProcessRecord,
)

logger = logging.getLogger("SafeType.Database")


class Database:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.init_db()

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}", exc_info=True)
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Create tables for processes, events, persistence, and detections if they do not exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Processes table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS processes (
                    pid INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    exe_path TEXT NOT NULL,
                    ppid INTEGER,
                    username TEXT,
                    create_time REAL,
                    cmdline TEXT,
                    status TEXT,
                    last_scanned_at TEXT NOT NULL
                )
            """)

            # Events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (pid) REFERENCES processes (pid) ON DELETE CASCADE
                )
            """)

            # Persistence table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS persistence (
                    persistence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    location TEXT NOT NULL,
                    details TEXT NOT NULL,
                    is_suspicious INTEGER NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)

            # Detections table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    exe_path TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    severity_level TEXT NOT NULL,
                    indicators_json TEXT NOT NULL,
                    detection_reasons_json TEXT NOT NULL,
                    recommended_actions_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)

            logger.info("Database schema initialized successfully.")

    def clear_all(self) -> None:
        """Clear all records from database (used for reset)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM detections")
            cursor.execute("DELETE FROM events")
            cursor.execute("DELETE FROM persistence")
            cursor.execute("DELETE FROM processes")
            logger.info("Cleared all records from database.")

    # ---------------- Process Operations ---------------- #
    def upsert_process(self, proc: ProcessRecord) -> None:
        scanned_at = proc.last_scanned_at or datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO processes (pid, name, exe_path, ppid, username, create_time, cmdline, status, last_scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(pid) DO UPDATE SET
                    name=excluded.name,
                    exe_path=excluded.exe_path,
                    ppid=excluded.ppid,
                    username=excluded.username,
                    create_time=excluded.create_time,
                    cmdline=excluded.cmdline,
                    status=excluded.status,
                    last_scanned_at=excluded.last_scanned_at
            """, (proc.pid, proc.name, proc.exe_path, proc.ppid, proc.username, proc.create_time, proc.cmdline, proc.status, scanned_at))

    def get_processes(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM processes ORDER BY name ASC")
            return [dict(row) for row in cursor.fetchall()]

    def get_process_by_pid(self, pid: int) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM processes WHERE pid = ?", (pid,))
            row = cursor.fetchone()
            return dict(row) if row else None

    # ---------------- Event Operations ---------------- #
    def add_event(self, evt: EventRecord) -> int:
        timestamp = evt.timestamp or datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO events (pid, event_type, description, severity, metadata_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (evt.pid, evt.event_type, evt.description, evt.severity, evt.metadata_json, timestamp))
            return cursor.lastrowid

    def get_events_for_process(self, pid: int) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events WHERE pid = ? ORDER BY timestamp DESC", (pid,))
            return [dict(row) for row in cursor.fetchall()]

    def get_all_events(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events ORDER BY timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]

    # ---------------- Persistence Operations ---------------- #
    def add_persistence(self, p: PersistenceRecord) -> int:
        timestamp = p.timestamp or datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO persistence (pid, name, type, location, details, is_suspicious, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (p.pid, p.name, p.type, p.location, p.details, 1 if p.is_suspicious else 0, timestamp))
            return cursor.lastrowid

    def get_persistence_records(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM persistence ORDER BY timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]

    # ---------------- Detection Operations ---------------- #
    def add_detection(self, det: DetectionRecord) -> int:
        timestamp = det.timestamp or datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO detections (pid, process_name, exe_path, risk_score, severity_level, indicators_json, detection_reasons_json, recommended_actions_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                det.pid,
                det.process_name,
                det.exe_path,
                det.risk_score,
                det.severity_level,
                det.indicators_json,
                det.detection_reasons_json,
                det.recommended_actions_json,
                timestamp,
            ))
            return cursor.lastrowid

    def quarantine_detection(self, pid: int) -> None:
        """Update risk score to 0 (LOW) and remove process record upon quarantine."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE detections SET
                    risk_score = 0,
                    severity_level = 'LOW',
                    indicators_json = '[]',
                    detection_reasons_json = '["Process terminated and binary quarantined by administrator."]',
                    recommended_actions_json = '["Process quarantined. Run a live system scan again to update active inventory."]'
                WHERE pid = ?
            """, (pid,))
            cursor.execute("DELETE FROM processes WHERE pid = ?", (pid,))
            logger.info(f"Quarantined detection record for PID {pid} - Risk score updated to 0 (LOW).")

    def get_detections(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM detections ORDER BY risk_score DESC, timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_latest_detection_for_process(self, pid: int) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM detections WHERE pid = ? ORDER BY timestamp DESC LIMIT 1", (pid,))
            row = cursor.fetchone()
            return dict(row) if row else None
