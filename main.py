"""
SafeType - Main CLI Entrypoint
SafeType Defensive Security
"""

import argparse
import sys
import subprocess
import logging
from safetype.config import DEFAULT_DB_PATH
from safetype.db.database import Database
from safetype.collectors.process_collector import ProcessCollector
from safetype.collectors.behavior_collector import BehaviorCollector
from safetype.collectors.persistence_collector import PersistenceCollector
from safetype.engine.risk_engine import RiskEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("SafeType.Main")


def run_scan(db: Database):
    logger.info("Initializing live system telemetry scan...")
    p_collector = ProcessCollector()
    b_collector = BehaviorCollector()
    pers_collector = PersistenceCollector()
    risk_engine = RiskEngine()

    procs = p_collector.collect_processes()
    pers_records = pers_collector.collect_persistence()

    for p in pers_records:
        db.add_persistence(p)

    high_critical_count = 0

    for proc in procs:
        db.upsert_process(proc)
        events = b_collector.analyze_process(proc, procs)
        for e in events:
            db.add_event(e)

        detection = risk_engine.evaluate_process(proc, events, pers_records)
        db.add_detection(detection)

        if detection.severity_level in ["HIGH", "CRITICAL"]:
            high_critical_count += 1

    logger.info(f"Scan complete. Total processes: {len(procs)}. High/Critical Alerts: {high_critical_count}")


def launch_dashboard():
    logger.info("Launching SafeType Dashboard...")
    dashboard_script = "safetype/app/dashboard.py"
    cmd = [sys.executable, "-m", "streamlit", "run", dashboard_script]
    subprocess.run(cmd)


def main():
    parser = argparse.ArgumentParser(description="SafeType Defensive Security")
    parser.add_argument("--scan", action="store_true", help="Perform live system telemetry scan")
    parser.add_argument("--dashboard", action="store_true", help="Launch Streamlit Dashboard")

    args = parser.parse_args()
    db = Database(DEFAULT_DB_PATH)

    if args.scan:
        run_scan(db)

    if args.dashboard or not any([args.scan, args.dashboard]):
        if not db.get_detections():
            logger.info("Database empty. Initializing baseline live system scan...")
            run_scan(db)
        launch_dashboard()


if __name__ == "__main__":
    main()
