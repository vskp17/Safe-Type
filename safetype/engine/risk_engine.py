"""
SafeType Risk Engine
Computes an explainable 0-100 risk score and maps to LOW, MEDIUM, HIGH, CRITICAL severity.
Enforces safety policy: Never classifies a process as HIGH or CRITICAL based on a single indicator alone.
"""

import json
import logging
from typing import List

from safetype.db.models import (
    DetectionRecord,
    EventRecord,
    PersistenceRecord,
    ProcessRecord,
)
from safetype.engine.detection_rules import DetectionRules, RuleResult

logger = logging.getLogger("SafeType.RiskEngine")


class RiskEngine:
    def __init__(self):
        pass

    @staticmethod
    def calculate_severity(score: int) -> str:
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"

    def evaluate_process(
        self,
        proc: ProcessRecord,
        events: List[EventRecord],
        persistence_records: List[PersistenceRecord],
    ) -> DetectionRecord:
        triggered_rules: List[RuleResult] = []

        rule_evaluators = [
            lambda: DetectionRules.evaluate_input_monitoring(events),
            lambda: DetectionRules.evaluate_yara_match(events),
            lambda: DetectionRules.evaluate_network_exfiltration(events),
            lambda: DetectionRules.evaluate_persistence(proc, persistence_records),
            lambda: DetectionRules.evaluate_unusual_location(events),
            lambda: DetectionRules.evaluate_process_context(proc, events),
            lambda: DetectionRules.evaluate_missing_signature(events),
            lambda: DetectionRules.evaluate_ancestry(events),
        ]

        for eval_fn in rule_evaluators:
            res = eval_fn()
            if res is not None:
                triggered_rules.append(res)

        raw_score = sum(r.score_contrib for r in triggered_rules)

        # Multi-Indicator Safety Policy: Single indicator processes capped at max score 55 (MEDIUM)
        if len(triggered_rules) <= 1:
            final_score = min(raw_score, 55)
        else:
            final_score = min(raw_score, 100)

        final_score = max(0, final_score)
        severity = self.calculate_severity(final_score)

        indicators = [r.rule_id for r in triggered_rules]
        reasons = [r.reasoning for r in triggered_rules]
        actions = [r.recommended_action for r in triggered_rules]

        if not actions:
            actions.append("No immediate action required. Process exhibits low risk telemetry.")

        return DetectionRecord(
            pid=proc.pid,
            process_name=proc.name,
            exe_path=proc.exe_path,
            risk_score=final_score,
            severity_level=severity,
            indicators_json=json.dumps(indicators),
            detection_reasons_json=json.dumps(reasons),
            recommended_actions_json=json.dumps(actions),
        )
