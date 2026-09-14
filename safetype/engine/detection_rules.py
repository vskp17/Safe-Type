"""
SafeType Explainable Detection Rules
Each rule evaluates metadata and events for a process and returns a RuleResult contribution.
"""

from dataclasses import dataclass
from typing import List, Optional
from safetype.config import RULE_WEIGHTS
from safetype.db.models import EventRecord, PersistenceRecord, ProcessRecord


@dataclass
class RuleResult:
    rule_id: str
    rule_name: str
    score_contrib: int
    reasoning: str
    recommended_action: str


class DetectionRules:
    @staticmethod
    def evaluate_input_monitoring(
        events: List[EventRecord],
    ) -> Optional[RuleResult]:
        for e in events:
            if e.event_type == "INPUT_MONITORING_BEHAVIOR":
                return RuleResult(
                    rule_id="INPUT_MONITORING_BEHAVIOR",
                    rule_name="Suspicious Input Monitoring Behavior",
                    score_contrib=RULE_WEIGHTS["INPUT_MONITORING_BEHAVIOR"],
                    reasoning=e.description,
                    recommended_action="Inspect process memory handles and active window hooks. Terminate process if unauthorized.",
                )
        return None

    @staticmethod
    def evaluate_yara_match(
        events: List[EventRecord],
    ) -> Optional[RuleResult]:
        for e in events:
            if e.event_type == "YARA_SIGNATURE_MATCH":
                return RuleResult(
                    rule_id="YARA_SIGNATURE_MATCH",
                    rule_name="Keylogger API String Signature Match",
                    score_contrib=RULE_WEIGHTS["YARA_SIGNATURE_MATCH"],
                    reasoning=e.description,
                    recommended_action="Static heuristic engine detected keylogging API strings. Quarantine binary immediately.",
                )
        return None

    @staticmethod
    def evaluate_network_exfiltration(
        events: List[EventRecord],
    ) -> Optional[RuleResult]:
        for e in events:
            if e.event_type == "OUTBOUND_NETWORK_EXFILTRATION":
                return RuleResult(
                    rule_id="OUTBOUND_NETWORK_EXFILTRATION",
                    rule_name="Outbound Network Exfiltration Telemetry",
                    score_contrib=RULE_WEIGHTS["OUTBOUND_NETWORK_EXFILTRATION"],
                    reasoning=e.description,
                    recommended_action="Block remote IP address at host firewall and isolate process network permissions.",
                )
        return None

    @staticmethod
    def evaluate_persistence(
        proc: ProcessRecord,
        persistence_records: List[PersistenceRecord],
    ) -> Optional[RuleResult]:
        for p in persistence_records:
            if p.is_suspicious:
                if (p.pid is not None and p.pid == proc.pid) or (
                    proc.exe_path and proc.exe_path.lower() in p.details.lower()
                ):
                    return RuleResult(
                        rule_id="SUSPICIOUS_PERSISTENCE",
                        rule_name="Suspicious Startup Persistence Indicator",
                        score_contrib=RULE_WEIGHTS["SUSPICIOUS_PERSISTENCE"],
                        reasoning=f"Process registered in persistence location '{p.type}': {p.location}",
                        recommended_action=f"Remove registry/startup entry at '{p.location}' and audit startup configuration.",
                    )
        return None

    @staticmethod
    def evaluate_unusual_location(
        events: List[EventRecord],
    ) -> Optional[RuleResult]:
        for e in events:
            if e.event_type == "UNUSUAL_EXE_LOCATION":
                return RuleResult(
                    rule_id="UNUSUAL_EXE_LOCATION",
                    rule_name="Unusual Executable Directory",
                    score_contrib=RULE_WEIGHTS["UNUSUAL_EXE_LOCATION"],
                    reasoning=e.description,
                    recommended_action="Verify executable binary authenticity. Move binary out of temp/public directories.",
                )
        return None

    @staticmethod
    def evaluate_process_context(
        proc: ProcessRecord,
        events: List[EventRecord],
    ) -> Optional[RuleResult]:
        for e in events:
            if e.event_type == "UNUSUAL_PROCESS_CONTEXT":
                return RuleResult(
                    rule_id="UNUSUAL_PROCESS_CONTEXT",
                    rule_name="Unusual Process Privilege/User Context",
                    score_contrib=RULE_WEIGHTS["UNUSUAL_PROCESS_CONTEXT"],
                    reasoning=e.description,
                    recommended_action="Audit user account privileges and ensure process is running under correct security context.",
                )
        if proc.username and "SYSTEM" in proc.username.upper():
            if proc.exe_path and ("\\users\\" in proc.exe_path.lower() or "\\appdata\\" in proc.exe_path.lower()):
                return RuleResult(
                    rule_id="UNUSUAL_PROCESS_CONTEXT",
                    rule_name="System Context Execution in User Folder",
                    score_contrib=RULE_WEIGHTS["UNUSUAL_PROCESS_CONTEXT"],
                    reasoning=f"Process '{proc.name}' running with SYSTEM context from user directory '{proc.exe_path}'",
                    recommended_action="Investigate potential privilege escalation exploit.",
                )
        return None

    @staticmethod
    def evaluate_missing_signature(
        events: List[EventRecord],
    ) -> Optional[RuleResult]:
        for e in events:
            if e.event_type == "MISSING_SIGNATURE":
                return RuleResult(
                    rule_id="MISSING_SIGNATURE",
                    rule_name="Missing Binary Signature / Metadata Anomaly",
                    score_contrib=RULE_WEIGHTS["MISSING_SIGNATURE"],
                    reasoning=e.description,
                    recommended_action="Perform hash lookup and code signature verification on binary executable.",
                )
        return None

    @staticmethod
    def evaluate_ancestry(
        events: List[EventRecord],
    ) -> Optional[RuleResult]:
        for e in events:
            if e.event_type == "SUSPICIOUS_ANCESTRY":
                return RuleResult(
                    rule_id="SUSPICIOUS_ANCESTRY",
                    rule_name="Suspicious Process Ancestry / Parent Lineage",
                    score_contrib=RULE_WEIGHTS["SUSPICIOUS_ANCESTRY"],
                    reasoning=e.description,
                    recommended_action="Trace parent PID process tree to identify initial script or execution vector.",
                )
        return None
