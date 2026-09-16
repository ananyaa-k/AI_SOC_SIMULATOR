"""Known malicious destination IP rule (RULE-002)."""

from __future__ import annotations

from typing import Sequence

from app.models.security_log import LogEventType, SecurityLog
from detection.mitre_mapping import get_rule_meta
from detection.schemas import Detection
from detection.rules.base import DetectionRule, RuleMeta
from simulation.log_generator import MALICIOUS_IPS


class MaliciousIPRule(DetectionRule):
    meta = RuleMeta(**get_rule_meta("RULE-002"))

    def evaluate(self, logs: Sequence[SecurityLog]) -> list[Detection]:
        detections: list[Detection] = []
        for log in sorted(logs, key=lambda event: event.timestamp):
            if log.event_type != LogEventType.NETWORK_CONNECTION:
                continue
            if log.destination_ip is None:
                continue

            matched_ip = str(log.destination_ip)
            if matched_ip not in MALICIOUS_IPS:
                continue

            detections.append(
                Detection(
                    rule_id=self.meta.rule_id,
                    rule_name=self.meta.name,
                    rule_description=self.meta.description,
                    severity=self.meta.severity,
                    mitre_tactic=self.meta.mitre_tactic,
                    mitre_technique=self.meta.mitre_technique,
                    mitre_technique_id=self.meta.mitre_technique_id,
                    evidence=[log],
                    detected_at=log.timestamp,
                    meta={
                        "matched_ip": matched_ip,
                        "category": MALICIOUS_IPS[matched_ip],
                    },
                )
            )
        return detections
