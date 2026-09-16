"""Suspicious PowerShell flag rule (RULE-003)."""

from __future__ import annotations

from typing import Sequence

from app.models.security_log import LogEventType, SecurityLog
from detection.mitre_mapping import get_rule_meta
from detection.schemas import Detection
from detection.rules.base import DetectionRule, RuleMeta
from simulation.log_generator import POWERSHELL_FLAGS


class SuspiciousPowerShellRule(DetectionRule):
    meta = RuleMeta(**get_rule_meta("RULE-003"))

    def evaluate(self, logs: Sequence[SecurityLog]) -> list[Detection]:
        detections: list[Detection] = []
        normalized_flags = tuple(flag.casefold() for flag in POWERSHELL_FLAGS)

        for log in sorted(logs, key=lambda event: event.timestamp):
            if log.event_type != LogEventType.POWERSHELL_EXEC or not log.command:
                continue

            command = log.command.casefold()
            matched_flags = [
                flag for flag, normalized in zip(POWERSHELL_FLAGS, normalized_flags)
                if normalized in command
            ]
            if not matched_flags:
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
                    meta={"matched_flags": matched_flags},
                )
            )
        return detections
