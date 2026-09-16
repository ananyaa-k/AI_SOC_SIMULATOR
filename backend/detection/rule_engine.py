"""Deterministic rule-engine orchestration for the SOC simulator."""

from __future__ import annotations

from typing import Sequence

from app.models.security_log import SecurityLog
from detection.rules.base import DetectionRule
from detection.rules.brute_force import BruteForceRule
from detection.rules.malicious_ip import MaliciousIPRule
from detection.rules.suspicious_command import SuspiciousCommandRule
from detection.rules.suspicious_powershell import SuspiciousPowerShellRule
from detection.schemas import Detection


def _default_rules() -> tuple[DetectionRule, ...]:
    return (
        BruteForceRule(),
        MaliciousIPRule(),
        SuspiciousPowerShellRule(),
        SuspiciousCommandRule(),
    )


def detect(
    logs: Sequence[SecurityLog],
    rules: Sequence[DetectionRule] | None = None,
) -> list[Detection]:
    """Evaluate normalized logs against the supplied/default deterministic rules.

    ``rules=None`` selects all four built-in rules. Rules own their correlation
    semantics; the engine only orchestrates them and returns a deterministic
    timestamp-ordered result. Empty input returns an empty list.
    """
    if not logs:
        return []

    active_rules = tuple(_default_rules() if rules is None else rules)
    if not active_rules:
        return []

    detections: list[Detection] = []
    for rule in active_rules:
        detections.extend(rule.evaluate(logs))

    return sorted(
        detections,
        key=lambda detection: (detection.detected_at, detection.rule_id),
    )
