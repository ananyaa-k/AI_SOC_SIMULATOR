"""Deterministic brute-force correlation rule (RULE-001)."""

from __future__ import annotations

from datetime import timedelta
from typing import Sequence

from app.models.security_log import LogEventType, SecurityLog
from detection.mitre_mapping import get_rule_meta
from detection.schemas import Detection
from detection.rules.base import DetectionRule, RuleMeta

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(seconds=60)


class BruteForceRule(DetectionRule):
    meta = RuleMeta(**get_rule_meta("RULE-001"))

    def evaluate(self, logs: Sequence[SecurityLog]) -> list[Detection]:
        candidates = sorted(
            (log for log in logs if log.event_type == LogEventType.AUTH_FAILURE),
            key=lambda log: log.timestamp,
        )
        if not candidates:
            return []

        # Correlate independently by source/target/user. A non-overlapping
        # window prevents one long burst from producing a detection per event.
        groups: dict[tuple[object, object, object], list[SecurityLog]] = {}
        for log in candidates:
            key = (log.source_ip, log.destination_ip, log.username)
            groups.setdefault(key, []).append(log)

        detections: list[Detection] = []
        for group in groups.values():
            start = 0
            while start < len(group):
                window_start = group[start].timestamp
                window_end = window_start + BRUTE_FORCE_WINDOW
                end = start
                while end < len(group) and group[end].timestamp <= window_end:
                    end += 1

                window = group[start:end]
                if len(window) >= BRUTE_FORCE_THRESHOLD:
                    evidence = window
                    detections.append(
                        Detection(
                            rule_id=self.meta.rule_id,
                            rule_name=self.meta.name,
                            rule_description=self.meta.description,
                            severity=self.meta.severity,
                            mitre_tactic=self.meta.mitre_tactic,
                            mitre_technique=self.meta.mitre_technique,
                            mitre_technique_id=self.meta.mitre_technique_id,
                            evidence=evidence,
                            detected_at=evidence[-1].timestamp,
                            meta={
                                "failure_count": len(evidence),
                                "window_seconds": int(BRUTE_FORCE_WINDOW.total_seconds()),
                                "source_ip": str(evidence[0].source_ip) if evidence[0].source_ip else None,
                                "destination_ip": str(evidence[0].destination_ip) if evidence[0].destination_ip else None,
                                "username": evidence[0].username,
                            },
                        )
                    )
                    # Consume the correlated burst. A later burst only gets a
                    # new detection after this window has been exhausted.
                    start = end
                else:
                    start += 1

        return sorted(detections, key=lambda detection: detection.detected_at)
