"""Alert manager (spec section 14).

Turns :class:`detection.schemas.Detection` events into stored, stateful
:class:`~app.models.alert.Alert` objects. Responsibilities are deliberately
narrow and contain NO AI reasoning:

* assign unique alert IDs (prefix + monotonic counter)
* normalize severity through :func:`app.models.alert.normalize_severity`
* attach timestamps
* deduplicate obvious repeats (same rule + same evidence, while the earlier
  alert is still open)
* keep alert state and expose structured slices for the API/dashboard

Storage is in-memory for the simulator; swapping to a real datastore later
only means changing the ``_store`` internals, not the public methods.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence

from app.models.alert import Alert, AlertStatus, Severity, normalize_severity
from detection.schemas import Detection


def _evidence_signature(evidence) -> tuple[str, ...]:
    """Stable fingerprint over triggering events (timestamp + raw message)."""
    return tuple(f"{e.timestamp.isoformat()}|{e.raw_message}" for e in evidence)


class AlertManager:
    def __init__(self) -> None:
        self._alerts: dict[str, Alert] = {}
        self._counter = 0

    # -- lifecycle ----------------------------------------------------------

    def reset(self) -> None:
        """Clear all state; used by tests and by a fresh-session button."""
        self._alerts.clear()
        self._counter = 0

    def create_alert(self, detection: Detection) -> Alert | None:
        """Create an alert from a detection, or return None if it is a duplicate."""
        duplicate = self._find_duplicate(detection)
        if duplicate is not None:
            return None

        self._counter += 1
        alert = Alert(
            alert_id=f"ALERT-{self._counter:04d}",
            timestamp=detection.detected_at,
            created_at=datetime.now(timezone.utc),
            severity=normalize_severity(detection.severity),
            rule_id=detection.rule_id,
            rule_name=detection.rule_name,
            description=detection.rule_description,
            source_ip=(
                str(detection.evidence[0].source_ip)
                if detection.evidence and detection.evidence[0].source_ip
                else None
            ),
            destination_ip=(
                str(detection.evidence[0].destination_ip)
                if detection.evidence and detection.evidence[0].destination_ip
                else None
            ),
            event_type=(
                detection.evidence[0].event_type if detection.evidence else None
            ),
            mitre_tactic=detection.mitre_tactic,
            mitre_technique=detection.mitre_technique,
            mitre_technique_id=detection.mitre_technique_id,
            evidence=detection.evidence,
            status=AlertStatus.NEW,
        )
        self._alerts[alert.alert_id] = alert
        return alert

    # -- queries -------------------------------------------------------------

    def get(self, alert_id: str) -> Alert | None:
        return self._alerts.get(alert_id)

    def list(self) -> list[Alert]:
        return sorted(
            self._alerts.values(),
            key=lambda a: a.created_at,
            reverse=True,
        )

    def count(self) -> int:
        return len(self._alerts)

    def by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for alert in self._alerts.values():
            counts[alert.severity.value] += 1
        return counts

    def by_status(self) -> dict[str, int]:
        counts = {s.value: 0 for s in AlertStatus}
        for alert in self._alerts.values():
            counts[alert.status.value] += 1
        return counts

    # -- internals -----------------------------------------------------------

    def _find_duplicate(self, detection: Detection) -> Alert | None:
        """Return an open alert already covering this detection, if any.

        Duplicate means: same rule fired on exactly the same triggering events
        while a NEW/TRIAGED alert with that signature still exists. Once an
        alert is resolved/closed the same evidence may legitimately re-fire.
        """
        sig = _evidence_signature(detection.evidence)
        for alert in self._alerts.values():
            if alert.rule_id != detection.rule_id:
                continue
            if alert.status not in (AlertStatus.NEW, AlertStatus.TRIAGED):
                continue
            if _evidence_signature(alert.evidence) == sig:
                return alert
        return None


# Module-level singleton so the API/dashboard share one view of alert state.
alert_manager = AlertManager()