"""In-memory incident store shared by the API and dashboard.

Mirrors :class:`alerts.alert_manager.AlertManager` so both alert and incident
reads stay trivial; a real datastore would replace the internals only.
"""

from __future__ import annotations

from app.models.incident import Incident


class IncidentStore:
    def __init__(self) -> None:
        self._incidents: dict[str, Incident] = {}

    def reset(self) -> None:
        self._incidents.clear()

    def add(self, incident: Incident) -> None:
        self._incidents[incident.incident_id] = incident

    def get(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def list(self) -> list[Incident]:
        return sorted(
            self._incidents.values(),
            key=lambda i: i.created_at,
            reverse=True,
        )

    def count(self) -> int:
        return len(self._incidents)

    def by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for incident in self._incidents.values():
            counts[incident.status.value] = counts.get(incident.status.value, 0) + 1
        return counts

    def by_technique(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for incident in self._incidents.values():
            key = incident.mitre_technique_id or "UNKNOWN"
            counts[key] = counts.get(key, 0) + 1
        return counts


incident_store = IncidentStore()