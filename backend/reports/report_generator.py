"""Incident report generation (spec section 15).

Produces two artifacts from the same structured :class:`Incident`:

* JSON report -- machine-readable, round-trippable
* human-readable report -- analyst-friendly markdown

The functions are pure: identical incident in, identical report out, which
keeps the auditorial requirement (reproducible from incident data).
"""

from __future__ import annotations

import json

from app.models.incident import Incident


def to_dict(incident: Incident) -> dict:
    """Stable dict representation of an incident for JSON export."""
    return incident.model_dump(mode="json")


def generate_json_report(incident: Incident) -> str:
    """Serialized, human-independent incident report."""
    return json.dumps(to_dict(incident), indent=2)


def generate_human_report(incident: Incident) -> str:
    """Analyst-readable markdown rendering of the incident."""
    lines = [
        f"# Incident Report: {incident.incident_id}",
        "",
        f"**Status:** {incident.status.value}",
        f"**Severity:** {incident.severity.value}",
        f"**Title:** {incident.title}",
        f"**Alert:** {incident.alert_id}",
        f"**Affected asset:** {incident.affected_asset or 'n/a'}",
        f"**Source IP:** {incident.source_ip or 'n/a'}",
        "",
        "## Description",
        "",
        incident.description or "No description provided.",
        "",
        "## MITRE ATT&CK",
        "",
        f"- Tactic: {incident.mitre_tactic or 'n/a'}",
        f"- Technique: {incident.mitre_technique or 'n/a'}",
        f"- Technique ID: {incident.mitre_technique_id or 'n/a'}",
        "",
        "## Evidence",
        "",
    ]
    for i, ev in enumerate(incident.evidence, start=1):
        lines.append(f"{i}. `{ev.timestamp.isoformat()}` {ev.event_type} :: {ev.raw_message}")

    lines += [
        "",
        "## RAG / Historical Context",
        "",
    ]
    if incident.historical_matches:
        for i, match in enumerate(incident.historical_matches, start=1):
            lines.append(
                f"{i}. Similarity {match.get('similarity', 'n/a'):} "
                f"-- {match.get('title', 'n/a')}"
            )
    else:
        lines.append("No historical matches retrieved.")

    lines += [
        "",
        "## Agent Decision (Day 6)",
        "",
        f"- Decision: {incident.agent_decision or 'PENDING'}",
        f"- Recommended response: {incident.recommended_response or 'n/a'}",
        f"- Response action: {incident.response_action or 'n/a'}",
        f"- Response status: {incident.response_status or 'n/a'}",
        f"- Escalation reason: {incident.escalation_reason or 'n/a'}",
        "",
        "## Timeline",
        "",
    ]
    for entry in incident.timeline:
        lines.append(f"- `{entry.timestamp.isoformat()}` **{entry.event}** {entry.detail}")

    return "\n".join(lines)