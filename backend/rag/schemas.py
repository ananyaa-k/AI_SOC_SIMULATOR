"""RAG schema — synthetic incident/response pairs and retrieval output."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class Playbook(BaseModel):
    """Structured response playbook an analyst would follow."""

    steps: list[str] = Field(description="Ordered response actions")
    containment: str | None = None
    eradication: str | None = None
    recovery: str | None = None
    lessons_learned: str | None = None


class IncidentResponsePair(BaseModel):
    """One synthetic historical incident + its analyst response (Day 4 content).

    The owner authors 50 of these. The embedding is derived from the concatenated
    text fields below; metadata fields enable filtered retrieval.
    """

    incident_id: str
    title: str
    description: str
    attack_pattern: str
    log_characteristics: str
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    analyst_investigation: str
    response_playbook: Playbook
    resolution: str
    lessons_learned: str
    source: str = "synthetic"
    created_at: datetime = Field(default_factory=lambda: datetime.now())


class RetrievedIncident(BaseModel):
    """Top-k retrieval result returned to the pipeline / dashboard."""

    incident: IncidentResponsePair
    similarity: float
    matched_fields: list[str] = Field(default_factory=list)


def pair_to_text(pair: IncidentResponsePair) -> str:
    """Concatenate the semantically-relevant fields for embedding."""
    parts = [
        f"Title: {pair.title}",
        f"Description: {pair.description}",
        f"Attack pattern: {pair.attack_pattern}",
        f"Log characteristics: {pair.log_characteristics}",
        f"MITRE: {pair.mitre_tactic} / {pair.mitre_technique} ({pair.mitre_technique_id})",
        f"Severity: {pair.severity}",
        f"Investigation: {pair.analyst_investigation}",
        f"Resolution: {pair.resolution}",
    ]
    return "\n".join(parts)