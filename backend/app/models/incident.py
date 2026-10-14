from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.models.alert import Alert, AlertStatus, Severity
from app.models.security_log import SecurityLog

AUDIT_EVENT_TYPES = Literal[
    "ALERT_CREATED",
    "DETECTION_RULE_TRIGGERED",
    "RAG_SEARCH_PERFORMED",
    "RETRIEVED_INCIDENTS",
    "CONFIDENCE_SCORED",
    "AGENT_DECISION",
    "RESPONSE_ACTION",
    "ESCALATED",
    "INCIDENT_CLOSED",
]


class AuditEntry(BaseModel):
    """One immutable step in an incident's audit trail (spec section 27)."""

    timestamp: datetime
    event: AUDIT_EVENT_TYPES
    detail: dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    """Incident assembled from an alert plus later triage/response phases.

    Fields meant to be filled by later phases (RAG on Day 4, confidence on
    Day 5, L1 agent + response on Day 6) are nullable now so an incident can
    exist from Day 3 onward without faking data the pipeline has not produced.
    """

    incident_id: str
    alert_id: str
    severity: Severity
    status: AlertStatus = AlertStatus.NEW
    title: str
    description: str | None = None
    affected_asset: str | None = None
    source_ip: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    mitre_technique_id: str | None = None

    evidence: list[SecurityLog] = Field(default_factory=list)

    # RAG / confidence
    historical_matches: list[dict[str, Any]] = Field(default_factory=list)
    # ok | no_matches | unavailable | error (see app.services.simulation_pipeline)
    rag_status: str | None = None
    confidence: float | None = None

    # Agent + response
    agent_decision: str | None = None  # AUTO_RESOLVE | ESCALATE
    recommended_response: str | None = None
    response_action: str | None = None
    response_status: str | None = None
    escalation_reason: str | None = None

    created_at: datetime
    updated_at: datetime
    timeline: list[AuditEntry] = Field(default_factory=list)

    @classmethod
    def from_alert(cls, incident_id: str, alert: Alert, title: str | None = None) -> "Incident":
        """Deterministically seed an incident from an alert before triage runs."""
        now = alert.created_at
        return cls(
            incident_id=incident_id,
            alert_id=alert.alert_id,
            severity=alert.severity,
            title=title or alert.rule_name,
            description=alert.description,
            affected_asset=alert.destination_ip or alert.source_ip,
            source_ip=alert.source_ip,
            mitre_tactic=alert.mitre_tactic,
            mitre_technique=alert.mitre_technique,
            mitre_technique_id=alert.mitre_technique_id,
            evidence=alert.evidence,
            created_at=now,
            updated_at=now,
            timeline=[
                AuditEntry(timestamp=now, event="ALERT_CREATED", detail={"alert_id": alert.alert_id}),
                AuditEntry(
                    timestamp=now,
                    event="DETECTION_RULE_TRIGGERED",
                    detail={"rule_id": alert.rule_id, "rule_name": alert.rule_name},
                ),
            ],
        )