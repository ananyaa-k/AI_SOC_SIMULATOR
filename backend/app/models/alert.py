from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from app.models.security_log import SecurityLog


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


def normalize_severity(value: str | Severity, default: Severity = Severity.MEDIUM) -> Severity:
    """Map any inbound string onto the canonical severity set.

    Falls back to ``default`` for unknown/blank values so a downstream or
    hand-built detection can never crash the alert pipeline with a bad label.
    """
    try:
        return Severity(value.upper()) if isinstance(value, str) else Severity(value)
    except (ValueError, AttributeError):
        return default


class AlertStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    AUTO_RESOLVED = "AUTO_RESOLVED"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"


class Alert(BaseModel):
    """Structured alert produced from a single detection (spec section 8).

    The alert is self-contained: everything a triage analyst (human or the
    Day 6 L1 agent) needs is on the object -- detection rule metadata, MITRE
    mapping, the exact evidence that triggered the rule, and current status.
    """

    alert_id: str
    timestamp: datetime
    severity: Severity
    rule_id: str
    rule_name: str
    description: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    event_type: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    mitre_technique_id: str | None = None
    evidence: list[SecurityLog] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.NEW
    confidence: float | None = None  # populated by Day 5 confidence scorer
    created_at: datetime