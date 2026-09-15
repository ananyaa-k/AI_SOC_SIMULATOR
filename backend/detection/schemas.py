"""Output contract of the detection layer.

The deterministic rule engine (implemented by the project owner) consumes
normalized :class:`~app.models.security_log.SecurityLog` records and emits
zero or more :class:`Detection` objects. Every detection carries its MITRE
ATT&CK mapping and the exact triggering events so the Day 3 alert manager can
build audit-able alerts without touching a single event.

Nothing in this file performs detection logic -- it only defines the shape
engine output must take.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.models.security_log import SecurityLog


class Detection(BaseModel):
    """A single rule firing, fully self-describing for downstream phases.

    ``evidence`` holds the exact SecurityLog records that triggered the rule
    (for multi-event rules this is the correlated cluster, not every log ever
    seen). ``meta`` is a free-form dict rules may populate with supporting
    values (e.g. failure count, flag hit, matched IP) for the alert manager
    and audit trail.
    """

    rule_id: str
    rule_name: str
    rule_description: str | None = None
    severity: str
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_id: str
    evidence: list[SecurityLog]
    detected_at: datetime
    meta: dict[str, Any] = {}