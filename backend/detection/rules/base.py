"""Rule-building primitives.

This is an interface, not an implementation. The project owner writes the
concrete rules in sibling modules and the engine in ``rule_engine.py``; those
are the core security-logic components and must not be authored by the
assistant.

Contract
--------
* A :class:`DetectionRule` is instantiated once (engine startup) and called
  with a batch of normalized logs.
* ``evaluate(logs)`` returns zero or more :class:`~detection.schemas.Detection`.
  Multi-event rules (e.g. brute force) correlate within the batch themselves;
  the engine does no correlation on their behalf.
* Rules must populate every MITRE field on the Detection from the shared
  registry in :mod:`detection.mitre_mapping` rather than hardcoding copies.
* ``evidence`` must reference the *triggering* events only -- this is what the
  Day 3 alert manager will display.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Sequence

from pydantic import BaseModel

from app.models.security_log import SecurityLog

from detection.schemas import Detection


class RuleMeta(BaseModel):
    """Metadata every rule class carries; read from :mod:`detection.mitre_mapping`."""

    rule_id: str
    name: str
    description: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_id: str


class DetectionRule(ABC):
    """Base class for all deterministic detection rules.

    Subclasses set ``meta = RuleMeta(**get_rule_meta("RULE-xxx"))`` and
    implement :meth:`evaluate`.
    """

    meta: RuleMeta | None = None

    @abstractmethod
    def evaluate(self, logs: Sequence[SecurityLog]) -> list[Detection]:
        """Return a Detection for each independent trigger found in ``logs``."""
        raise NotImplementedError