"""Deterministic confidence scorer (Day 5).

Answers one question for the Day 6 L1 agent: *how well does this incident
match something we have already seen and handled?* The score is built only
from facts the pipeline already has -- the rule severity and the RAG matches
-- so every number is explainable and reproducible. No LLM is involved.

    evidence = 0.60 * top_similarity
             + 0.25 * technique_agreement
             + 0.15 * severity_agreement
    confidence = evidence * SEVERITY_FACTOR[rule severity]

* ``top_similarity``: cosine similarity of the best historical match, clamped
  to [0, 1].
* ``technique_agreement``: 1.0 when the best match has the alert's exact MITRE
  technique ID, 0.5 when only the parent technique agrees (T1110 vs
  T1110.003), else 0.0. Only the best match counts: the knowledge base holds
  about one pair per technique, so a share-of-top-k measure would cap well
  below 1.0 even on a perfect hit.
* ``severity_agreement``: 1.0 when the best match has the same severity as the
  rule, 0.5 when it is one level apart, else 0.0.
* ``SEVERITY_FACTOR``: higher-severity rules need stronger evidence before the
  system trusts its own read, so their score is discounted. This keeps a
  CRITICAL incident from ever looking as "safe" as a LOW one on equal evidence.

No historical matches means nothing to compare against, so confidence is 0.0.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, Field

from app.models.alert import Severity, normalize_severity

WEIGHT_SIMILARITY = 0.60
WEIGHT_TECHNIQUE = 0.25
WEIGHT_SEVERITY = 0.15

SEVERITY_FACTOR: dict[Severity, float] = {
    Severity.LOW: 1.00,
    Severity.MEDIUM: 0.95,
    Severity.HIGH: 0.85,
    Severity.CRITICAL: 0.75,
}

SCORER_VERSION = "rule-rag-v1"


class ConfidenceResult(BaseModel):
    """Score plus the breakdown that produced it (written to the audit trail)."""

    score: float = Field(ge=0.0, le=1.0)
    rule_severity: Severity
    severity_factor: float
    top_similarity: float
    technique_agreement: float
    severity_agreement: float
    match_count: int
    top_match_title: str | None = None
    reasons: list[str] = Field(default_factory=list)
    scorer: str = SCORER_VERSION

    def audit_detail(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def _severity_agreement(rule: Severity, match_severity: Any) -> float:
    if not match_severity:
        return 0.0
    gap = abs(rule.rank - normalize_severity(match_severity).rank)
    return {0: 1.0, 1: 0.5}.get(gap, 0.0)


def _technique_agreement(alert_technique: str | None, match_technique: Any) -> float:
    if not alert_technique or not match_technique:
        return 0.0
    if match_technique == alert_technique:
        return 1.0
    if match_technique.split(".")[0] == alert_technique.split(".")[0]:
        return 0.5
    return 0.0


def score_confidence(
    rule_severity: Severity | str,
    technique_id: str | None,
    matches: Sequence[dict[str, Any]],
) -> ConfidenceResult:
    """Score an incident from its rule severity and RAG matches.

    ``matches`` are the ``Incident.historical_matches`` dicts: each carries
    ``similarity`` and, when known, ``title``, ``mitre_technique_id`` and
    ``severity``. Order does not matter; the best match is picked here.
    """
    severity = normalize_severity(rule_severity)
    factor = SEVERITY_FACTOR[severity]

    if not matches:
        return ConfidenceResult(
            score=0.0,
            rule_severity=severity,
            severity_factor=factor,
            top_similarity=0.0,
            technique_agreement=0.0,
            severity_agreement=0.0,
            match_count=0,
            reasons=["No historical matches retrieved; nothing to compare against."],
        )

    best = max(matches, key=lambda m: float(m.get("similarity") or 0.0))
    top_similarity = _clamp(float(best.get("similarity") or 0.0))

    technique_agreement = _technique_agreement(technique_id, best.get("mitre_technique_id"))
    severity_agreement = _severity_agreement(severity, best.get("severity"))

    evidence = (
        WEIGHT_SIMILARITY * top_similarity
        + WEIGHT_TECHNIQUE * technique_agreement
        + WEIGHT_SEVERITY * severity_agreement
    )
    score = round(_clamp(evidence * factor), 3)

    reasons = [
        f"Best historical match {best.get('title', 'unknown')!r} at similarity {top_similarity:.2f}.",
        f"Best match technique {best.get('mitre_technique_id') or 'unknown'} vs alert technique {technique_id or 'n/a'}.",
        f"Best match severity {best.get('severity') or 'unknown'} vs rule severity {severity.value}.",
        f"{severity.value} rule severity applies a x{factor:.2f} caution factor.",
    ]

    return ConfidenceResult(
        score=score,
        rule_severity=severity,
        severity_factor=factor,
        top_similarity=round(top_similarity, 3),
        technique_agreement=round(technique_agreement, 3),
        severity_agreement=severity_agreement,
        match_count=len(matches),
        top_match_title=best.get("title"),
        reasons=reasons,
    )
