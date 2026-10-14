"""Structured output of the L1 analyst."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Decision = Literal["AUTO_RESOLVE", "ESCALATE"]


class LLMVerdict(BaseModel):
    """What the LLM is asked to return (parsed from its JSON reply)."""

    decision: Decision
    reason: str = Field(min_length=1)
    recommended_action: str
    recommended_response: str = ""


class AgentDecision(BaseModel):
    """Final decision after deterministic guardrails have been applied.

    ``llm_decision`` keeps what the model proposed so the audit trail shows
    when a guardrail overrode it.
    """

    decision: Decision
    reason: str
    recommended_action: str
    recommended_response: str
    llm_decision: Decision | None = None
    guardrails_triggered: list[str] = Field(default_factory=list)
    model: str | None = None
