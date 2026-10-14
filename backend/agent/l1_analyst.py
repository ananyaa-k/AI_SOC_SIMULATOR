"""AI L1 analyst (Day 6).

Reads an incident (alert data, evidence, RAG matches, confidence), asks a
Groq-hosted LLM through LangChain whether it can be auto-resolved, and then
applies deterministic guardrails before anything is recorded. The LLM can
only ever make a decision *more* cautious: a guardrail can turn an
AUTO_RESOLVE into an ESCALATE, never the reverse.

Guardrails (any one forces ESCALATE):

* no LLM configured, the call failed, or the reply could not be parsed
* confidence missing or below ``auto_resolve_threshold``
* severity CRITICAL
* no historical (RAG) matches to support the decision
* the recommended action is not in the simulated action catalog

Every decision is appended to the incident's audit timeline:
``AGENT_DECISION`` -> ``RESPONSE_ACTION`` -> ``INCIDENT_CLOSED`` | ``ESCALATED``.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Callable

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import ValidationError

from agent.response_simulator import RESPONSE_ACTIONS, is_known_action, simulate_response
from agent.schemas import AgentDecision, LLMVerdict
from app.models.alert import AlertStatus, Severity
from app.models.incident import AuditEntry, Incident

logger = logging.getLogger(__name__)

DEFAULT_AUTO_RESOLVE_THRESHOLD = 0.85

# Used when the LLM gives no usable recommendation: a sensible default the
# human analyst can approve or change.
DEFAULT_ACTION_BY_TECHNIQUE: dict[str, str] = {
    "T1110": "BLOCK_IP",
    "T1071": "BLOCK_IP",
    "T1059.001": "KILL_PROCESS",
    "T1059": "KILL_PROCESS",
}

SYSTEM_PROMPT = f"""You are an L1 SOC analyst triaging alerts in a SIMULATED security operations center.
All telemetry is synthetic and every response action is simulated; nothing touches real systems.

Decide whether the incident can be safely AUTO_RESOLVE'd (it closely matches a known, well-understood
historical pattern with a standard playbook) or must be ESCALATE'd to a human analyst (novel, ambiguous,
high impact, or weak supporting evidence). When unsure, escalate.

Pick exactly one recommended_action from this catalog:
{json.dumps(RESPONSE_ACTIONS, indent=2)}

Reply with ONLY a JSON object, no prose, in this shape:
{{"decision": "AUTO_RESOLVE" | "ESCALATE", "reason": "<one or two sentences>",
  "recommended_action": "<catalog key>", "recommended_response": "<short analyst-facing response plan>"}}"""


def build_incident_prompt(incident: Incident) -> str:
    """Render the facts the LLM is allowed to reason over."""
    evidence = [e.raw_message for e in incident.evidence[:5]]
    matches = [
        {k: m.get(k) for k in ("title", "similarity", "incident_id", "mitre_technique_id") if k in m}
        for m in incident.historical_matches
    ]
    payload = {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity.value,
        "source_ip": incident.source_ip,
        "affected_asset": incident.affected_asset,
        "mitre": {
            "tactic": incident.mitre_tactic,
            "technique": incident.mitre_technique,
            "technique_id": incident.mitre_technique_id,
        },
        "confidence": incident.confidence,
        "evidence_sample": evidence,
        "evidence_count": len(incident.evidence),
        "historical_matches": matches,
    }
    return "Triage this incident:\n" + json.dumps(payload, indent=2, default=str)


def parse_verdict(text: str) -> LLMVerdict:
    """Pull the JSON object out of the model reply and validate it."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match is None:
        raise ValueError("no JSON object in LLM reply")
    return LLMVerdict.model_validate(json.loads(match.group(0)))


def _action_target(incident: Incident, action: str) -> str | None:
    if action in ("DISABLE_ACCOUNT", "RESET_CREDENTIALS"):
        for e in incident.evidence:
            if e.username:
                return e.username
        return None
    if action in ("ISOLATE_HOST", "KILL_PROCESS", "QUARANTINE_FILE"):
        if incident.evidence:
            return incident.evidence[0].source
        return incident.affected_asset
    return incident.source_ip or incident.affected_asset


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class L1Analyst:
    def __init__(
        self,
        llm: BaseChatModel | None,
        *,
        model_name: str | None = None,
        auto_resolve_threshold: float = DEFAULT_AUTO_RESOLVE_THRESHOLD,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self.llm = llm
        self.model_name = model_name
        self.auto_resolve_threshold = auto_resolve_threshold
        self._clock = clock

    # -- decision ------------------------------------------------------------

    def decide(self, incident: Incident) -> AgentDecision:
        """Ask the LLM, then apply guardrails. Never raises on LLM problems."""
        verdict: LLMVerdict | None = None
        guardrails: list[str] = []

        if self.llm is None:
            guardrails.append("llm_unavailable")
        else:
            try:
                reply = self.llm.invoke(
                    [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=build_incident_prompt(incident))]
                )
                verdict = parse_verdict(str(reply.content))
            except (ValueError, ValidationError) as exc:
                logger.warning("L1 agent could not parse LLM reply for %s: %s", incident.incident_id, exc)
                guardrails.append("llm_output_invalid")
            except Exception as exc:  # network, auth, rate limit...
                logger.warning("L1 agent LLM call failed for %s: %s", incident.incident_id, exc)
                guardrails.append("llm_error")

        if incident.confidence is None:
            guardrails.append("confidence_missing")
        elif incident.confidence < self.auto_resolve_threshold:
            guardrails.append("confidence_below_threshold")
        if incident.severity == Severity.CRITICAL:
            guardrails.append("critical_severity")
        if not incident.historical_matches:
            guardrails.append("no_historical_match")

        action = verdict.recommended_action if verdict else None
        if verdict is not None and not is_known_action(action):
            guardrails.append("unknown_action")
        if not is_known_action(action):
            action = DEFAULT_ACTION_BY_TECHNIQUE.get(incident.mitre_technique_id or "", "MONITOR")

        llm_decision = verdict.decision if verdict else None
        if llm_decision == "AUTO_RESOLVE" and not guardrails:
            decision, reason = "AUTO_RESOLVE", verdict.reason
        elif llm_decision == "ESCALATE":
            decision, reason = "ESCALATE", verdict.reason
        else:
            decision = "ESCALATE"
            reason = "Guardrail forced escalation: " + ", ".join(guardrails)
            if verdict is not None:
                reason += f". Agent had proposed {verdict.decision}: {verdict.reason}"

        recommended_response = (verdict.recommended_response if verdict else "") or RESPONSE_ACTIONS[action]
        return AgentDecision(
            decision=decision,
            reason=reason,
            recommended_action=action,
            recommended_response=recommended_response,
            llm_decision=llm_decision,
            guardrails_triggered=guardrails,
            model=self.model_name,
        )

    # -- recording -----------------------------------------------------------

    def apply(self, incident: Incident, decision: AgentDecision) -> Incident:
        """Write the decision onto the incident and its audit timeline."""
        now = self._clock()
        auto = decision.decision == "AUTO_RESOLVE"
        response = simulate_response(
            decision.recommended_action, _action_target(incident, decision.recommended_action), approved=auto
        )

        incident.agent_decision = decision.decision
        incident.recommended_response = decision.recommended_response
        incident.response_action = response.action
        incident.response_status = response.status
        incident.escalation_reason = None if auto else decision.reason
        incident.status = AlertStatus.AUTO_RESOLVED if auto else AlertStatus.ESCALATED
        incident.updated_at = now

        incident.timeline.append(
            AuditEntry(
                timestamp=now,
                event="AGENT_DECISION",
                detail={
                    "decision": decision.decision,
                    "reason": decision.reason,
                    "llm_decision": decision.llm_decision,
                    "guardrails_triggered": decision.guardrails_triggered,
                    "confidence": incident.confidence,
                    "model": decision.model,
                },
            )
        )
        incident.timeline.append(AuditEntry(timestamp=now, event="RESPONSE_ACTION", detail=response.as_detail()))
        if auto:
            incident.timeline.append(
                AuditEntry(timestamp=now, event="INCIDENT_CLOSED", detail={"resolution": "auto-resolved by L1 agent"})
            )
        else:
            incident.timeline.append(AuditEntry(timestamp=now, event="ESCALATED", detail={"reason": decision.reason}))
        return incident

    def triage(self, incident: Incident) -> AgentDecision:
        decision = self.decide(incident)
        self.apply(incident, decision)
        return decision


def build_default_llm(api_key: str | None, model: str) -> BaseChatModel | None:
    """ChatGroq when a key is configured, otherwise None (agent escalates)."""
    if not api_key:
        return None
    try:
        from langchain_groq import ChatGroq
    except ImportError:
        logger.warning("langchain-groq not installed; L1 agent will escalate everything")
        return None
    return ChatGroq(model=model, api_key=api_key, temperature=0)


_default_analyst: L1Analyst | None = None


def get_l1_analyst() -> L1Analyst:
    """Process-wide analyst built lazily from settings."""
    global _default_analyst
    if _default_analyst is None:
        from app.config import settings

        _default_analyst = L1Analyst(
            build_default_llm(settings.groq_api_key, settings.llm_model),
            model_name=settings.llm_model if settings.groq_api_key else None,
        )
    return _default_analyst


def set_l1_analyst(analyst: L1Analyst | None) -> None:
    """Override the process-wide analyst (tests, or a fresh config)."""
    global _default_analyst
    _default_analyst = analyst

