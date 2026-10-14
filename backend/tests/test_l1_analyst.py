"""L1 analyst tests with a mocked LLM (no network)."""

import json
from datetime import datetime, timezone

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel

from agent.l1_analyst import L1Analyst, build_default_llm, build_incident_prompt, parse_verdict
from agent.response_simulator import STATUS_PENDING_APPROVAL, STATUS_SIMULATED
from app.models.alert import AlertStatus, Severity
from app.models.incident import Incident
from app.models.security_log import LogEventType, SecurityLog

NOW = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)


def make_incident(**overrides) -> Incident:
    base = dict(
        incident_id="INC-0001",
        alert_id="ALERT-0001",
        # MEDIUM: HIGH and CRITICAL always escalate, so the happy path needs MEDIUM.
        severity=Severity.MEDIUM,
        title="Brute-Force Detection",
        description="Multiple auth failures.",
        affected_asset="10.0.0.5",
        source_ip="203.0.113.10",
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
        mitre_technique_id="T1110",
        evidence=[
            SecurityLog(
                timestamp=NOW,
                source="srv-auth-01",
                event_type=LogEventType.AUTH_FAILURE,
                source_ip="203.0.113.10",
                username="admin",
                raw_message="Failed password for admin",
            )
        ],
        historical_matches=[
            {"similarity": 0.91, "title": "Brute-force SSH against authentication server", "incident_id": "SYN-0001"}
        ],
        confidence=0.93,
        created_at=NOW,
        updated_at=NOW,
    )
    base.update(overrides)
    return Incident(**base)


def fake_llm(**verdict) -> FakeListChatModel:
    body = {
        "decision": "AUTO_RESOLVE",
        "reason": "Matches known brute-force pattern SYN-0001 with standard playbook.",
        "recommended_action": "BLOCK_IP",
        "recommended_response": "Block 203.0.113.10 and reset admin password.",
    }
    body.update(verdict)
    return FakeListChatModel(responses=[json.dumps(body)])


def analyst(llm) -> L1Analyst:
    return L1Analyst(llm, model_name="fake", clock=lambda: NOW)


def events(incident: Incident) -> list[str]:
    return [e.event for e in incident.timeline]


def test_auto_resolve_when_llm_agrees_and_guardrails_pass() -> None:
    incident = make_incident()
    decision = analyst(fake_llm()).triage(incident)

    assert decision.decision == "AUTO_RESOLVE"
    assert decision.guardrails_triggered == []
    assert incident.status == AlertStatus.AUTO_RESOLVED
    assert incident.agent_decision == "AUTO_RESOLVE"
    assert incident.response_action == "BLOCK_IP"
    assert incident.response_status == STATUS_SIMULATED
    assert incident.escalation_reason is None
    assert events(incident)[-3:] == ["AGENT_DECISION", "RESPONSE_ACTION", "INCIDENT_CLOSED"]
    response = incident.timeline[-2].detail
    assert response["simulated"] is True
    assert response["target"] == "203.0.113.10"


def test_llm_escalation_is_always_honored() -> None:
    incident = make_incident()
    decision = analyst(fake_llm(decision="ESCALATE", reason="Login succeeded after guesses.")).triage(incident)

    assert decision.decision == "ESCALATE"
    assert incident.status == AlertStatus.ESCALATED
    assert incident.escalation_reason == "Login succeeded after guesses."
    assert incident.response_status == STATUS_PENDING_APPROVAL
    assert events(incident)[-3:] == ["AGENT_DECISION", "RESPONSE_ACTION", "ESCALATED"]


@pytest.mark.parametrize(
    "overrides, guardrail",
    [
        ({"confidence": 0.5}, "confidence_below_threshold"),
        ({"confidence": None}, "confidence_missing"),
        ({"severity": Severity.CRITICAL}, "critical_severity"),
        ({"severity": Severity.HIGH}, "high_severity"),
        ({"rag_status": "unavailable"}, "rag_unavailable"),
        ({"rag_status": "error"}, "rag_unavailable"),
        ({"historical_matches": []}, "no_historical_match"),
    ],
)
def test_guardrails_override_auto_resolve(overrides, guardrail) -> None:
    incident = make_incident(**overrides)
    decision = analyst(fake_llm()).triage(incident)

    assert decision.llm_decision == "AUTO_RESOLVE"
    assert decision.decision == "ESCALATE"
    assert guardrail in decision.guardrails_triggered
    assert guardrail in incident.escalation_reason
    assert incident.status == AlertStatus.ESCALATED
    assert incident.timeline[-3].detail["guardrails_triggered"] == decision.guardrails_triggered


def test_unknown_action_falls_back_and_escalates() -> None:
    incident = make_incident()
    decision = analyst(fake_llm(recommended_action="NUKE_DATACENTER")).triage(incident)

    assert decision.decision == "ESCALATE"
    assert "unknown_action" in decision.guardrails_triggered
    assert incident.response_action == "BLOCK_IP"  # technique default for T1110


def test_unparseable_llm_reply_escalates() -> None:
    incident = make_incident()
    decision = analyst(FakeListChatModel(responses=["I think it's fine, close it."])).triage(incident)

    assert decision.decision == "ESCALATE"
    assert decision.llm_decision is None
    assert "llm_output_invalid" in decision.guardrails_triggered


def test_llm_exception_escalates() -> None:
    class Broken:
        def invoke(self, _messages):
            raise RuntimeError("rate limited")

    incident = make_incident()
    decision = analyst(Broken()).triage(incident)

    assert decision.decision == "ESCALATE"
    assert "llm_error" in decision.guardrails_triggered


def test_no_llm_configured_escalates() -> None:
    incident = make_incident()
    decision = L1Analyst(None).triage(incident)

    assert decision.decision == "ESCALATE"
    assert decision.guardrails_triggered[0] == "llm_unavailable"
    assert build_default_llm(None, "any-model") is None


def test_account_actions_target_the_username() -> None:
    incident = make_incident()
    analyst(fake_llm(recommended_action="RESET_CREDENTIALS")).triage(incident)
    assert incident.timeline[-2].detail["target"] == "admin"


def test_prompt_includes_rag_matches_and_confidence() -> None:
    prompt = build_incident_prompt(make_incident())
    assert "SYN-0001" in prompt
    assert "0.93" in prompt
    assert "T1110" in prompt


def test_parse_verdict_tolerates_code_fences() -> None:
    text = '```json\n{"decision": "ESCALATE", "reason": "x", "recommended_action": "MONITOR"}\n```'
    assert parse_verdict(text).decision == "ESCALATE"


def test_pipeline_records_agent_decision(monkeypatch) -> None:
    """End to end with RAG stubbed: every incident gets a decision and audit trail."""
    from alerts.alert_manager import alert_manager
    from app.services import simulation_pipeline as pipeline

    monkeypatch.setattr(pipeline, "_rag_initialized", True)
    monkeypatch.setattr(pipeline, "retrieve", lambda alert, config: [])

    result = pipeline.run_scenario("brute_force", seed=1)

    assert result["incident_count"] >= 1
    assert set(result["decisions"].values()) == {"ESCALATE"}  # no LLM in tests
    for inc_id in result["incidents"]:
        incident = pipeline._default_incident_store.get(inc_id)
        assert incident.status == AlertStatus.ESCALATED
        assert events(incident)[-3:] == ["AGENT_DECISION", "RESPONSE_ACTION", "ESCALATED"]
        assert alert_manager.get(incident.alert_id).status == AlertStatus.ESCALATED

    # Escalated alerts stay open, so re-running the same seed is still deduplicated.
    assert pipeline.run_scenario("brute_force", seed=1)["alert_count"] == 0
