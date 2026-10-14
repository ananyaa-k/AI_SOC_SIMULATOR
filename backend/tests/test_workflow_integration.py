"""End-to-end workflow tests: API request -> final incident outcome.

Every scenario is driven through ``POST /simulate/{scenario}`` and the result
is checked stage by stage (logs, detection, alert, incident, RAG, confidence,
L1 decision, simulated response, audit timeline, report, metrics). Failure
paths cover missing LLM credentials, provider errors, invalid model output,
missing/broken RAG data, empty retrieval and unsupported scenarios.

RAG runs on the conftest STAND-IN embedding, so these tests prove wiring and
state consistency, not retrieval quality (see test_retrieval.py for that).
"""

from __future__ import annotations

import json
import socket
import subprocess

import pytest
from fastapi.testclient import TestClient
from langchain_core.language_models.fake_chat_models import FakeListChatModel

from agent.l1_analyst import L1Analyst, set_l1_analyst
from agent.response_simulator import RESPONSE_ACTIONS, STATUS_PENDING_APPROVAL, STATUS_SIMULATED
from app.main import app
from app.services import simulation_pipeline as pipeline
from detection.mitre_mapping import RULES, expected_rule_for_scenario
from rag.schemas import IncidentResponsePair, RetrievedIncident
from simulation.log_generator import SCENARIOS, generate_scenario

ALL_SCENARIOS = sorted(SCENARIOS)

ESCALATED_TRAIL = [
    "ALERT_CREATED",
    "DETECTION_RULE_TRIGGERED",
    "RAG_SEARCH_PERFORMED",
    "CONFIDENCE_SCORED",
    "AGENT_DECISION",
    "RESPONSE_ACTION",
    "ESCALATED",
]
RESOLVED_TRAIL = ESCALATED_TRAIL[:-1] + ["INCIDENT_CLOSED"]


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def llm_replying(**verdict) -> L1Analyst:
    body = {
        "decision": "AUTO_RESOLVE",
        "reason": "Matches a known pattern with a standard playbook.",
        "recommended_action": "MONITOR",
        "recommended_response": "Watchlist the indicator.",
    }
    body.update(verdict)
    return L1Analyst(FakeListChatModel(responses=[json.dumps(body)]), model_name="fake")


def strong_match_for(technique_id: str, severity: str) -> RetrievedIncident:
    """A historical match that agrees on technique and severity at high similarity."""
    pair = IncidentResponsePair(
        incident_id="SYN-TEST",
        title="Known pattern",
        description="",
        attack_pattern="",
        log_characteristics="",
        mitre_tactic="",
        mitre_technique="",
        mitre_technique_id=technique_id,
        severity=severity,
        analyst_investigation="",
        response_playbook={"steps": []},
        resolution="",
        lessons_learned="",
    )
    return RetrievedIncident(incident=pair, similarity=0.97)


def events(incident: dict) -> list[str]:
    return [e["event"] for e in incident["timeline"]]


def guardrails(incident: dict) -> list[str]:
    entry = next(e for e in incident["timeline"] if e["event"] == "AGENT_DECISION")
    return entry["detail"]["guardrails_triggered"]


# --- happy path, every scenario ----------------------------------------------


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_scenario_end_to_end_without_llm(client, scenario: str) -> None:
    logs = generate_scenario(scenario)
    malicious = [e for e in logs if e.metadata["ground_truth"]]
    rule_id = expected_rule_for_scenario(scenario)
    rule = RULES[rule_id]

    resp = client.post(f"/simulate/{scenario}")
    assert resp.status_code == 200
    body = resp.json()

    # Logs + detection
    assert body["log_count"] == len(logs)
    assert body["detection_count"] >= 1
    assert body["alert_count"] == body["incident_count"] == body["detection_count"]

    alerts = {a["alert_id"]: a for a in client.get("/alerts").json()}
    incidents = client.get("/incidents").json()
    assert len(alerts) == len(incidents) == body["incident_count"]

    covered = set()
    for inc in incidents:
        alert = alerts[inc["alert_id"]]
        # Detection: correct rule, severity and MITRE mapping, only malicious evidence
        assert alert["rule_id"] == rule_id
        assert alert["severity"] == inc["severity"] == rule["severity"]
        assert inc["mitre_technique_id"] == rule["mitre_technique_id"]
        assert inc["mitre_tactic"] == rule["mitre_tactic"]
        assert inc["evidence"] and all(e["metadata"]["ground_truth"] for e in inc["evidence"])
        covered |= {(e["timestamp"], e["raw_message"]) for e in inc["evidence"]}

        # RAG + confidence
        assert inc["rag_status"] == "ok"
        assert inc["historical_matches"]
        assert 0.0 <= inc["confidence"] <= 1.0
        assert alert["confidence"] == inc["confidence"]
        rag = next(e for e in inc["timeline"] if e["event"] == "RAG_SEARCH_PERFORMED")
        assert rag["detail"]["match_count"] == len(inc["historical_matches"])
        scored = next(e for e in inc["timeline"] if e["event"] == "CONFIDENCE_SCORED")
        assert scored["detail"]["score"] == inc["confidence"]

        # No LLM configured -> conservative escalation, response only pending
        assert inc["agent_decision"] == "ESCALATE"
        assert inc["status"] == alert["status"] == "ESCALATED"
        assert "llm_unavailable" in guardrails(inc)
        assert "llm_unavailable" in inc["escalation_reason"]
        assert inc["response_action"] in RESPONSE_ACTIONS
        assert inc["response_status"] == STATUS_PENDING_APPROVAL
        response = next(e for e in inc["timeline"] if e["event"] == "RESPONSE_ACTION")
        assert response["detail"]["simulated"] is True

        # Audit trail: exact order, timestamps never go backwards
        assert events(inc) == ESCALATED_TRAIL
        stamps = [e["timestamp"] for e in inc["timeline"]]
        assert stamps == sorted(stamps)

        # Reports agree with stored state
        report = json.loads(client.get(f"/incidents/{inc['incident_id']}/report").json()["content"])
        assert report == inc
        text = client.get(f"/incidents/{inc['incident_id']}/report", params={"format": "text"}).json()["content"]
        assert f"**Status:** {inc['status']}" in text
        assert f"- Decision: {inc['agent_decision']}" in text
        assert f"Confidence: {inc['confidence']:.2f}" in text

    # Every ground-truth malicious event is covered by some detection's evidence
    assert covered == {(e.timestamp.isoformat().replace("+00:00", "Z"), e.raw_message) for e in malicious}

    metrics = client.get("/metrics").json()
    assert metrics["total_logs"] == len(logs)
    assert metrics["malicious_logs"] == len(malicious)
    assert metrics["detected_malicious_logs"] == len(malicious)
    assert metrics["detection_rate"] == 1.0
    assert metrics["total_alerts"] == metrics["total_incidents"] == len(incidents)
    assert metrics["escalated"] == len(incidents)
    assert metrics["auto_resolved"] == 0
    assert metrics["alerts_by_status"]["ESCALATED"] == len(incidents)
    assert metrics["incidents_by_technique"] == {rule["mitre_technique_id"]: len(incidents)}


def test_simulate_all_keeps_metrics_consistent(client) -> None:
    body = client.post("/simulate").json()
    assert [s["scenario"] for s in body["scenarios"]] == ALL_SCENARIOS
    metrics = client.get("/metrics").json()
    incidents = client.get("/incidents").json()
    assert metrics["total_incidents"] == len(incidents) == sum(s["incident_count"] for s in body["scenarios"])
    assert metrics["total_logs"] == sum(s["log_count"] for s in body["scenarios"])
    assert metrics["detection_rate"] == 1.0
    assert metrics["escalated"] + metrics["auto_resolved"] == len(incidents)
    assert sum(metrics["alerts_by_severity"].values()) == metrics["total_alerts"]


def test_rerun_is_deduplicated_while_escalations_are_open(client) -> None:
    first = client.post("/simulate/malicious_ip").json()
    second = client.post("/simulate/malicious_ip").json()
    assert first["alert_count"] >= 1
    assert second["detection_count"] == first["detection_count"]
    assert second["alert_count"] == second["incident_count"] == 0
    assert client.get("/metrics").json()["total_incidents"] == first["incident_count"]


# --- L1 decision paths -------------------------------------------------------


def test_medium_incident_auto_resolves_when_llm_and_guardrails_agree(client, monkeypatch) -> None:
    monkeypatch.setattr(pipeline, "retrieve", lambda alert, config: [strong_match_for("T1059", "MEDIUM")])
    set_l1_analyst(llm_replying())

    body = client.post("/simulate/suspicious_command").json()
    for inc_id in body["incidents"]:
        inc = client.get(f"/incidents/{inc_id}").json()
        assert inc["confidence"] >= 0.85
        assert inc["agent_decision"] == "AUTO_RESOLVE"
        assert inc["status"] == "AUTO_RESOLVED"
        assert client.get(f"/alerts/{inc['alert_id']}").json()["status"] == "AUTO_RESOLVED"
        assert inc["response_status"] == STATUS_SIMULATED
        assert inc["escalation_reason"] is None
        assert events(inc) == RESOLVED_TRAIL
    metrics = client.get("/metrics").json()
    assert metrics["auto_resolved"] == body["incident_count"]
    assert metrics["escalated"] == 0


@pytest.mark.parametrize(
    "scenario, technique, severity, guardrail",
    [
        ("brute_force", "T1110", "HIGH", "high_severity"),
        ("malicious_ip", "T1071", "HIGH", "high_severity"),
    ],
)
def test_high_severity_escalates_even_when_llm_says_auto_resolve(
    client, monkeypatch, scenario, technique, severity, guardrail
) -> None:
    monkeypatch.setattr(pipeline, "retrieve", lambda alert, config: [strong_match_for(technique, severity)])
    set_l1_analyst(llm_replying(recommended_action="BLOCK_IP"))

    body = client.post(f"/simulate/{scenario}").json()
    for inc_id in body["incidents"]:
        inc = client.get(f"/incidents/{inc_id}").json()
        decision = next(e for e in inc["timeline"] if e["event"] == "AGENT_DECISION")["detail"]
        assert decision["llm_decision"] == "AUTO_RESOLVE"
        assert inc["agent_decision"] == "ESCALATE"
        assert guardrail in decision["guardrails_triggered"]
        assert inc["response_status"] == STATUS_PENDING_APPROVAL


@pytest.mark.parametrize(
    "analyst_factory, guardrail",
    [
        (lambda: L1Analyst(None), "llm_unavailable"),
        (lambda: L1Analyst(FakeListChatModel(responses=["I think it is fine."])), "llm_output_invalid"),
        (lambda: L1Analyst(FakeListChatModel(responses=['{"decision": "MAYBE"}'])), "llm_output_invalid"),
        (lambda: llm_replying(recommended_action="WIPE_SERVER"), "unknown_action"),
    ],
    ids=["missing_api_key", "prose_reply", "schema_violation", "action_outside_catalog"],
)
def test_llm_failures_escalate(client, monkeypatch, analyst_factory, guardrail) -> None:
    monkeypatch.setattr(pipeline, "retrieve", lambda alert, config: [strong_match_for("T1059", "MEDIUM")])
    set_l1_analyst(analyst_factory())

    body = client.post("/simulate/suspicious_command").json()
    assert body["incident_count"] >= 1
    for inc_id in body["incidents"]:
        inc = client.get(f"/incidents/{inc_id}").json()
        assert inc["agent_decision"] == "ESCALATE"
        assert guardrail in guardrails(inc)
        assert inc["response_action"] in RESPONSE_ACTIONS
        assert events(inc) == ESCALATED_TRAIL


def test_llm_provider_error_escalates(client, monkeypatch) -> None:
    class TimingOutLLM(FakeListChatModel):
        def invoke(self, *args, **kwargs):  # noqa: D401 - test double
            raise TimeoutError("provider timed out")

    monkeypatch.setattr(pipeline, "retrieve", lambda alert, config: [strong_match_for("T1059", "MEDIUM")])
    set_l1_analyst(L1Analyst(TimingOutLLM(responses=["unused"])))

    body = client.post("/simulate/suspicious_command").json()
    assert body["incident_count"] >= 1
    for inc_id in body["incidents"]:
        inc = client.get(f"/incidents/{inc_id}").json()
        assert inc["agent_decision"] == "ESCALATE"
        assert "llm_error" in guardrails(inc)


# --- RAG failure paths --------------------------------------------------------


def test_missing_historical_dataset_is_explicit_and_escalates(client, monkeypatch, tmp_path) -> None:
    import rag.playbooks as playbooks

    monkeypatch.setattr(playbooks, "DEFAULT_PAIRS_PATH", tmp_path / "missing.jsonl")
    set_l1_analyst(llm_replying())

    resp = client.post("/simulate/suspicious_command")
    assert resp.status_code == 200
    for inc_id in resp.json()["incidents"]:
        inc = client.get(f"/incidents/{inc_id}").json()
        assert inc["rag_status"] == "unavailable"
        assert inc["historical_matches"] == []
        assert inc["confidence"] == 0.0
        rag = next(e for e in inc["timeline"] if e["event"] == "RAG_SEARCH_PERFORMED")
        assert "knowledge base is empty" in rag["detail"]["error"]
        assert {"rag_unavailable", "no_historical_match", "confidence_below_threshold"} <= set(guardrails(inc))
        assert inc["agent_decision"] == "ESCALATE"

    health = client.get("/health").json()
    assert health["rag"]["ready"] is False
    assert "knowledge base is empty" in health["rag"]["error"]


def test_embedding_model_failure_does_not_break_simulation(client, monkeypatch) -> None:
    def broken_index():
        raise OSError("could not download all-MiniLM-L6-v2")

    monkeypatch.setattr(pipeline, "initialize_rag", broken_index)

    resp = client.post("/simulate/brute_force")
    assert resp.status_code == 200
    inc = client.get("/incidents").json()[0]
    assert inc["rag_status"] == "unavailable"
    assert "could not download" in inc["timeline"][2]["detail"]["error"]
    assert "rag_unavailable" in guardrails(inc)
    assert inc["status"] == "ESCALATED"


def test_retrieval_error_mid_pipeline_is_recorded(client, monkeypatch) -> None:
    def broken_retrieve(alert, config):
        raise RuntimeError("chroma query failed")

    monkeypatch.setattr(pipeline, "retrieve", broken_retrieve)

    resp = client.post("/simulate/malicious_ip")
    assert resp.status_code == 200
    incidents = client.get("/incidents").json()
    assert len(incidents) == resp.json()["alert_count"]  # no alert left without an incident
    for inc in incidents:
        assert inc["rag_status"] == "error"
        assert "rag_unavailable" in guardrails(inc)
        assert inc["status"] == "ESCALATED"


def test_empty_retrieval_scores_zero_and_escalates(client, monkeypatch) -> None:
    monkeypatch.setattr(pipeline, "retrieve", lambda alert, config: [])
    set_l1_analyst(llm_replying())

    client.post("/simulate/suspicious_powershell")
    for inc in client.get("/incidents").json():
        assert inc["rag_status"] == "no_matches"
        assert inc["confidence"] == 0.0
        assert "no_historical_match" in guardrails(inc)
        assert "rag_unavailable" not in guardrails(inc)
        assert inc["status"] == "ESCALATED"


# --- input validation + safety -----------------------------------------------


def test_unsupported_scenario_changes_nothing(client) -> None:
    resp = client.post("/simulate/ransomware")
    assert resp.status_code == 404
    assert "brute_force" in resp.json()["detail"]
    metrics = client.get("/metrics").json()
    assert metrics["total_logs"] == metrics["total_alerts"] == metrics["total_incidents"] == 0


def test_pipeline_never_opens_sockets_or_processes(client, monkeypatch) -> None:
    """Responses are records only: a full run with an auto-resolving LLM must not
    touch the network or spawn processes."""

    def forbidden(*args, **kwargs):
        raise AssertionError("simulated response attempted a real side effect")

    monkeypatch.setattr(pipeline, "retrieve", lambda alert, config: [strong_match_for("T1059", "MEDIUM")])
    set_l1_analyst(llm_replying(recommended_action="KILL_PROCESS"))
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    body = pipeline.run_scenario("suspicious_command")
    assert set(body["decisions"].values()) == {"AUTO_RESOLVE"}
    inc = pipeline._default_incident_store.get(body["incidents"][0])
    assert inc.response_status == STATUS_SIMULATED
    assert inc.timeline[-2].detail["simulated"] is True
