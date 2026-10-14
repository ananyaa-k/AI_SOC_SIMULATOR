"""Day 5 confidence scoring tests.

Unit tests cover the scoring formula directly. The pipeline tests swap the
SentenceTransformer model for a deterministic bag-of-words embedding and use a
throwaway Chroma directory, so they run offline and never touch data/vectorstore.
"""

import hashlib
import math

import pytest

from app.models.alert import Severity
from triage.confidence import SEVERITY_FACTOR, score_confidence


def match(similarity, technique="T1110", severity="HIGH", title="Past incident"):
    return {
        "similarity": similarity,
        "title": title,
        "mitre_technique_id": technique,
        "severity": severity,
    }


# --- formula -----------------------------------------------------------------


def test_no_matches_scores_zero_with_reason() -> None:
    result = score_confidence(Severity.HIGH, "T1110", [])
    assert result.score == 0.0
    assert result.match_count == 0
    assert "No historical matches" in result.reasons[0]


def test_perfect_evidence_is_capped_by_severity_factor() -> None:
    matches = [match(1.0), match(1.0)]
    result = score_confidence(Severity.HIGH, "T1110", matches)
    assert result.score == pytest.approx(SEVERITY_FACTOR[Severity.HIGH])
    assert result.technique_agreement == 1.0
    assert result.severity_agreement == 1.0


def test_higher_severity_lowers_confidence_on_equal_evidence() -> None:
    scores = [
        score_confidence(sev, "T1110", [match(0.8, severity=sev.value)]).score
        for sev in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
    ]
    assert scores == sorted(scores, reverse=True)
    assert scores[0] > scores[-1]


def test_higher_similarity_raises_confidence() -> None:
    low = score_confidence(Severity.MEDIUM, "T1110", [match(0.3, severity="MEDIUM")])
    high = score_confidence(Severity.MEDIUM, "T1110", [match(0.9, severity="MEDIUM")])
    assert high.score > low.score


def test_technique_agreement_steps() -> None:
    exact = score_confidence(Severity.HIGH, "T1110", [match(0.7)])
    parent = score_confidence(Severity.HIGH, "T1110", [match(0.7, technique="T1110.003")])
    other = score_confidence(Severity.HIGH, "T1110", [match(0.7, technique="T1059")])
    assert (exact.technique_agreement, parent.technique_agreement, other.technique_agreement) == (1.0, 0.5, 0.0)
    assert exact.score > parent.score > other.score


def test_only_best_match_drives_technique_agreement() -> None:
    # One pair per technique in the knowledge base: weaker off-technique
    # neighbours in the top-k must not drag a perfect hit down.
    result = score_confidence(
        Severity.HIGH, "T1110", [match(0.9), match(0.4, technique="T1059"), match(0.3, technique="T1071")]
    )
    assert result.technique_agreement == 1.0


def test_severity_agreement_steps() -> None:
    same = score_confidence(Severity.HIGH, "T1110", [match(0.7, severity="HIGH")])
    near = score_confidence(Severity.HIGH, "T1110", [match(0.7, severity="CRITICAL")])
    far = score_confidence(Severity.HIGH, "T1110", [match(0.7, severity="LOW")])
    assert (same.severity_agreement, near.severity_agreement, far.severity_agreement) == (1.0, 0.5, 0.0)


def test_best_match_is_picked_regardless_of_order() -> None:
    result = score_confidence(
        Severity.HIGH, "T1110", [match(0.2, title="weak"), match(0.9, title="strong")]
    )
    assert result.top_match_title == "strong"
    assert result.top_similarity == 0.9


def test_out_of_range_similarity_is_clamped() -> None:
    assert score_confidence(Severity.LOW, "T1110", [match(1.4, severity="LOW")]).score <= 1.0
    assert score_confidence(Severity.LOW, None, [match(-0.3, severity="LOW")]).score >= 0.0


def test_missing_metadata_does_not_crash() -> None:
    result = score_confidence("high", None, [{"similarity": 0.5}])
    assert 0.0 < result.score < 1.0
    assert result.technique_agreement == 0.0
    assert result.severity_agreement == 0.0


def test_scoring_is_deterministic() -> None:
    matches = [match(0.71), match(0.42, technique="T1059", severity="MEDIUM")]
    first = score_confidence(Severity.HIGH, "T1110", matches)
    assert all(score_confidence(Severity.HIGH, "T1110", matches) == first for _ in range(5))


# --- pipeline ----------------------------------------------------------------

DIM = 384


def _fake_embed(text: str) -> list[float]:
    vec = [0.0] * DIM
    for token in text.lower().split():
        vec[int(hashlib.md5(token.encode()).hexdigest(), 16) % DIM] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


@pytest.fixture
def offline_rag(tmp_path, monkeypatch):
    import rag.retriever as retriever
    import rag.vector_store as vector_store
    from app.config import settings
    from app.services import simulation_pipeline

    monkeypatch.setattr(vector_store, "embed_text", _fake_embed)
    monkeypatch.setattr(vector_store, "embed_texts", lambda texts: [_fake_embed(t) for t in texts])
    monkeypatch.setattr(settings, "vector_store_path", tmp_path / "vectorstore")
    monkeypatch.setattr(retriever, "_vector_store", None)
    monkeypatch.setattr(simulation_pipeline, "_rag_initialized", False)
    yield


SCENARIOS = ["brute_force", "malicious_ip", "suspicious_powershell", "suspicious_command"]


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_pipeline_fills_confidence_and_audits_it(offline_rag, scenario: str) -> None:
    from app.models.incident_store import incident_store
    from app.services.simulation_pipeline import run_scenario

    result = run_scenario(scenario, seed=1)
    assert result["incident_count"] >= 1

    for incident in incident_store.list():
        assert incident.historical_matches, "fixture should index the synthetic pairs"
        assert incident.confidence is not None
        assert 0.0 < incident.confidence <= SEVERITY_FACTOR[incident.severity]

        scored = [e for e in incident.timeline if e.event == "CONFIDENCE_SCORED"]
        assert len(scored) == 1
        detail = scored[0].detail
        assert detail["score"] == incident.confidence
        assert detail["rule_severity"] == incident.severity.value
        assert detail["match_count"] == len(incident.historical_matches)
        assert detail["reasons"]
        events = [e.event for e in incident.timeline]
        assert events.index("CONFIDENCE_SCORED") < events.index("AGENT_DECISION")
        decision = next(e for e in incident.timeline if e.event == "AGENT_DECISION")
        assert "confidence_missing" not in str(decision.detail)

        match0 = incident.historical_matches[0]
        assert {"incident_id", "mitre_technique_id", "severity"} <= match0.keys()


def test_alert_carries_same_confidence(offline_rag) -> None:
    from alerts.alert_manager import alert_manager
    from app.models.incident_store import incident_store
    from app.services.simulation_pipeline import run_scenario

    run_scenario("brute_force", seed=1)
    for incident in incident_store.list():
        assert alert_manager.get(incident.alert_id).confidence == incident.confidence


def test_pipeline_scores_zero_when_knowledge_base_is_empty(offline_rag, monkeypatch) -> None:
    from app.models.incident_store import incident_store
    from app.services import simulation_pipeline

    monkeypatch.setattr(simulation_pipeline, "initialize_rag", lambda: 0)
    simulation_pipeline.run_scenario("brute_force", seed=1)
    incident = incident_store.list()[0]
    assert incident.historical_matches == []
    assert incident.confidence == 0.0
    assert "CONFIDENCE_SCORED" in [e.event for e in incident.timeline]


def test_report_shows_confidence(offline_rag) -> None:
    from app.models.incident_store import incident_store
    from app.services.simulation_pipeline import run_scenario
    from reports.report_generator import generate_human_report

    run_scenario("brute_force", seed=1)
    incident = incident_store.list()[0]
    assert f"Confidence: {incident.confidence:.2f}" in generate_human_report(incident)
