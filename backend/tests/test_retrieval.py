"""Day 4 retrieval accuracy evaluation (spec section 21).

Target: 90%+ of repeated attack patterns retrieve the correct historical playbook.

Methodology:
- For each scenario, inject N independently-seeded batches.
- For each batch, run retrieval and check if the EXPECTED synthetic pair
  (by incident_id) appears in the top-3 results.
- Accuracy = correct_retrievals / total_test_cases.
"""

import pytest

from app.services.simulation_pipeline import run_scenario, reset_pipeline
from rag.schemas import IncidentResponsePair
from rag.vector_store import VectorStore
from rag.retriever import RetrievalConfig, retrieve

# Map scenario -> expected synthetic incident_id in data/incidents/synthetic_pairs.jsonl
EXPECTED_PAIR = {
    "brute_force": "SYN-0001",
    "malicious_ip": "SYN-0003",
    "suspicious_powershell": "SYN-0002",
    "suspicious_command": "SYN-0004",
}

EVAL_SEEDS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
TOP_K = 3
TARGET_ACCURACY = 0.90

# Retrieval quality depends on the real embedding model (see conftest.py).
pytestmark = pytest.mark.real_embeddings


def test_vector_store_indexed() -> None:
    from app.services.simulation_pipeline import initialize_rag
    from rag.playbooks import load_pairs

    expected = len(load_pairs())
    assert expected > 0, "historical incident dataset is missing or empty"
    assert initialize_rag() == expected
    assert VectorStore().count() == expected


@pytest.mark.parametrize("scenario", sorted(EXPECTED_PAIR))
def test_retrieval_correctness(scenario: str) -> None:
    """Each seed for a scenario should retrieve the expected pair in top-3."""
    expected_id = EXPECTED_PAIR[scenario]
    for seed in EVAL_SEEDS:
        # Fresh run for each seed
        from app.services.simulation_pipeline import reset_pipeline, run_scenario
        reset_pipeline()
        from alerts.alert_manager import alert_manager
        from app.models.incident_store import incident_store
        alert_manager.reset()
        incident_store.reset()

        result = run_scenario(scenario, seed=seed)
        assert result["incident_count"] >= 1

        # Get the last created incident
        from app.models.incident_store import incident_store as store
        incidents = store.list()
        assert incidents
        latest = incidents[0]

        # Check historical matches contain expected pair
        matched_ids = [m.get("incident_id") for m in latest.historical_matches if m.get("incident_id")]
        # Our retriever doesn't populate incident_id in historical_matches yet
        # Instead check title match via the expected pair's title
        from rag.schemas import IncidentResponsePair
        from rag.playbooks import load_pairs
        pairs = {p.incident_id: p for p in load_pairs()}
        expected_title = pairs[expected_id].title

        retrieved_titles = [m.get("title", "") for m in latest.historical_matches]
        assert expected_title in retrieved_titles[:TOP_K], (
            f"scenario={scenario} seed={seed}: expected '{expected_title}' "
            f"in top-{TOP_K} of {retrieved_titles}"
        )


def test_retrieval_accuracy_summary() -> None:
    """Overall accuracy assertion (prints table like detection rate test)."""
    correct = 0
    total = 0
    per_scenario = {}
    for scenario in sorted(EXPECTED_PAIR):
        expected_id = EXPECTED_PAIR[scenario]
        from rag.schemas import IncidentResponsePair
        from rag.playbooks import load_pairs
        pairs = {p.incident_id: p for p in load_pairs()}
        expected_title = pairs[expected_id].title

        hits = 0
        for seed in EVAL_SEEDS:
            from app.services.simulation_pipeline import reset_pipeline, run_scenario
            reset_pipeline()
            from alerts.alert_manager import alert_manager
            from app.models.incident_store import incident_store
            alert_manager.reset()
            incident_store.reset()

            result = run_scenario(scenario, seed=seed)
            from app.models.incident_store import incident_store as store
            latest = store.list()[0]
            titles = [m.get("title", "") for m in latest.historical_matches[:TOP_K]]
            if expected_title in titles:
                hits += 1
            total += 1
        per_scenario[scenario] = {"hits": hits, "cases": len(EVAL_SEEDS)}
        correct += hits

    accuracy = correct / total
    print("\n=== RAG RETRIEVAL ACCURACY ===")
    for sc, row in per_scenario.items():
        print(f"  {sc:<22} {row['hits']:>2}/{row['cases']} ({row['hits']/row['cases']:.0%})")
    print(f"  OVERALL: {correct}/{total} = {accuracy:.2%} (target >= {TARGET_ACCURACY:.0%})")
    print("=================================")
    assert accuracy >= TARGET_ACCURACY, (
        f"retrieval accuracy {accuracy:.2%} below target {TARGET_ACCURACY:.0%}"
    )