"""Phase 1 acceptance: detection rate >= 80% on injected known-attack logs.

Methodology (documented, not claimed as production-grade):
1. For every attack scenario in :mod:`simulation.log_generator`, inject several
   independently-seeded batches of simulated attack logs.
2. Run each batch through the deterministic rule engine.
3. A case is a "true positive" when the scenario's expected rule (from the
   MITRE registry) fired at least once.
4. Detection rate = true positives / total injected cases.

Both-detection and false-positive direction matter: benign-stream behavior is
covered separately in test_detection_rules.py.

Run with ``pytest -s backend/tests/test_detection_rate.py`` to see the printed
rate table; CI just asserts the gate.
"""

import pytest

from simulation.log_generator import SCENARIOS, generate_scenario

rule_engine = pytest.importorskip(
    "rule_engine", reason="rule_engine.py not implemented yet (Day 2 core task)"
)
detect = rule_engine.detect

from detection.mitre_mapping import RULES  # noqa: E402

DETECTION_RATE_TARGET = 0.80
EVAL_SEEDS = [1, 2, 3, 4, 5, 6, 7, 8]


def expected_rule(scenario: str) -> str:
    for rule_id, meta in RULES.items():
        if meta["scenario"] == scenario:
            return rule_id
    raise KeyError(f"no rule registered for scenario {scenario!r}")


def evaluate_detection_rate() -> dict[str, object]:
    total_cases = 0
    hits = 0
    per_scenario: dict[str, dict] = {}
    for scenario in sorted(SCENARIOS):
        fired = sum(
            1
            for seed in EVAL_SEEDS
            if expected_rule(scenario) in {d.rule_id for d in detect(generate_scenario(scenario, seed=seed))}
        )
        cases = len(EVAL_SEEDS)
        total_cases += cases
        hits += fired
        per_scenario[scenario] = {
            "hits": fired,
            "cases": cases,
            "rate": fired / cases,
        }
    overall = hits / total_cases
    return {
        "per_scenario": per_scenario,
        "overall_rate": overall,
        "hits": hits,
        "total_cases": total_cases,
        "target": DETECTION_RATE_TARGET,
        "passed": overall >= DETECTION_RATE_TARGET,
    }


def test_detection_rate_meets_target() -> None:
    result = evaluate_detection_rate()
    print("\n=== DETECTION RATE EVALUATION ===")
    for scenario, row in result["per_scenario"].items():
        print(f"  {scenario:<22} {row['hits']:>2}/{row['cases']}  ({row['rate']:.2%})")
    print(
        f"  OVERALL: {result['hits']}/{result['total_cases']} = {result['overall_rate']:.2%} "
        f"(target >= {result['target']:.0%})"
    )
    print("==================================")
    assert result["passed"], (
        f"detection rate {result['overall_rate']:.2%} below target "
        f"{result['target']:.0%}"
    )