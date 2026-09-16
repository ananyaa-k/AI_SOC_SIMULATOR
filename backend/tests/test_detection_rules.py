"""Behavior tests for the deterministic detection layer.

CONTRACT-AS-SPEC: these tests pin the interface the owner's ``rule_engine.py``
and rule classes must implement. Until ``rule_engine.py`` exists they are
skipped via ``importorskip`` so the rest of the suite stays green.

Public interface under test
---------------------------
``rule_engine.detect(logs, rules=None) -> list[Detection]``

* ``logs``: sequence of :class:`~app.models.security_log.SecurityLog` (any order;
  the engine may sort internally).
* ``rules``: optional sequence of :class:`~detection.rules.base.DetectionRule`;
  when omitted the engine must use its built-in default rule set, which must
  include the four rules in :mod:`detection.mitre_mapping`.
"""

import pytest

from app.models.security_log import SecurityLog
from simulation.log_generator import generate_benign, generate_scenario

rule_engine = pytest.importorskip(
    "detection.rule_engine", reason="rule_engine.py not implemented yet (Day 2 core task)"
)
detect = rule_engine.detect

# Rule IDs for every scenario, from the shared MITRE registry.
from detection.mitre_mapping import RULES  # noqa: E402

SCENARIO_RULES = {
    meta["scenario"]: rule_id for rule_id, meta in RULES.items() if meta["scenario"]
}


def detection_for(scenario: str) -> list:
    return detect(generate_scenario(scenario))


@pytest.mark.parametrize("scenario", sorted(SCENARIO_RULES))
def test_scenario_fires_expected_rule(scenario: str) -> None:
    rule_id = SCENARIO_RULES[scenario]
    detections = detect(generate_scenario(scenario))
    assert rule_id in {d.rule_id for d in detections}, (
        f"expected {rule_id} in {[d.rule_id for d in detections]}"
    )


@pytest.mark.parametrize("scenario", sorted(SCENARIO_RULES))
def test_benign_stream_does_not_false_positive(scenario: str) -> None:
    """A detector that fires on clean traffic is worse than one that misses."""
    for seed in (1, 2, 3, 7, 11):
        benign = generate_benign(seed=seed)
        detections = detect(benign)
        assert detections == [], (
            f"benign seed={seed} produced {[d.rule_id for d in detections]}"
        )


@pytest.mark.parametrize("scenario", sorted(SCENARIO_RULES))
def test_mitre_fields_match_registry(scenario: str) -> None:
    rule_id = SCENARIO_RULES[scenario]
    expected = RULES[rule_id]
    detections = [d for d in detect(generate_scenario(scenario)) if d.rule_id == rule_id]
    assert detections, "expected at least one matching detection"
    for d in detections:
        assert d.mitre_tactic == expected["mitre_tactic"]
        assert d.mitre_technique == expected["mitre_technique"]
        assert d.mitre_technique_id == expected["mitre_technique_id"]
        assert d.severity == expected["severity"]


def test_empty_input_yields_no_detections() -> None:
    assert detect([]) == []


def test_evidence_references_real_logs() -> None:
    logs = generate_scenario("suspicious_powershell")
    for d in detect(logs):
        assert d.evidence, "detection must reference triggering logs"
        for ev in d.evidence:
            assert isinstance(ev, SecurityLog)
            assert ev in logs


def test_combined_scenarios_do_not_crash_and_validate() -> None:
    all_logs = [
        *generate_scenario("brute_force"),
        *generate_scenario("suspicious_powershell"),
        *generate_scenario("malicious_ip"),
        *generate_scenario("suspicious_command"),
    ]
    detections = detect(all_logs)
    for d in detections:
        assert d.detected_at is not None
        assert d.evidence
    # Detector must find at least the four distinct rule types present.
    assert {d.rule_id for d in detections} & set(SCENARIO_RULES.values()) == set(
        SCENARIO_RULES.values()
    )


def test_detection_is_deterministic() -> None:
    logs = generate_scenario("malicious_ip")
    assert detect(logs) == detect(logs)