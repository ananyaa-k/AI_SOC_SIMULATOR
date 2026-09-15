import pytest
from pydantic import ValidationError

from app.models.security_log import SecurityLog
from simulation.log_generator import (
    MALICIOUS_IPS,
    SCENARIOS,
    SUSPICIOUS_COMMANDS,
    generate_all,
    generate_scenario,
    to_json_lines,
)

ALL_SCENARIOS = sorted(SCENARIOS)


def test_all_scenarios_are_known() -> None:
    assert "brute_force" in SCENARIOS
    assert "suspicious_powershell" in SCENARIOS
    assert "malicious_ip" in SCENARIOS
    assert "suspicious_command" in SCENARIOS


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_all_logs_validate_against_schema(scenario: str) -> None:
    logs = generate_scenario(scenario)
    assert logs, f"scenario {scenario} produced no logs"
    for log in logs:
        # Re-validating the model proves every record conforms to the schema.
        assert SecurityLog.model_validate(log.model_dump())


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_every_scenario_mixes_benign_and_malicious(scenario: str) -> None:
    logs = generate_scenario(scenario)
    truth = {log.metadata["ground_truth"] for log in logs}
    assert truth == {True, False}, (
        f"scenario {scenario} must contain both benign and malicious events "
        f"so the detector cannot rely on a single event type"
    )


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_scenario_is_deterministic(scenario: str) -> None:
    assert generate_scenario(scenario) == generate_scenario(scenario), (
        "same scenario + default seed must produce identical logs"
    )


def test_different_seeds_produce_different_logs() -> None:
    a = generate_scenario("brute_force", seed=1)
    b = generate_scenario("brute_force", seed=2)
    assert a != b


def test_unknown_scenario_raises() -> None:
    with pytest.raises(KeyError):
        generate_scenario("does_not_exist")


def test_brute_force_has_repeated_failures_from_same_source() -> None:
    logs = generate_scenario("brute_force")
    failures = [e for e in logs if e.event_type == "AUTH_FAILURE"]
    assert len(failures) >= 20
    sources = {e.source_ip for e in failures}
    assert len(sources) == 1, "all failures should come from the same source IP"
    usernames = {e.username for e in failures}
    assert usernames == {"admin"}


def test_malicious_ip_connects_to_every_listed_ip() -> None:
    logs = generate_scenario("malicious_ip")
    seen = {str(e.destination_ip) for e in logs if e.event_type == "NETWORK_CONNECTION"}
    assert all(ip in seen for ip in MALICIOUS_IPS), "scenario must touch every known malicious IP"


def test_suspicious_command_contains_suspicious_command() -> None:
    logs = generate_scenario("suspicious_command")
    cmds = {e.command for e in logs if e.event_type == "COMMAND_EXEC"}
    assert cmds & set(SUSPICIOUS_COMMANDS), "must include at least one suspicious command"


def test_powershell_scenario_uses_obfuscation_flags() -> None:
    logs = generate_scenario("suspicious_powershell")
    ps = [e for e in logs if e.event_type == "POWERSHELL_EXEC"]
    assert ps
    encoded = [e for e in ps if "-enc" in (e.command or "") or "-encodedcommand" in (e.command or "")]
    assert encoded, "expected at least one -enc / -encodedcommand invocation"
    assert "bypass" in " ".join(e.command or "" for e in ps)


def test_generate_all_covers_all_scenarios() -> None:
    batches = generate_all()
    assert set(batches) == set(SCENARIOS)
    assert sum(len(v) for v in batches.values()) > 0


def test_to_json_lines_is_ndjson() -> None:
    lines = to_json_lines(generate_scenario("brute_force"))
    parsed = [SecurityLog.model_validate_json(line) for line in lines.splitlines()]
    assert parsed


def test_logs_are_time_ordered() -> None:
    logs = generate_scenario("brute_force")
    stamps = [e.timestamp for e in logs]
    assert stamps == sorted(stamps)


def test_invalid_ip_is_rejected_by_schema() -> None:
    with pytest.raises(ValidationError):
        SecurityLog.model_validate(
            {
                "timestamp": "2026-09-01T08:00:00Z",
                "source": "srv-auth-01",
                "event_type": "AUTH_FAILURE",
                "source_ip": "not-an-ip",
                "raw_message": "bad ip",
            }
        )


def test_missing_optional_fields_are_allowed() -> None:
    log = SecurityLog.model_validate(
        {
            "timestamp": "2026-09-01T08:00:00Z",
            "source": "srv-web-01",
            "event_type": "URL_REQUEST",
            "raw_message": "GET / 200",
        }
    )
    assert log.source_ip is None
    assert log.destination_port is None