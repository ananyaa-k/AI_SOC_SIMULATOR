"""Report generator tests (spec section 15)."""

import json
from datetime import datetime, timezone

from app.models.alert import Alert, AlertStatus, Severity
from app.models.incident import Incident
from app.models.security_log import LogEventType, SecurityLog
from reports.report_generator import generate_human_report, generate_json_report


def make_alert() -> Alert:
    return Alert(
        alert_id="ALERT-0001",
        timestamp=datetime(2026, 9, 1, 8, 0, 10, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        rule_id="RULE-001",
        rule_name="Brute-Force Detection",
        description="Multiple auth failures.",
        source_ip="203.0.113.10",
        destination_ip="10.0.0.5",
        event_type="AUTH_FAILURE",
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
        mitre_technique_id="T1110",
        evidence=[
            SecurityLog(
                timestamp=datetime(2026, 9, 1, 8, 0, 5, tzinfo=timezone.utc),
                source="srv-auth-01",
                event_type=LogEventType.AUTH_FAILURE,
                source_ip="203.0.113.10",
                destination_ip="10.0.0.5",
                username="admin",
                raw_message="Failed password for admin",
            )
        ],
        status=AlertStatus.NEW,
        created_at=datetime(2026, 9, 1, 8, 0, 11, tzinfo=timezone.utc),
    )


def make_incident() -> Incident:
    return Incident.from_alert("INC-0001", make_alert())


def test_json_report_is_valid_and_complete() -> None:
    incident = make_incident()
    data = json.loads(generate_json_report(incident))
    for field in (
        "incident_id",
        "alert_id",
        "severity",
        "title",
        "source_ip",
        "mitre_tactic",
        "mitre_technique_id",
        "evidence",
        "timeline",
    ):
        assert field in data, f"missing required field {field}"
    assert data["incident_id"] == "INC-0001"
    assert data["evidence"], "report must carry evidence"

    # Reproducibility: same incident in, byte-identical report out.
    assert generate_json_report(incident) == generate_json_report(incident)


def test_human_report_contains_sections() -> None:
    text = generate_human_report(make_incident())
    for marker in (
        "Incident Report: INC-0001",
        "MITRE ATT&CK",
        "T1110",
        "Evidence",
        "Timeline",
    ):
        assert marker in text, f"human report missing {marker!r}"


def test_human_report_reflects_later_phases_when_present() -> None:
    incident = make_incident()
    incident.agent_decision = "AUTO_RESOLVE"
    incident.response_action = "BLOCK_IP"
    incident.response_status = "SIMULATED"
    incident.historical_matches = [{"similarity": 0.93, "title": "Prior brute force"}]
    text = generate_human_report(incident)
    assert "AUTO_RESOLVE" in text
    assert "BLOCK_IP" in text
    assert "SIMULATED" in text
    assert "0.93" in text