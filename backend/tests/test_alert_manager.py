"""Alert manager behavior tests (spec section 14)."""

from datetime import datetime, timezone

from alerts.alert_manager import AlertManager
from app.models.alert import Severity, AlertStatus
from app.models.security_log import LogEventType, SecurityLog
from detection.schemas import Detection


def make_detection(
    evidence: list[SecurityLog] | None = None,
    rule_id: str = "RULE-001",
    severity: str = "HIGH",
) -> Detection:
    evidence = evidence or [
        SecurityLog(
            timestamp=datetime(2026, 9, 1, 8, 0, 10, tzinfo=timezone.utc),
            source="srv-auth-01",
            event_type=LogEventType.AUTH_FAILURE,
            source_ip="203.0.113.10",
            destination_ip="10.0.0.5",
            username="admin",
            raw_message="Failed password for admin",
        )
    ]
    return Detection(
        rule_id=rule_id,
        rule_name="Brute-Force Detection",
        rule_description="desc",
        severity=severity,
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
        mitre_technique_id="T1110",
        evidence=evidence,
        detected_at=evidence[-1].timestamp,
    )


def test_alert_created_from_detection() -> None:
    manager = AlertManager()
    alert = manager.create_alert(make_detection())
    assert alert is not None
    assert alert.status == AlertStatus.NEW
    assert alert.severity == Severity.HIGH
    assert alert.rule_id == "RULE-001"
    assert alert.source_ip == "203.0.113.10"
    assert alert.destination_ip == "10.0.0.5"
    assert alert.event_type == "AUTH_FAILURE"
    assert alert.mitre_technique_id == "T1110"
    assert alert.evidence


def test_alert_ids_are_unique_and_monotonic() -> None:
    manager = AlertManager()
    a1 = manager.create_alert(make_detection())
    a2 = manager.create_alert(make_detection(evidence=[make_detection().evidence[0].model_copy(update={"timestamp": datetime(2026, 9, 1, 8, 1, 0, tzinfo=timezone.utc)})]))
    assert a1 is not None and a2 is not None
    assert a1.alert_id != a2.alert_id
    assert a1.alert_id.startswith("ALERT-")
    assert len(manager.list()) == 2


def test_duplicate_detection_is_suppressed() -> None:
    manager = AlertManager()
    first = manager.create_alert(make_detection())
    second = manager.create_alert(make_detection())
    assert first is not None
    assert second is None, "identical open evidence must not create a second alert"
    assert manager.count() == 1


def test_duplicate_allowed_after_resolved() -> None:
    manager = AlertManager()
    first = manager.create_alert(make_detection())
    assert first is not None
    # Simulate resolution (as Day 6 will): resolved alerts no longer dedup.
    first.status = AlertStatus.CLOSED
    reopened = manager.create_alert(make_detection())
    assert reopened is not None
    assert manager.count() == 2


def test_unknown_severity_normalized_to_medium() -> None:
    manager = AlertManager()
    alert = manager.create_alert(make_detection(severity="EXTREME"))
    assert alert is not None
    assert alert.severity == Severity.MEDIUM


def test_severity_counts() -> None:
    manager = AlertManager()
    manager.create_alert(make_detection(severity="HIGH"))
    manager.create_alert(make_detection(rule_id="RULE-002", severity="MEDIUM"))
    counts = manager.by_severity()
    assert counts["HIGH"] == 1
    assert counts["MEDIUM"] == 1
    assert counts["LOW"] == 0


def test_evidence_without_ips_does_not_crash() -> None:
    manager = AlertManager()
    log = SecurityLog(
        timestamp=datetime(2026, 9, 1, 8, 0, 0, tzinfo=timezone.utc),
        source="srv-web-01",
        event_type=LogEventType.URL_REQUEST,
        raw_message="GET /index.html 200",
    )
    alert = manager.create_alert(make_detection(evidence=[log]))
    assert alert is not None
    assert alert.source_ip is None
    assert alert.destination_ip is None