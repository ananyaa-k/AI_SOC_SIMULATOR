"""End-to-end API tests for the Day 3 pipeline (spec 28-30, 35)."""

import json

from fastapi.testclient import TestClient

from app.main import app


def test_simulate_scenario_flows_through_pipeline() -> None:
    with TestClient(app) as client:
        resp = client.post("/simulate/brute_force")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scenario"] == "brute_force"
    assert body["detection_count"] >= 1
    assert body["alert_count"] >= 1
    assert body["incident_count"] == body["alert_count"]


def test_unknown_scenario_returns_404() -> None:
    with TestClient(app) as client:
        resp = client.post("/simulate/nope")
    assert resp.status_code == 404


def test_simulate_all_runs_every_scenario() -> None:
    with TestClient(app) as client:
        resp = client.post("/simulate")
    assert resp.status_code == 200
    scenarios = resp.json()["scenarios"]
    assert len(scenarios) == 4


def test_alerts_are_queryable_by_id_and_filter() -> None:
    with TestClient(app) as client:
        client.post("/simulate/brute_force")
        alerts = client.get("/alerts").json()
        assert len(alerts) >= 1
        alert_id = alerts[0]["alert_id"]
        detail = client.get(f"/alerts/{alert_id}")
        assert detail.status_code == 200
        assert detail.json()["alert_id"] == alert_id
        missing = client.get("/alerts/ALERT-9999")
        assert missing.status_code == 404
        highs = client.get("/alerts", params={"severity": "HIGH"}).json()
        assert all(a["severity"] == "HIGH" for a in highs)


def test_incidents_and_reports() -> None:
    with TestClient(app) as client:
        client.post("/simulate/malicious_ip")
        incidents = client.get("/incidents").json()
        assert incidents, "expected incidents after simulation"
        inc_id = incidents[0]["incident_id"]

        detail = client.get(f"/incidents/{inc_id}")
        assert detail.status_code == 200
        assert detail.json()["mitre_technique_id"] == "T1071"

        rep = client.get(f"/incidents/{inc_id}/report", params={"format": "json"})
        assert rep.status_code == 200
        parsed = json.loads(rep.json()["content"])
        assert parsed["incident_id"] == inc_id

        text = client.get(f"/incidents/{inc_id}/report", params={"format": "text"})
        assert "Incident Report" in text.json()["content"]


def test_metrics_reflect_real_state() -> None:
    with TestClient(app) as client:
        before = client.get("/metrics").json()
        assert before["total_alerts"] == 0

        client.post("/simulate/suspicious_command")

        after = client.get("/metrics").json()
        assert after["total_alerts"] >= 1
        assert after["total_incidents"] >= 1
        assert after["malicious_logs"] >= 1
        assert 0 <= after["detection_rate"] <= 1
        assert set(after["alerts_by_severity"]) >= {"LOW", "MEDIUM", "HIGH", "CRITICAL"}