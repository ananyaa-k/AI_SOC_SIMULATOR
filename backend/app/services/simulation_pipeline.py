"""End-to-end simulation pipeline (Day 3 scope).

Wires the deterministic chain for one scenario:

    generate logs -> detect -> alert -> incident

Later phases slot in between alert and incident (RAG Day 4, confidence Day 5,
L1 agent + response Day 6) without changing this orchestration shape.

Pipeline statistics accumulate across calls so /metrics (spec section 39) can
report on real simulated data only -- never fabricated values.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.alert import Alert
from app.models.incident import Incident
from alerts.alert_manager import AlertManager
from detection.rule_engine import detect
from simulation.log_generator import SCENARIOS, generate_scenario


@dataclass
class PipelineStats:
    total_logs: int = 0
    malicious_logs: int = 0
    total_detections: int = 0
    incidents: dict[str, IndividualStats] = field(default_factory=dict)


@dataclass
class IndividualStats:
    incidents: int = 0
    alerts: int = 0
    detections: int = 0


def _incident_counter() -> int:
    global _incident_seq
    _incident_seq += 1
    return _incident_seq


_incident_seq = 0
pipeline_stats = PipelineStats()


def reset_pipeline() -> None:
    """Reset counter + stats; used by tests. Fresh-session button may reuse."""
    global _incident_seq
    _incident_seq = 0
    pipeline_stats.total_logs = 0
    pipeline_stats.malicious_logs = 0
    pipeline_stats.total_detections = 0
    pipeline_stats.incidents.clear()


def run_scenario(
    scenario: str,
    manager: AlertManager | None = None,
    seed: int | None = None,
) -> dict:
    """Run one full simulated scenario through the Day 3 pipeline.

    Returns a summary dict grouped per alert/incident so the API can return a
    compact payload while the stores keep the full objects.
    """
    if scenario not in SCENARIOS:
        raise KeyError(f"unknown scenario {scenario!r}; choose from {sorted(SCENARIOS)}")

    manager = manager or _default_manager
    logs = generate_scenario(scenario, seed=seed)
    detections = detect(logs)

    pipeline_stats.total_logs += len(logs)
    pipeline_stats.malicious_logs += sum(
        1 for e in logs if e.metadata.get("ground_truth") is True
    )
    pipeline_stats.total_detections += len(detections)

    alerts: list[Alert] = []
    incidents: list[Incident] = []
    for detection in detections:
        alert = manager.create_alert(detection)
        if alert is None:
            continue  # duplicate, already covered by an open alert
        alerts.append(alert)
        incident = Incident.from_alert(f"INC-{_incident_counter():04d}", alert)
        _default_incident_store.add(incident)
        incidents.append(incident)

    entry = pipeline_stats.incidents.setdefault(
        scenario, IndividualStats()
    )
    entry.detections = len(detections)
    entry.alerts += len(alerts)
    entry.incidents += len(incidents)

    return {
        "scenario": scenario,
        "log_count": len(logs),
        "detection_count": len(detections),
        "alert_count": len(alerts),
        "incident_count": len(incidents),
        "alerts": [a.alert_id for a in alerts],
        "incidents": [i.incident_id for i in incidents],
    }


# Late-import singletons depend on module-level circular-safe imports.
from alerts.alert_manager import alert_manager as _default_manager  # noqa: E402
from app.models.incident_store import incident_store as _default_incident_store  # noqa: E402