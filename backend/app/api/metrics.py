from fastapi import APIRouter

from app.services.simulation_pipeline import pipeline_stats
from alerts.alert_manager import alert_manager
from app.models.incident_store import incident_store

router = APIRouter(tags=["metrics"])


@router.get("/metrics")
def metrics() -> dict:
    """Operational metrics computed from real simulator state (spec 39).

    Nothing here is fabricated: every number derives from stored alerts,
    incidents, or the accumulating pipeline statistics.
    """
    by_severity = alert_manager.by_severity()
    by_status = alert_manager.by_status()
    incidents_by_status = incident_store.by_status()

    # Share of ground-truth malicious log events that ended up in the evidence
    # of at least one detection. None until a simulation has run.
    detection_rate = None
    if pipeline_stats.malicious_logs:
        detection_rate = pipeline_stats.detected_malicious_logs / pipeline_stats.malicious_logs

    return {
        "total_logs": pipeline_stats.total_logs,
        "malicious_logs": pipeline_stats.malicious_logs,
        "detected_malicious_logs": pipeline_stats.detected_malicious_logs,
        "total_detections": pipeline_stats.total_detections,
        "detection_rate": detection_rate,
        "total_alerts": alert_manager.count(),
        "alerts_by_severity": by_severity,
        "alerts_by_status": by_status,
        "total_incidents": incident_store.count(),
        "incidents_by_status": incidents_by_status,
        "incidents_by_technique": incident_store.by_technique(),
        # Incident outcomes (one incident per alert, so these match the alert
        # status counts; read from incidents because that is where the L1
        # agent records its decision).
        "auto_resolved": incidents_by_status.get("AUTO_RESOLVED", 0),
        "escalated": incidents_by_status.get("ESCALATED", 0),
    }