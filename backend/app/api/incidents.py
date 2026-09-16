from fastapi import APIRouter, HTTPException, Query

from app.models.incident import Incident
from app.models.incident_store import incident_store
from reports.report_generator import generate_human_report, generate_json_report

router = APIRouter(tags=["incidents"])


@router.get("/incidents")
def list_incidents(
    status: str | None = Query(default=None),
    technique: str | None = Query(default=None),
) -> list[Incident]:
    incidents = incident_store.list()
    if status is not None:
        incidents = [i for i in incidents if i.status.value == status.upper()]
    if technique is not None:
        incidents = [i for i in incidents if i.mitre_technique_id == technique.upper()]
    return incidents


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str) -> Incident:
    incident = incident_store.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"incident {incident_id} not found")
    return incident


@router.get("/incidents/{incident_id}/report")
def get_report(incident_id: str, format: str = Query(default="json")) -> dict:
    """Incident report; format=text returns the analyst-readable markdown."""
    incident = incident_store.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"incident {incident_id} not found")
    if format == "text":
        return {"incident_id": incident_id, "format": "text", "content": generate_human_report(incident)}
    if format == "json":
        return {"incident_id": incident_id, "format": "json", "content": generate_json_report(incident)}
    raise HTTPException(status_code=400, detail="format must be 'json' or 'text'")