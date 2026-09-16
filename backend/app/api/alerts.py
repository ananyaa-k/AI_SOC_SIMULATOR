from fastapi import APIRouter, HTTPException, Query

from alerts.alert_manager import alert_manager
from app.models.alert import Alert, AlertStatus, Severity

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def list_alerts(
    severity: Severity | None = Query(default=None),
    status: AlertStatus | None = Query(default=None),
) -> list[Alert]:
    """Alert feed, newest first; optional severity/status filters."""
    alerts = alert_manager.list()
    if severity is not None:
        alerts = [a for a in alerts if a.severity == severity]
    if status is not None:
        alerts = [a for a in alerts if a.status == status]
    return alerts


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str) -> Alert:
    alert = alert_manager.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"alert {alert_id} not found")
    return alert