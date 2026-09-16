"""Shared fixtures: reset in-memory stores so tests stay independent."""

import pytest


@pytest.fixture(autouse=True)
def _reset_stores():
    from alerts.alert_manager import alert_manager
    from app.models.incident_store import incident_store
    from app.services.simulation_pipeline import reset_pipeline

    alert_manager.reset()
    incident_store.reset()
    reset_pipeline()
    yield