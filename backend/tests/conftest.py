"""Shared fixtures: reset in-memory stores so tests stay independent."""

import pytest


@pytest.fixture(autouse=True)
def _reset_stores():
    from alerts.alert_manager import alert_manager
    from app.models.incident_store import incident_store
    from agent.l1_analyst import L1Analyst, set_l1_analyst
    from app.services.simulation_pipeline import reset_pipeline

    alert_manager.reset()
    incident_store.reset()
    reset_pipeline()
    # Never call a real LLM from tests, even if .env carries a Groq key.
    set_l1_analyst(L1Analyst(llm=None))
    yield
    set_l1_analyst(None)