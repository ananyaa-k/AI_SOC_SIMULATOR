from fastapi import APIRouter, HTTPException

from app.services.simulation_pipeline import run_scenario
from simulation.log_generator import SCENARIOS

router = APIRouter(tags=["simulation"])


@router.post("/simulate")
def simulate_all() -> dict:
    """Run every attack scenario once; returns per-scenario summaries."""
    return {"scenarios": [run_scenario(name) for name in sorted(SCENARIOS)]}


@router.post("/simulate/{scenario}")
def simulate_one(scenario: str) -> dict:
    """Run a single attack scenario end to end (spec section 30)."""
    try:
        return run_scenario(scenario)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"unknown scenario {scenario!r}; choose from {sorted(SCENARIOS)}",
        )