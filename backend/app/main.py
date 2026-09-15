from fastapi import FastAPI

from app.api.health import router as health_router
from app.config import settings

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Simulated SOC pipeline: attack logs -> deterministic detection -> "
        "alerts -> RAG triage -> L1 AI agent -> mock response. See /docs."
    ),
)

app.include_router(health_router)


@app.get("/", tags=["meta"])
def root() -> dict[str, str]:
    return {"message": f"{settings.app_name} API", "docs": "/docs", "health": "/health"}