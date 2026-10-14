from fastapi import APIRouter

from app.config import settings
from app.services.simulation_pipeline import rag_status

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    """Liveness probe plus the readiness of the optional AI dependencies.

    ``rag.ready`` is False until the first simulation has indexed the
    knowledge base (or if indexing failed; ``rag.error`` says why).
    ``llm_configured`` is False when no GROQ_API_KEY is set, in which case
    every incident is escalated.
    """
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "llm_configured": bool(settings.groq_api_key),
        "rag": rag_status(),
    }
