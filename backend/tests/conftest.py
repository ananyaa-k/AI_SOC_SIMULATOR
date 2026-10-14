"""Shared fixtures: reset in-memory stores and isolate RAG so tests stay independent.

RAG in tests
------------
Every test gets its own empty ChromaDB directory (never ``data/vectorstore``).
By default the SentenceTransformer model is replaced with a STAND-IN embedding
(hashed bag of words) so the pipeline runs offline and deterministically. The
stand-in exercises indexing, persistence and wiring, NOT retrieval quality.

Tests marked ``real_embeddings`` use the real ``all-MiniLM-L6-v2`` model. When
it cannot be loaded (e.g. no network access to huggingface.co on first run)
they are skipped with a "MANUAL VERIFICATION REQUIRED" reason, never passed.
"""

import hashlib
import math

import pytest

STAND_IN_DIM = 384


def stand_in_embed(text: str) -> list[float]:
    """Deterministic offline embedding for tests only (not semantic)."""
    vec = [0.0] * STAND_IN_DIM
    for token in text.lower().split():
        vec[int(hashlib.md5(token.encode()).hexdigest(), 16) % STAND_IN_DIM] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


_model_error: list[str] = []  # memoized across the session: [] = untried


def _real_model_error() -> str | None:
    if not _model_error:
        try:
            from rag.embeddings import _get_model

            _get_model()
            _model_error.append("")
        except Exception as exc:  # network, proxy, missing cache...
            _model_error.append(f"{type(exc).__name__}: {exc}"[:300])
    return _model_error[0] or None


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


@pytest.fixture(autouse=True)
def _isolated_rag(request, tmp_path, monkeypatch):
    import rag.retriever as retriever
    import rag.vector_store as vector_store
    from app.config import settings
    from app.services import simulation_pipeline

    monkeypatch.setattr(settings, "vector_store_path", tmp_path / "vectorstore")
    monkeypatch.setattr(retriever, "_vector_store", None)
    monkeypatch.setattr(simulation_pipeline, "_rag_initialized", False)
    monkeypatch.setattr(simulation_pipeline, "_rag_error", None)

    if request.node.get_closest_marker("real_embeddings"):
        error = _real_model_error()
        if error:
            pytest.skip(f"MANUAL VERIFICATION REQUIRED: embedding model unavailable ({error})")
    else:
        monkeypatch.setattr(vector_store, "embed_text", stand_in_embed)
        monkeypatch.setattr(vector_store, "embed_texts", lambda texts: [stand_in_embed(t) for t in texts])
    yield
