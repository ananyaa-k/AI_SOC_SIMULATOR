"""Embedding generation using SentenceTransformers (local, no API key)."""

from __future__ import annotations

import hashlib
from functools import lru_cache

import numpy as np
from sentence_transformers import SentenceTransformer

# Small, fast model; 384-dim embeddings. Deterministic across runs.
MODEL_NAME = "all-MiniLM-L6-v2"


@lru_cache(maxsize=1)
def _get_model() -> SentenceTransformer:
    return SentenceTransformer(MODEL_NAME)


def embed_text(text: str) -> list[float]:
    """Embed a single text string; returns a python list of floats."""
    model = _get_model()
    vec = model.encode(text, normalize_embeddings=True)
    return vec.astype(np.float32).tolist()


def embed_texts(texts: list[str]) -> list[list[float]]:
    """Batch embed; returns list of vectors."""
    model = _get_model()
    vecs = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    return vecs.astype(np.float32).tolist()


def _stable_id(text: str) -> str:
    """Deterministic ID from content hash (prevents duplicate vectors on re-index)."""
    return hashlib.sha256(text.encode()).hexdigest()[:16]