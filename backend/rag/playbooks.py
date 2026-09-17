"""Load synthetic incident/response pairs from JSONL for indexing."""

from __future__ import annotations

import json
from pathlib import Path

from app.config import settings
from rag.schemas import IncidentResponsePair


DEFAULT_PAIRS_PATH = settings.data_dir / "incidents" / "synthetic_pairs.jsonl"


def load_pairs(path: Path | None = None) -> list[IncidentResponsePair]:
    """Load all pairs from JSONL file; one JSON object per line."""
    p = path or DEFAULT_PAIRS_PATH
    if not p.exists():
        return []
    pairs: list[IncidentResponsePair] = []
    with p.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                pairs.append(IncidentResponsePair(**data))
            except Exception as e:
                raise ValueError(f"invalid pair at line {line_num}: {e}") from e
    return pairs


def load_and_index(path: Path | None = None) -> int:
    """Load pairs and upsert into vector store; returns count indexed."""
    from rag.vector_store import VectorStore

    pairs = load_pairs(path)
    if not pairs:
        return 0
    store = VectorStore()
    store.index_pairs(pairs)
    return len(pairs)