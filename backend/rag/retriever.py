"""Retrieval service — maps an alert to top-k historical incidents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.models.alert import Alert
from rag.schemas import IncidentResponsePair, RetrievedIncident
from rag.vector_store import VectorStore


@dataclass
class RetrievalConfig:
    top_k: int = 3
    # Optional metadata filter map; passed as Chroma `where` clause.
    # e.g. {"mitre_technique_id": "T1110"} restricts to matching technique.
    filter: dict[str, Any] | None = None


# Module-level singleton (initialized lazily by pipeline).
_vector_store: VectorStore | None = None


def get_vector_store() -> VectorStore:
    global _vector_store
    if _vector_store is None:
        _vector_store = VectorStore()
    return _vector_store


def build_query_text(alert: Alert) -> str:
    """Compose a retrieval query from alert fields."""
    parts = [
        f"Rule: {alert.rule_name}",
        f"Description: {alert.description or ''}",
        f"MITRE: {alert.mitre_tactic} / {alert.mitre_technique} ({alert.mitre_technique_id})",
        f"Severity: {alert.severity.value}",
        f"Source IP: {alert.source_ip or ''}",
    ]
    if alert.evidence:
        parts.append("Evidence: " + "; ".join(e.raw_message for e in alert.evidence[:3]))
    return "\n".join(p for p in parts if p.strip())


def retrieve(alert: Alert, config: RetrievalConfig | None = None) -> list[RetrievedIncident]:
    """Return top-k retrieved incidents with similarity scores."""
    config = config or RetrievalConfig()
    store = get_vector_store()
    if store.count() == 0:
        return []
    query = build_query_text(alert)
    raw = store.query(query, k=config.top_k, where=config.filter)
    out: list[RetrievedIncident] = []
    for hit in raw:
        meta = hit["metadata"]
        pair = IncidentResponsePair(
            incident_id=meta.get("incident_id", hit["id"]),
            title=meta.get("title", "Unknown"),
            description="",
            attack_pattern=meta.get("attack_pattern", ""),
            log_characteristics="",
            mitre_tactic=meta.get("mitre_tactic", ""),
            mitre_technique=meta.get("mitre_technique", ""),
            mitre_technique_id=meta.get("mitre_technique_id", ""),
            severity=meta.get("severity", "MEDIUM"),
            analyst_investigation="",
            response_playbook={"steps": []},
            resolution="",
            lessons_learned="",
            source=meta.get("source", "synthetic"),
        )
        # Convert cosine distance -> similarity (1 - distance for cosine space)
        similarity = 1.0 - hit["distance"]
        out.append(
            RetrievedIncident(
                incident=pair,
                similarity=similarity,
                matched_fields=[],
            )
        )
    return out