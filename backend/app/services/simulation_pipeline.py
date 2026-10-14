"""End-to-end simulation pipeline.

Wires the deterministic chain for one scenario:

    generate logs -> detect -> alert -> [RAG retrieval] -> [confidence] -> [L1 agent] -> incident

Confidence must be scored before the L1 agent runs: the agent escalates any
incident with no confidence. RAG problems (empty knowledge base, embedding
model unavailable, retrieval error) are recorded on the incident as
``rag_status`` plus a ``RAG_SEARCH_PERFORMED`` audit entry rather than raised.

Pipeline statistics accumulate across calls so /metrics (spec section 39) can
report on real simulated data only -- never fabricated values.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.models.alert import Alert
from app.models.incident import AuditEntry, Incident
from agent.l1_analyst import L1Analyst, get_l1_analyst
from alerts.alert_manager import AlertManager
from detection.rule_engine import detect
from rag.retriever import RetrievalConfig, build_query_text, get_vector_store, retrieve
from simulation.log_generator import SCENARIOS, generate_scenario
from triage.confidence import score_confidence


logger = logging.getLogger(__name__)

# RAG outcome recorded on every incident (``Incident.rag_status``) so a missing
# knowledge base or embedding model is visible instead of looking like "no
# similar history".
RAG_OK = "ok"  # at least one historical match retrieved
RAG_NO_MATCHES = "no_matches"  # search ran, nothing came back
RAG_UNAVAILABLE = "unavailable"  # knowledge base empty or failed to index
RAG_ERROR = "error"  # the search itself raised


@dataclass
class PipelineStats:
    total_logs: int = 0
    malicious_logs: int = 0
    # Malicious (ground-truth) logs that appear in at least one detection's
    # evidence. detection_rate = detected_malicious_logs / malicious_logs.
    detected_malicious_logs: int = 0
    total_detections: int = 0
    incidents: dict[str, IndividualStats] = field(default_factory=dict)


@dataclass
class IndividualStats:
    incidents: int = 0
    alerts: int = 0
    detections: int = 0


def _incident_counter() -> int:
    global _incident_seq
    _incident_seq += 1
    return _incident_seq


_incident_seq = 0
pipeline_stats = PipelineStats()
_rag_initialized = False
# Why RAG is not ready (None once indexing succeeded); copied into the audit trail.
_rag_error: str | None = None


def reset_pipeline() -> None:
    """Reset counter + stats; used by tests. Fresh-session button may reuse."""
    global _incident_seq
    _incident_seq = 0
    pipeline_stats.total_logs = 0
    pipeline_stats.malicious_logs = 0
    pipeline_stats.detected_malicious_logs = 0
    pipeline_stats.total_detections = 0
    pipeline_stats.incidents.clear()


def initialize_rag() -> int:
    """Load synthetic pairs and index into vector store; returns count indexed."""
    from rag.playbooks import load_and_index
    return load_and_index()


def _ensure_rag() -> None:
    """Index the knowledge base once; on failure remember why and retry next run.

    Never raises: a missing dataset or embedding model must not take down the
    simulation. Incidents then carry ``rag_status="unavailable"`` and the L1
    guardrails escalate them.
    """
    global _rag_initialized, _rag_error
    if _rag_initialized:
        return
    try:
        indexed = initialize_rag()
    except Exception as exc:  # model download, chroma, malformed dataset...
        logger.warning("RAG initialization failed: %s", exc)
        _rag_error = f"knowledge base indexing failed: {type(exc).__name__}: {exc}"[:500]
        return
    if indexed == 0:
        _rag_error = "knowledge base is empty: no historical incidents were indexed"
        return
    _rag_initialized = True
    _rag_error = None


def rag_status() -> dict:
    """Current RAG readiness, for /health and the dashboard."""
    return {"ready": _rag_initialized, "error": _rag_error}


def _historical_context(alert: Alert, rag_config: RetrievalConfig) -> tuple[list[dict], dict]:
    """Retrieve historical matches; returns (matches, audit detail). Never raises."""
    detail: dict = {"top_k": rag_config.top_k}
    if not _rag_initialized:
        return [], {**detail, "status": RAG_UNAVAILABLE, "match_count": 0, "error": _rag_error}
    try:
        retrieved = retrieve(alert, rag_config)
    except Exception as exc:
        logger.warning("RAG retrieval failed for %s: %s", alert.alert_id, exc)
        error = f"{type(exc).__name__}: {exc}"[:500]
        return [], {**detail, "status": RAG_ERROR, "match_count": 0, "error": error}
    matches = [
        {
            "incident_id": r.incident.incident_id,
            "title": r.incident.title,
            "similarity": r.similarity,
            "mitre_technique_id": r.incident.mitre_technique_id,
            "severity": r.incident.severity,
        }
        for r in retrieved
    ]
    return matches, {
        **detail,
        "status": RAG_OK if matches else RAG_NO_MATCHES,
        "match_count": len(matches),
        "matches": [
            {"incident_id": m["incident_id"], "similarity": round(m["similarity"], 3)} for m in matches
        ],
    }


def run_scenario(
    scenario: str,
    manager: AlertManager | None = None,
    seed: int | None = None,
    rag_config: RetrievalConfig | None = None,
    analyst: L1Analyst | None = None,
) -> dict:
    """Run one full simulated scenario through the pipeline.

    Returns a summary dict grouped per alert/incident so the API can return a
    compact payload while the stores keep the full objects.
    """
    if scenario not in SCENARIOS:
        raise KeyError(f"unknown scenario {scenario!r}; choose from {sorted(SCENARIOS)}")

    manager = manager or _default_manager
    rag_config = rag_config or RetrievalConfig()
    _ensure_rag()
    logs = generate_scenario(scenario, seed=seed)
    detections = detect(logs)

    detected_keys = {(e.timestamp, e.raw_message) for d in detections for e in d.evidence}
    malicious = [e for e in logs if e.metadata.get("ground_truth") is True]
    pipeline_stats.total_logs += len(logs)
    pipeline_stats.malicious_logs += len(malicious)
    pipeline_stats.detected_malicious_logs += sum(
        1 for e in malicious if (e.timestamp, e.raw_message) in detected_keys
    )
    pipeline_stats.total_detections += len(detections)

    alerts: list[Alert] = []
    incidents: list[Incident] = []
    for detection in detections:
        alert = manager.create_alert(detection)
        if alert is None:
            continue  # duplicate, already covered by an open alert
        alerts.append(alert)
        incident = Incident.from_alert(f"INC-{_incident_counter():04d}", alert)

        # RAG: historical context (failures are recorded, never raised)
        incident.historical_matches, rag_detail = _historical_context(alert, rag_config)
        incident.rag_status = rag_detail["status"]
        searched_at = datetime.now(timezone.utc)
        incident.timeline.append(
            AuditEntry(timestamp=searched_at, event="RAG_SEARCH_PERFORMED", detail=rag_detail)
        )

        # Confidence from rule severity + RAG matches (deterministic, no LLM)
        result = score_confidence(
            alert.severity, alert.mitre_technique_id, incident.historical_matches
        )
        incident.confidence = result.score
        alert.confidence = result.score
        scored_at = datetime.now(timezone.utc)
        incident.timeline.append(
            AuditEntry(timestamp=scored_at, event="CONFIDENCE_SCORED", detail=result.audit_detail())
        )
        incident.updated_at = scored_at

        # L1 agent decides auto-resolve vs escalate (simulated response)
        (analyst or get_l1_analyst()).triage(incident)
        alert.status = incident.status

        _default_incident_store.add(incident)
        incidents.append(incident)

    entry = pipeline_stats.incidents.setdefault(
        scenario, IndividualStats()
    )
    entry.detections = len(detections)
    entry.alerts += len(alerts)
    entry.incidents += len(incidents)

    return {
        "scenario": scenario,
        "log_count": len(logs),
        "detection_count": len(detections),
        "alert_count": len(alerts),
        "incident_count": len(incidents),
        "alerts": [a.alert_id for a in alerts],
        "incidents": [i.incident_id for i in incidents],
        "decisions": {i.incident_id: i.agent_decision for i in incidents},
    }


# Late-import singletons depend on module-level circular-safe imports.
from alerts.alert_manager import alert_manager as _default_manager  # noqa: E402
from app.models.incident_store import incident_store as _default_incident_store  # noqa: E402