# Implementation Roadmap

Organized by priority and dependency, not by date. Each task lists its
objective, dependencies, acceptance criteria, status and how it is verified.
Status values: **DONE**, **IN PROGRESS**, **TODO**, **MANUAL** (needs a person
with network access or provider credentials).

Evidence for every DONE item is in
[simulation-workflow-audit.md](simulation-workflow-audit.md).

## Blockers vs. improvements

These stand between the project and a convincing demo:

1. **P2.6** Verify real-model retrieval and confidence values. If real similarities never reach the auto-resolve threshold, the demo shows only escalations.
2. **P3.6** Verify a live Groq run end to end.
3. **P1.5** Merge the confidence-scoring PR (#3) and this branch.

Everything else improves the demo but does not block it.

---

## Priority 1: Establish a reliable baseline

| ID | Task | Depends on | Acceptance criteria | Status | Verification |
|---|---|---|---|---|---|
| P1.1 | Inspect repo, git state, dependencies, config and tests | — | Baseline recorded | DONE | audit "Baseline" section |
| P1.2 | Run existing tests and record real failures | P1.1 | Failures listed with root cause | DONE (86 pass, 11 fail on model download) | `pytest` |
| P1.3 | Reconcile README and previous claims with the code | P1.1 | No stale day plan or unsupported numbers in README | DONE | README review |
| P1.4 | Make missing RAG data, missing deps and model failures explicit, not silent or fatal | P1.1 | `rag_status` on every incident, `/health` shows `rag.error`, no HTTP 500 | DONE | `test_missing_historical_dataset_*`, `test_embedding_model_failure_*` |
| P1.5 | Land open work: PR #3 (confidence), then this branch | — | Both merged to `master`, CI-equivalent `pytest` green | TODO | GitHub |
| P1.6 | Isolate tests from `data/vectorstore` and from the network | — | Tests use temp ChromaDB dirs; offline run passes; model-dependent tests skip with a reason | DONE | `pytest` → 114 passed, 6 skipped |

## Priority 2: Complete and verify the core pipeline

| ID | Task | Depends on | Acceptance criteria | Status | Verification |
|---|---|---|---|---|---|
| P2.1 | Log generation for all scenarios | — | Deterministic, ground-truth labelled | DONE | `test_log_generator.py` |
| P2.2 | Rules, evidence, severity, MITRE mapping | P2.1 | Each scenario fires only its rule; evidence covers all malicious events | DONE | `test_detection_rules.py`, integration tests |
| P2.3 | Alerts, dedup, incident creation, audit entries | P2.2 | One incident per alert, exact timeline order | DONE | integration tests |
| P2.4 | RAG indexing, persistence, matches on incident | P1.4 | Matches with similarity, technique and severity on the incident and in the audit | DONE (stand-in embedding) | integration tests |
| P2.5 | Confidence scoring, rationale, no-match behaviour | P2.4 | Score in [0,1], reasons in audit, 0.0 when no matches | DONE | `test_confidence.py` |
| P2.6 | Real-model retrieval quality and real confidence values | P2.4 | `pytest backend/tests/test_retrieval.py -s` passes; record top similarity per scenario in the audit | MANUAL | run locally with internet |
| P2.7 | Grow the historical dataset beyond 5 pairs (several per technique, including benign/false-positive cases) | P2.6 | Retrieval evaluation still ≥ 90% top-3 with ≥ 3 candidates per technique | TODO (improvement) | `test_retrieval.py` |
| P2.8 | Decide confidence tiers if a single 0.85 threshold proves too blunt | P2.6 | Documented tiers, tests updated | TODO (only if P2.6 shows the need) | `test_confidence.py` |

## Priority 3: AI-assisted L1 triage

| ID | Task | Depends on | Acceptance criteria | Status | Verification |
|---|---|---|---|---|---|
| P3.1 | Agent receives confidence, matches and RAG status | P2.5 | Prompt contains them | DONE | `test_prompt_includes_rag_matches_and_confidence` |
| P3.2 | Structured output; handle malformed replies, errors, timeouts, missing key | — | Each case escalates with a named guardrail | DONE | `test_llm_failures_escalate[*]`, `test_llm_provider_error_escalates` |
| P3.3 | Deterministic guardrails independent of the LLM (confidence, no history, RAG down, HIGH/CRITICAL, unknown action) | P3.2 | LLM `AUTO_RESOLVE` cannot bypass any of them | DONE | `test_guardrails_override_auto_resolve[*]`, `test_high_severity_*` |
| P3.4 | Approved catalog of simulated actions only | — | Unknown actions rejected; no side effects | DONE | `test_pipeline_never_opens_sockets_or_processes` |
| P3.5 | Decision, rationale, action and outcome in timeline | P3.3 | `AGENT_DECISION`, `RESPONSE_ACTION`, closing entry | DONE | integration tests |
| P3.6 | Live Groq run | P3.2 | All scenarios produce a parsed `llm_decision` | MANUAL | set `GROQ_API_KEY`, run all scenarios |

## Priority 4: Dashboard and reporting

| ID | Task | Depends on | Acceptance criteria | Status | Verification |
|---|---|---|---|---|---|
| P4.1 | Show evidence, severity, matches, confidence and reasons, decision, guardrails, response status, escalation reason, timeline | P3.5 | All visible in incident detail | DONE | live browser run |
| P4.2 | Metrics reflect stored state with honest labels | — | Detection rate = malicious events covered; "Incidents" not "Open Incidents" | DONE | integration tests + browser run |
| P4.3 | Report consistency | — | JSON report equals stored incident; text shows the same fields | DONE | integration tests |
| P4.4 | Human action on escalated incidents (approve or close) | P4.1 | `POST /incidents/{id}/resolve` sets `CLOSED` and appends an audit entry; button in UI | TODO (improvement; strengthens the "human in the loop" story) | new tests |
| P4.5 | Reset endpoint/button for repeat demos | — | `POST /reset` clears stores and stats | TODO (improvement) | new test |

## Priority 5: Reliability and developer experience

| ID | Task | Depends on | Acceptance criteria | Status | Verification |
|---|---|---|---|---|---|
| P5.1 | Tests per pipeline stage, including failure paths | — | Integration suite present | DONE | `test_workflow_integration.py` |
| P5.2 | Reproducible dependencies (pin or lock Python deps) | — | `pip install` from a lock gives the tested versions | TODO | fresh venv install |
| P5.3 | CI: `pytest` + `npm run build` on push | P5.2 | Workflow green on `master` | TODO | GitHub Actions |
| P5.4 | Lint and type checks (e.g. ruff; `tsc` already runs in `npm run build`) | P5.3 | Clean run in CI | TODO (improvement) | CI |
| P5.5 | Docker / Compose for one-command startup | P5.2 | `docker compose up` serves API and dashboard; model cached in a volume | TODO (improvement) | manual run |
| P5.6 | Troubleshooting notes (model download, missing key, port clash) | — | README section | TODO (improvement) | review |

## Priority 6: Portfolio readiness

| ID | Task | Depends on | Acceptance criteria | Status | Verification |
|---|---|---|---|---|---|
| P6.1 | Clean-setup run of the whole workflow | P1.5, P2.6, P3.6 | Fresh clone → README steps → all scenarios → expected outcomes | TODO | manual, recorded in audit |
| P6.2 | Record real test results and limitations | P6.1 | Audit updated with real-model numbers | TODO | audit |
| P6.3 | README, roadmap, UI and code agree | P6.1 | Review pass | TODO | review |
| P6.4 | Demo script for a recruiter or interviewer | P6.1 | Below, refreshed with real numbers | DRAFT | dry run |

### Demo script (draft)

1. Start the API and dashboard (README → Setup). Point out the warning banner if no Groq key is set.
2. Click **brute force**. One HIGH alert appears; open it and walk through the evidence (25 failed SSH logins), MITRE T1110, historical matches, confidence breakdown, and the `high_severity` guardrail forcing escalation with the response left pending approval.
3. Click **suspicious command**. MEDIUM alerts appear; show how confidence and the LLM verdict decide between auto-resolve and escalate, and that the response is marked `simulated`.
4. Open the analyst report for one incident and show it matches the timeline.
5. Show `/metrics` and `/docs`, then explain that detection is deterministic and the LLM can only make outcomes more cautious.

## Out of scope

Real integrations (SIEM, EDR, firewall APIs), a database migration away from
in-memory storage, multi-agent setups, and performance work. None of these
strengthens the core demo.
