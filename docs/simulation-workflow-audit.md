# Simulation Workflow Audit

**Audited:** 2026-10-14, on branch `claude/project-thread-60esf1`. That branch is
stacked on the confidence-scoring branch (PR #3), which sits on `master` after
PRs #1 and #2.

**Method:** the code path was traced from `POST /simulate/{scenario}` to the
final incident state. Each stage was checked by a test
(`backend/tests/test_workflow_integration.py` unless noted), and the API and
dashboard were run live in a headless Chromium.

**Environment limits:** this environment cannot reach huggingface.co, so the
real `all-MiniLM-L6-v2` model never loaded here. Integration tests and the live
dashboard run used a **stand-in hashed embedding** (`stand_in_embed` in
`backend/tests/conftest.py`). It proves indexing, persistence and wiring, not
retrieval quality. No Groq key was available, so LLM behaviour was tested with
LangChain's `FakeListChatModel` only.

## Baseline (before this round of changes)

- `pytest`: **86 passed, 11 failed**. All 11 failures were `httpx.ProxyError: 403` while downloading the embedding model: 5 tests in `test_api_simulate.py` and 6 in `test_retrieval.py`.
- The README described a day-by-day plan ("Later phases add `rag/`, `agent/`…") although RAG, confidence and the L1 agent already existed. It also claimed "detection rate 100%", which is true only under the evaluation harness's own definition.
- Commit `36cd545` says "50 synthetic pairs, retrieval 100% accuracy". The dataset has **5** pairs, and with 5 candidates a top-3 hit is a weak test.
- RAG problems were silent or fatal. A missing dataset gave empty matches with no explanation, and an embedding-model failure made `/simulate` return HTTP 500.
- HIGH-severity incidents could auto-resolve. In practice only perfect similarity reaches 0.85, but no guardrail stopped it.
- `/metrics.detection_rate` was `detections / malicious events`, so `brute_force` showed 4% (1 detection over 25 events).
- Tests read and wrote the real `data/vectorstore/`, and `test_vector_store_indexed` passed only if an earlier run had already indexed it.
- The dashboard labelled the total incident count "Open Incidents" and showed stale "Day 4 / Day 6" placeholders.

## Changes made during this audit

| Problem | Fix | Where |
|---|---|---|
| RAG failure was fatal or silent | `_ensure_rag()` never raises; each incident gets `rag_status` (`ok`, `no_matches`, `unavailable`, `error`) and a `RAG_SEARCH_PERFORMED` audit entry; `/health` reports `rag.ready` and `rag.error` | `simulation_pipeline.py`, `incident.py`, `health.py` |
| RAG outage not a guardrail | new `rag_unavailable` guardrail | `agent/l1_analyst.py` |
| HIGH severity not escalated | new `high_severity` guardrail | `agent/l1_analyst.py` |
| LLM call could hang | `ChatGroq(timeout=20, max_retries=1)` | `agent/l1_analyst.py` |
| Misleading detection rate | now `detected_malicious_logs / malicious_logs`; outcome counts read from incidents | `simulation_pipeline.py`, `metrics.py` |
| Tests coupled to network and real store | per-test temp ChromaDB; stand-in embedding by default; `real_embeddings` marker skips with "MANUAL VERIFICATION REQUIRED" | `tests/conftest.py`, `pytest.ini`, `test_retrieval.py` |
| No end-to-end tests | 20 integration tests | `tests/test_workflow_integration.py` |
| Dashboard gaps | RAG status, match technique and severity, confidence reasons, LLM proposal vs final decision, guardrails, recommended response, LLM/RAG warning banners, correct labels | `frontend/src/` |

## Workflow table

| # | Stage | Expected behavior | Actual behavior | Evidence / test | Status |
|---|---|---|---|---|---|
| 1 | Simulation input | Known scenario names run; unknown ones are rejected without side effects | `run_scenario` raises `KeyError` for unknown names, mapped to 404 with the valid list; nothing is generated or stored | `simulate.py`; `test_unsupported_scenario_changes_nothing`, `test_unknown_scenario_returns_404` | PASS |
| 2 | Log generation | Deterministic per (scenario, seed); every event labelled with ground truth and scenario; safe IPs | Seeded `random.Random`, fixed base timestamp; `metadata.ground_truth/scenario/attack_category` on every event; RFC 5737 IPs (internal hosts use 10.0.0.0/8) | `log_generator.py`; `test_log_generator.py` (determinism, labels) | PASS |
| 3 | Detection | The expected rule fires; evidence is the triggering events; MITRE from registry; no benign false positives | Each scenario fires only its rule; evidence holds only ground-truth events and covers **all** of them; severity/tactic/technique match `mitre_mapping.RULES`; benign stream gives 0 detections | `test_scenario_end_to_end_without_llm[*]`, `test_detection_rules.py`, `test_detection_rate.py` (32/32 seeds) | PASS |
| 3a | Duplicate detections | Repeats controlled | Brute force uses non-overlapping 60 s windows (25 failures → 1 detection). Alert manager drops same-rule + same-evidence while the earlier alert is open; re-running a scenario creates 0 alerts | `test_rerun_is_deduplicated_while_escalations_are_open`, `test_alert_manager.py` | PASS |
| 4 | Alert and incident creation | Unique IDs, normalized severity, one incident per alert, linked IDs, lifecycle state | `ALERT-NNNN` / `INC-NNNN`; `incident.alert_id` links back; alert status mirrors the incident outcome. `TRIAGED` and `CLOSED` are defined but never set, and no human action endpoint exists | integration tests check counts, links and statuses | PARTIAL (no human lifecycle) |
| 5a | RAG: dataset and deps | Dataset present; deps declared | `data/incidents/synthetic_pairs.jsonl` has 5 valid records; `chromadb`, `sentence-transformers`, `numpy` in `requirements.txt` | file inspection; `test_vector_store_indexed` (real model) | PASS (5 records only) |
| 5b | RAG: indexing and persistence | Idempotent indexing into persistent ChromaDB | Content-hash IDs + `upsert`; `PersistentClient` at `VECTOR_STORE_PATH`; indexed once per process, retried on the next run after a failure | integration tests index into a temp dir via the real Chroma code path | PASS (stand-in embedding) |
| 5c | RAG: matches reach the incident | Top-k matches with similarity, technique and severity on the incident and in the audit trail | `historical_matches` has `incident_id`, `title`, `similarity`, `mitre_technique_id`, `severity`; `RAG_SEARCH_PERFORMED` lists IDs and similarities | `test_scenario_end_to_end_without_llm[*]` | PASS (wiring) |
| 5d | RAG: retrieval quality | The right historical incident ranks in the top 3 | Not runnable here (model download blocked). With the stand-in, the right pair ranked first in the live PowerShell run (0.44 vs 0.23) | `test_retrieval.py` skipped: **MANUAL VERIFICATION REQUIRED** | NOT VERIFIED |
| 6 | Confidence scoring | Score in [0,1], explained factors, conservative with no matches | Deterministic formula; full breakdown and reasons in `CONFIDENCE_SCORED`; no matches → 0.0 with an explicit reason; scored before the agent | `test_confidence.py` (18 tests), integration tests | PASS |
| 6a | Confidence tiers / reachability | It must be clear when auto-resolve is possible | Single threshold 0.85, no named tiers. MEDIUM needs a top similarity ≥ ~0.83 with exact technique and severity agreement; HIGH/CRITICAL can never auto-resolve. Real-model similarities are unknown | arithmetic from `triage/confidence.py`; `test_medium_incident_auto_resolves_when_llm_and_guardrails_agree` | PARTIAL (real-model values unverified) |
| 7 | L1 agent input | Agent gets the incident facts it needs | Prompt carries severity, MITRE, ≤5 evidence lines, matches, confidence and RAG status | `test_prompt_includes_rag_matches_and_confidence` | PASS |
| 7a | L1 agent output and guardrails | Valid structured decision; LLM can't bypass guardrails | JSON parsed into `LLMVerdict`; any guardrail turns `AUTO_RESOLVE` into `ESCALATE`; LLM `ESCALATE` always honoured; `llm_decision` kept in audit | `test_l1_analyst.py`, `test_high_severity_escalates_even_when_llm_says_auto_resolve[*]`, `test_llm_failures_escalate[*]` | PASS (fake LLM) |
| 7b | Live Groq call | Real model returns parseable verdicts | Not run; no API key available | — | MANUAL VERIFICATION REQUIRED |
| 8 | Response or escalation | Actions recorded, never executed; escalation updates incident and alert | Catalog-only actions; `simulated: true`; `SIMULATED` on auto-resolve, `PENDING_HUMAN_APPROVAL` on escalation; incident and alert both set to `AUTO_RESOLVED` / `ESCALATED`; `escalation_reason` filled only when escalated. A full auto-resolving run with `socket.connect` and `subprocess.Popen` patched to fail completes cleanly | `test_pipeline_never_opens_sockets_or_processes`, integration tests | PASS |
| 9 | Audit timeline | Ordered entries that reflect what happened | Exactly `ALERT_CREATED, DETECTION_RULE_TRIGGERED, RAG_SEARCH_PERFORMED, CONFIDENCE_SCORED, AGENT_DECISION, RESPONSE_ACTION, ESCALATED/INCIDENT_CLOSED`, timestamps non-decreasing. `RETRIEVED_INCIDENTS` is a declared event type that is never emitted (folded into `RAG_SEARCH_PERFORMED`) | integration tests assert the exact list | PASS |
| 10 | Reports and metrics | Reports and metrics agree with stored state | JSON report equals `GET /incidents/{id}`; Markdown shows the same status, decision and confidence; metrics totals equal store counts, `escalated + auto_resolved = incidents`, severity counts sum to alerts | `test_scenario_end_to_end_without_llm[*]`, `test_simulate_all_keeps_metrics_consistent` | PASS |
| 10a | Metric meaning | Labels match what is counted | `total_logs` and `total_detections` accumulate across reruns while alerts are deduped, so "Detections" can exceed "Total Alerts" (32 vs 15 after rerunning all scenarios). This is documented, not a bug | live run | PASS |
| 11 | Frontend | Buttons call the right endpoints; views refresh | Live headless-Chromium run: scenario button → `POST /simulate/brute_force`, "Run All" → `POST /simulate`; stat cards, feed, chart and incident detail updated; LLM warning banner shown; `npm run build` passes. No automated frontend tests | manual browser run, 2026-10-14 | PASS (manual) |
| 12 | Failure: missing API key | Escalate, keep running | `llm_unavailable` on every incident; banner on dashboard | `test_llm_failures_escalate[missing_api_key]` | PASS |
| 12 | Failure: LLM error / timeout | Escalate | `llm_error` | `test_llm_provider_error_escalates`, `test_llm_exception_escalates` | PASS |
| 12 | Failure: invalid agent output | Escalate | `llm_output_invalid` (prose and schema-violating JSON); `unknown_action` for actions outside the catalog | `test_llm_failures_escalate[*]` | PASS |
| 12 | Failure: missing RAG data | Explicit and safe | `rag_status=unavailable`, error text in audit and `/health`, confidence 0, escalated | `test_missing_historical_dataset_is_explicit_and_escalates` | PASS |
| 12 | Failure: embedding model unavailable | No 500; explicit | HTTP 200, `rag_unavailable`, escalated. Also seen live against the real model with the download blocked: `/health` showed `"knowledge base indexing failed: ProxyError: 403 Forbidden"` | `test_embedding_model_failure_does_not_break_simulation`, live run | PASS |
| 12 | Failure: retrieval error mid-run | No alert left without an incident | `rag_status=error`, every alert still gets an incident | `test_retrieval_error_mid_pipeline_is_recorded` | PASS |
| 12 | Failure: empty retrieval | Conservative | `no_matches`, confidence 0, `no_historical_match` | `test_empty_retrieval_scores_zero_and_escalates` | PASS |
| 12 | Failure: other partial failures | Pipeline fails cleanly | An exception outside RAG and the LLM (e.g. in `L1Analyst.apply`) would still surface as HTTP 500 and could leave a `NEW` alert without an incident. No such path is known to be reachable | code reading | NOT VERIFIED |

## Open findings

1. **Retrieval quality and real confidence values: MANUAL VERIFICATION REQUIRED.** Run `pytest backend/tests/test_retrieval.py -s` on a machine that can reach huggingface.co, then run all scenarios and note the top similarities and confidences. If real similarities sit well below 0.83, nothing can ever auto-resolve and the demo shows only escalations.
2. **Live Groq behaviour: MANUAL VERIFICATION REQUIRED.** Set `GROQ_API_KEY`, run all scenarios, and confirm the `AGENT_DECISION` entries show a parsed `llm_decision` rather than `llm_output_invalid` or `llm_error`.
3. **Knowledge base is small** (5 pairs, one per technique plus a password-spray variant).
4. **No human step.** Escalated incidents cannot be approved, closed or reset through the API or dashboard.
5. **No reset endpoint.** Demoing twice needs an API restart.
