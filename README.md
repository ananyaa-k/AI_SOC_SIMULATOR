# AI SOC Simulator

Simulated Security Operations Center pipeline:

```
Attack Logs -> Deterministic Detection -> Alert -> RAG / Historical Context
            -> Confidence -> L1 AI Agent -> Auto-Resolve | Escalate -> Incident Report
```

A deliberately small, explainable project that separates **deterministic
security detection** from **AI-assisted triage and response decisions**. The
LLM never replaces the detection engine.

## Status

Active build. Day 1 complete: project foundation + deterministic log generator.
Day 2 in progress: deterministic detection layer (interface scaffolded; the
rule engine + rules are the owner's implementation).

## Stack

- Backend: Python, FastAPI, Pydantic, Uvicorn, pytest
- Frontend: React + Recharts (starting Day 3)
- Knowledge: ChromaDB or pgvector (starting Day 4)
- AI: Groq + LangChain, single L1 agent (starting Day 6)
- DevOps: Docker, docker-compose, GitHub Actions (Day 7)

## Setup (Day 1)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env   # optional now; required from Day 6
```

### Run the API

```powershell
uvicorn app.main:app --reload --app-dir backend
# http://127.0.0.1:8000/health
# docs at http://127.0.0.1:8000/docs
```

### Generate logs

```powershell
python -m simulation.log_generator --scenario brute_force --out ../data/logs/brute_force.ndjson
python -m simulation.log_generator --out ../data/logs/all.ndjson   # all scenarios
```

The generator is deterministic: the same `--seed` always produces identical
logs (default seeds are stable per scenario).

### Run tests

```powershell
pytest
```

## Structure (Day 1)

```
backend/
  app/
    main.py                 # FastAPI app
    config.py               # settings via .env (pydantic-settings)
    api/health.py           # GET /health
    models/security_log.py  # normalized SecurityLog schema
  simulation/
    log_generator.py        # deterministic simulated attack log generator
  tests/                    # pytest suite
data/
  logs/                     # generated sample logs
docs/
  log-schema.md             # field reference + design decisions
```

Later phases add `detection/`, `alerts/`, `rag/`, `agent/`, `reports/`,
`response/`, the React dashboard, Docker and CI.

## Safety

This is a simulator. IPs use RFC 5737 documentation ranges, attack traffic is
fabricated, and no real infrastructure is ever modified. Historical incidents
(when added) are explicitly labeled as synthetic.

## Docs

- [docs/log-schema.md](docs/log-schema.md) – normalized security log schema