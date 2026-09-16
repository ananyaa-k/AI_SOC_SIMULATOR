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

Active build. Day 1: foundation + log generator. Day 2: deterministic
detection layer (detection rate 100% on the eval harness). Day 3: alerts,
incidents, report generator, simulation API, and the React dashboard
foundation.

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

### Run the dashboard (Day 3+)

```powershell
cd frontend
npm install        # first time only
npm run dev        # http://127.0.0.1:5173  (proxies /alerts, /incidents, etc. to :8000)
```

One click of a **simulate** button triggers: generate logs -> detect -> alert
-> incident -> dashboard refresh.

### API

| Endpoint                  | Purpose                                    |
| ------------------------- | ------------------------------------------ |
| `GET /health`             | liveness                                   |
| `GET /alerts`             | alert feed (optional `severity`,`status`)  |
| `GET /alerts/{id}`        | single alert                              |
| `GET /incidents`          | incidents (optional `status`,`technique`) |
| `GET /incidents/{id}`     | single incident                           |
| `GET /incidents/{id}/report?format=json\|text` | incident report        |
| `POST /simulate`          | run every scenario once                    |
| `POST /simulate/{scenario}` | run one scenario end to end              |
| `GET /metrics`            | live metrics from real stored state        |

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

## Structure (Day 1-3)

```
backend/
  app/
    main.py                 # FastAPI app + routers
    config.py               # settings via .env (pydantic-settings)
    api/health.py           # GET /health
    api/alerts.py           # GET /alerts, GET /alerts/{id}
    api/incidents.py        # GET /incidents{,/{id}}, /incidents/{id}/report
    api/simulate.py         # POST /simulate{,/{scenario}}
    api/metrics.py          # GET /metrics
    models/security_log.py  # normalized SecurityLog schema
    models/alert.py         # Alert + Severity + Status
    models/incident.py      # Incident + AuditEntry (timeline)
    models/incident_store.py # in-memory incident store
    services/simulation_pipeline.py  # generate->detect->alert->incident
  detection/                # deterministic rule engine + MITRE registry (Day 2)
  alerts/alert_manager.py   # alert lifecycle + dedup (Day 3)
  reports/report_generator.py # JSON + analyst-readable reports (Day 3)
  simulation/log_generator.py # deterministic simulated log generator
  tests/                    # pytest suite
frontend/
  src/                      # React + TS + Recharts dashboard
data/
  logs/                     # generated sample logs
docs/
  log-schema.md             # SecurityLog reference
  detection-rules.md        # detection layer design + contract
```

Later phases add `rag/`, `agent/`, `response/`, Docker, and CI.

## Safety

This is a simulator. IPs use RFC 5737 documentation ranges, attack traffic is
fabricated, and no real infrastructure is ever modified. Historical incidents
(when added) are explicitly labeled as synthetic.

## Docs

- [docs/log-schema.md](docs/log-schema.md) – normalized security log schema