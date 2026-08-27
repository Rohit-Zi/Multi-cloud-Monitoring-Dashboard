# CloudGuard — Multi-Cloud Security Command Center

A security monitoring platform that ingests **real AWS activity via CloudTrail**, evaluates it against a rule engine, and surfaces alerts in a live multi-cloud dashboard. Built to answer one question continuously: *did anything suspicious just happen in this cloud account, and how bad is it?*

AWS integration is live and real — not simulated. Azure and GCP are architected for the same pattern and are the next connectors to land.

---

## Why this exists

Most student cloud-security projects stop at "generate a fake alert and show it in a table." This one goes further: it authenticates against a real AWS account, pulls actual CloudTrail events, runs them through a rule engine, and persists genuine alerts — while keeping a simulator alongside it for controlled testing and demos. The line between "real" and "test" data is a deliberate part of the design, not an afterthought.

---

## Architecture

```
                         AWS ACCOUNT
                             │
                    CloudTrail Event History
                    (free, 90-day, no Trail required)
                             │
                             ▼
                      aws_connector.py
              ┌──────────────┴──────────────┐
              │                             │
        normalize_event()          get_rule_event_type()
     (raw AWS JSON → common          (maps real AWS event
      Log schema)                    names → rule keys)
              │                             │
              └──────────────┬──────────────┘
                             ▼
                       Rule Engine
              (per-provider rulebook: severity,
                 alert title, alert eligibility)
                             │
                  ┌──────────┴──────────┐
                  │                     │
             no match               match found
                  │                     │
                  ▼                     ▼
             Log only            Log + linked Alert
                  │                     │
                  └──────────┬──────────┘
                             ▼
                    SQLite (SQLAlchemy + Alembic)
                             │
                             ▼
                        FastAPI REST API
                             │
                             ▼
                    React Dashboard (per-cloud tabs)

     ┌─────────────────────────────────────────────┐
     │  CloudTrail Simulator — parallel test path   │
     │  Same Rule Engine, fabricated events, used   │
     │  for demos and rule testing without touching │
     │  real AWS.                                   │
     └─────────────────────────────────────────────┘
```

Two ways real data reaches the database:
- **On-demand:** `POST /aws/sync` — pulls and processes events immediately
- **Automatic:** a background scheduler polls every 5 minutes with an overlapping 15-minute lookback window

Both paths share one function (`process_aws_event`), so there's a single source of truth for how an event becomes a log or an alert — not two versions of the same logic drifting apart.

---

## Key design decisions

**Deduplication is identity-based, not timing-based.** Every log stores CloudTrail's own `EventId` under a unique constraint. Overlapping polling windows, manual syncs, and the scheduler can all run against the same time range without ever producing duplicate rows — correctness doesn't depend on getting the timing exactly right.

**Logs and alerts are decoupled.** `alert_id` on a log is nullable by design: routine activity is recorded as a log for audit purposes, but only events the Rule Engine actually flags become alerts. This mirrors how real CloudTrail-based monitoring works — most events are noise, and a monitoring tool that alerts on everything is not usefully different from one that alerts on nothing.

**Least-privilege AWS access.** The connector authenticates as a dedicated, read-only IAM identity — not an administrative account. It can read CloudTrail and (soon) describe resources; it cannot create, modify, or delete anything in the AWS account it monitors.

**No AWS credentials leave the backend.** The frontend never talks to AWS directly — every request goes through the FastAPI layer, which is the only component holding cloud credentials.

---

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript, TailwindCSS, Recharts |
| Backend | FastAPI, SQLAlchemy, Alembic (migrations) |
| Database | SQLite (dev) |
| Cloud SDK | boto3 (AWS) |
| Scheduling | APScheduler |
| Detection | Custom Rule Engine + Severity Normalizer |

---

## Getting started

### Backend
```bash
cd Backend
python -m venv venv
.\venv\Scripts\Activate.ps1        # Windows
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```
Runs on `http://127.0.0.1:8000` — interactive API docs at `/docs`.

**AWS credentials:** configure a read-only IAM user (`ReadOnlyAccess` policy is sufficient) via:
```bash
aws configure
```
The connector uses whatever credentials are active in the environment — never hardcode keys into the project.

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Runs on `http://localhost:5173`.

---

## Project structure
```
project-minor/
├── Backend/
│   ├── app/
│   │   ├── api/            # FastAPI routers (alerts, logs, simulator, aws_router)
│   │   ├── connectors/      # aws_connector.py — real cloud data ingestion
│   │   ├── models/          # SQLAlchemy models (Alert, Log, User, Insight)
│   │   ├── processors/      # RuleEngine, SeverityNormalizer
│   │   ├── services/        # CloudTrailSimulator, LogGenerator, aws_poller
│   │   └── db/
│   ├── alembic/              # Schema migrations
│   └── requirements.txt
└── frontend/
    └── src/
```

---

## Current scope and roadmap

This is a working single-account monitoring tool, not a multi-tenant SaaS product — that distinction is intentional, not an oversight. Extending it to let arbitrary customers connect their own cloud accounts would require per-tenant IAM role assumption, tenant-scoped data isolation, and a substantially larger security review; that's out of scope for this project's current stage and is noted here deliberately rather than left unaddressed.

**Done:**
- Real AWS CloudTrail ingestion, normalization, and rule-based alerting
- Deduplicated, automatic + on-demand sync
- Least-privilege AWS credentials
- Git-safe secrets handling

**In progress / planned:**
- AWS resource discovery (real EC2 / S3 / IAM inventory, not alert-derived)
- Explicit `real` vs. `simulated` data tagging
- App-level authentication (JWT-based) ahead of containerization
- Docker packaging (backend, frontend, database)
- Azure connector, mirroring the same architecture
- GCP connector

**Known limitation:** IAM console sign-in events are recorded by AWS in a region determined by browser session state, not the account's default region — the connector currently polls a single region and does not yet account for this.

---

## Author
Rohit Zi
