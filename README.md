# Universal Vulnerability Tracker (UVT) — v2.24.0

A full-stack vulnerability management platform with a Python/Flask API backend and vanilla JavaScript frontend. Track products, software components, vulnerabilities, SLA compliance, and risk trends across your organization.

**Key capabilities:**
- Product catalog with SBOM ingestion (CycloneDX/SPDX) and dependency graphing
- Vulnerability lifecycle management with severity, status, SLA tracking, and merge/dedup
- Team-based access control (Default team + custom teams) layered on top of Admin / Analyst / Viewer roles, JWT + cookie auth, optional OIDC SSO and email verification on sign-up
- Multi-widget dashboard with risk trends, SLA deadlines, and per-user work queues
- Plugin framework for external feeds (NVD, ExploitDB, CISA KEV) and integrations (Slack, Jira)
- Inbound webhooks + bulk scanner imports (Nessus / Qualys / Trivy)
- Known-exploited (KEV) flagging, watched-vulnerability notifications, and remediation (MTTR) metrics
- Background job queue (Celery + Redis) with metrics, caching, and async PDF rendering
- Branded PDF reports (WeasyPrint + Matplotlib) with executive-summary layout, severity donut, and SLA bar
- Full-text search, notification rules, report scheduling, API versioning (`/api/v1/*`)
- User preferences, keyboard shortcuts, and light/dark theme

## Quick Start

### Prerequisites
- Python 3.11+
- Optional: PostgreSQL (default is local SQLite), Redis (for Celery, caching, rate limiting)

### Backend
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export FLASK_APP=backend.uvt_app
flask run --debug          # http://127.0.0.1:5000
flask seed-admin --username admin --email admin@example.com --password 'CHOOSE-A-STRONG-PASSPHRASE'
```

### Frontend
```bash
cd frontend && python -m http.server 5173   # http://127.0.0.1:5173
```

### Docker
```bash
docker compose up --build
```

Services: backend (Gunicorn), frontend (Nginx), PostgreSQL, Redis, Celery worker + beat.

## Documentation

| Document | Description |
|----------|-------------|
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Production deployment — env vars, Docker, K8s, backups, runbook |
| [docs/BACKEND.md](docs/BACKEND.md) | Backend architecture — modules, models, services, auth, CLI |
| [docs/FRONTEND.md](docs/FRONTEND.md) | Frontend architecture — pages, routes, state, API adapters |
| [docs/TESTING_README.md](docs/TESTING_README.md) | Testing guide — pytest, smoke tests, repo hygiene |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Version history |
| [docs/backend-architecture.md](docs/backend-architecture.md) | Model bounded context rules |
| [SECURITY_FIXES.md](SECURITY_FIXES.md) | Security audit findings and fixes |
| [FEATURE_ROADMAP.md](FEATURE_ROADMAP.md) | Feature roadmap and status |
| [VISUAL_REWORK.md](VISUAL_REWORK.md) | Frontend visual design improvements |
