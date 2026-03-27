# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Universal Vulnerability Tracker (UVT) — a full-stack vulnerability management platform with a Python/Flask API backend and vanilla JavaScript frontend (no bundler, ES modules).

## Common Commands

### Backend

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run API server (http://127.0.0.1:5000)
export FLASK_APP=backend.uvt_app
flask run --debug

# Seed admin user
flask seed-admin --username admin --email admin@example.com --password changeme

# Run plugins / notification scan
flask run-plugins [--plugin-id ID] [--include-disabled] [--only-due]
flask run-notification-scan [--dry-run]
```

### Frontend

```bash
# Serve frontend (http://127.0.0.1:5173)
cd frontend && python -m http.server 5173
```

### Testing

```bash
# Backend tests with coverage
pytest --cov=backend --cov-report=term-missing

# Run a single test file or test
pytest backend/tests/test_auth.py
pytest backend/tests/test_auth.py::test_function_name -v

# Frontend smoke tests
node --test frontend/tests/**/*.test.js
# or: npm run test:smoke
```

### Repository Hygiene

```bash
./scripts/check-no-artifacts.sh   # CI runs this — no .pyc or __pycache__ in repo
```

## Architecture

### Backend (`/backend/`)

**App factory** in `backend/uvt_app.py` — initializes CORS, auth, DB, plugins.

**Three-layer design:** Blueprints → Services → Models

- **`/backend/api/`** — Flask blueprints (17 route modules: auth, products, vulnerabilities, reports, plugins, notifications, users, etc.)
- **`/backend/services/`** — Business logic (auth, notifications, SBOM ingest, CVE enrichment, deduplication, Jira sync, email, Slack, reporting, SLA tracking)
- **`/backend/models/`** — SQLAlchemy models organized by bounded context:
  - `auth.py` — User, ApiToken, RefreshToken, AuditLog
  - `products.py` — Product, ProductVersion, Control, SoftwareComponent, ComponentDependency
  - `vulnerabilities.py` — Vulnerability, VulnerabilityComment, AttackVector, SlaPolicy, SavedVulnerabilityFilter
  - `notifications.py` — Notification, NotificationRule, NotificationDeliveryLog
  - `plugins.py` — PluginConfig, PluginRun, PluginRunArtifact, ExternalSourceState
  - `reports.py` — ReportSchedule, ReportTemplate, ReportArtifact
- **`/backend/serializers/`** — JSON schema definitions
- **`/backend/plugins/`** — Plugin execution framework
- **`backend/auth.py`** — Token generation, password hashing, scope enforcement
- **`backend/permissions.py`** — Role-based access control (Admin/Analyst/Viewer)

**Cross-context model rules:** Use string relationship targets (`db.relationship("User")`) and table-name foreign keys (`db.ForeignKey("users.id")`). Import models from `backend/models/__init__.py`.

### Frontend (`/frontend/`)

Vanilla JS with hash-based routing, no framework or bundler.

- **`/frontend/src/main.js`** — Bootstrap, live notifications, session refresh
- **`/frontend/src/router/`** — Hash router with auth/role guards
- **`/frontend/src/state/`** — Centralized store, permissions, session management
- **`/frontend/src/api/`** — API adapters per domain
- **`/frontend/src/features/`** — Feature modules (dashboard, vulnerabilities)
- **`/frontend/src/views/`** — Page components
- **`/frontend/src/ui/`** — Shared UI primitives (modals, forms, toast)

### Configuration

Key env vars (see `/backend/dev.env` for full list):

- `DATABASE_URL` — default: `sqlite:///uvt.db`; supports PostgreSQL
- `SECRET_KEY` / `JWT_SECRET` — signing secrets (have dev defaults)
- `ALLOW_PUBLIC_REGISTRATION` — enables `/api/auth/register` (default: `false`; tests set `true`)
- `CORS_ALLOWED_ORIGINS` — comma-separated origins
- `RATE_LIMIT_ENABLED` / `RATE_LIMIT_BACKEND` — `memory` or `redis`
- `OIDC_*` — Optional SSO configuration
- `PLUGIN_IMPORT_PATHS` — comma-separated Python module paths for custom plugins
- Frontend API base override: `window.__UVT_API_BASE__`

### Testing Notes

- Backend tests use in-memory SQLite with shared fixtures in `/backend/tests/conftest.py`
- Key fixtures: `app`, `client`, `user_factory`, `admin_user`, `auth_header`, `sample_product_version`, `sample_vulnerabilities`
- Frontend smoke tests validate router guards, API adapter contracts, query composition
- CI workflow (`repo-hygiene.yml`) prevents Python bytecode/build artifacts from being committed
