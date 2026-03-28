# Universal Vulnerability Tracker (UVT) — v2.0.7

A full-stack vulnerability management platform with a Python/Flask API backend and vanilla JavaScript frontend. Track products, software components, vulnerabilities, SLA compliance, and risk trends across your organization.

**Key capabilities:**
- Product catalog with SBOM ingestion (CycloneDX/SPDX) and dependency graphing
- Vulnerability lifecycle management with severity, status, SLA tracking, and merge/dedup
- Role-based access control (Admin / Analyst / Viewer) with JWT + cookie auth and optional OIDC SSO
- Multi-widget dashboard with risk trends, SLA deadlines, and per-user work queues
- Plugin framework for external feeds (NVD, ExploitDB) and integrations (Slack, Jira)
- Notification rules with email, Slack, and webhook delivery + escalation
- Report templates and scheduled delivery (CSV, JSON, PDF)
- Security control catalog with framework mapping

## Table of Contents
- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
- [Configuration](#configuration)
- [Project Layout](#project-layout)
- [Testing](#testing)
- [v2 Improvements](#v2-improvements)
- [Documentation](#documentation)

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ (for frontend smoke tests only)
- Optional: PostgreSQL (default is local SQLite)

### Backend
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export FLASK_APP=backend.uvt_app
flask run --debug          # http://127.0.0.1:5000
flask seed-admin --username admin --email admin@example.com --password changeme
```

### Frontend
```bash
cd frontend && python -m http.server 5173   # http://127.0.0.1:5173
```

To point the frontend at a different API:
```html
<script>window.__UVT_API_BASE__ = "https://api.example.com";</script>
```

## Docker Deployment

```bash
docker compose up --build
```

Services: backend (Gunicorn), frontend (Nginx), PostgreSQL, Redis (rate limiting).

## Configuration

### Core
| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///uvt.db` | DB connection string (PostgreSQL supported) |
| `SECRET_KEY` | `dev-secret` | Flask session secret (**must change in prod**) |
| `JWT_SECRET` | `dev-jwt-secret` | Token signing secret (**must change in prod**) |
| `ALLOW_PUBLIC_REGISTRATION` | `false` | Enable `/api/auth/register` |

### CORS
| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ALLOWED_ORIGINS` | local dev origins | Comma-separated full origins |

### Auth Cookies
| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_COOKIE_SECURE` | `true` in production | `Secure` cookie flag |
| `AUTH_COOKIE_SAMESITE` | `Lax` | `Lax`, `Strict`, or `None` |
| `AUTH_COOKIE_DOMAIN` | unset | Cookie domain override |

### OIDC (Optional SSO)
| Variable | Description |
|----------|-------------|
| `OIDC_ENABLED` | Enable OIDC authentication |
| `OIDC_ISSUER` | OIDC provider issuer URL |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | OAuth2 client credentials |
| `OIDC_REDIRECT_URL` | Callback URL |
| `OIDC_SCOPES` | Requested scopes |
| `OIDC_GROUPS_CLAIM` | Claim for group-to-role mapping |
| `OIDC_ROLE_MAPPING` | JSON map of group names to UVT roles |

### Rate Limiting
| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `RATE_LIMIT_BACKEND` | `memory` | `memory` or `redis` |

### Plugins
| Variable | Description |
|----------|-------------|
| `PLUGIN_IMPORT_PATHS` | Comma-separated Python module paths for custom plugins |

See `backend/dev.env` for the full variable reference.

## Project Layout

```
backend/
  uvt_app.py          App factory
  config.py           Typed configuration (AppConfig dataclass)
  auth.py             JWT/cookie auth, API tokens, password hashing
  permissions.py      RBAC (Admin/Analyst/Viewer), scope enforcement
  database.py         SQLAlchemy setup, TZDateTime type
  rate_limiter.py     Sliding-window rate limiting (memory/Redis)
  cli.py              CLI commands (seed-admin, run-plugins, run-notification-scan)
  api/                24 Flask blueprints (auth, products, vulns, users, plugins, etc.)
  services/           Business logic (20 modules)
  models/             SQLAlchemy models by bounded context (auth, products, vulns, notifications, plugins, reports)
  serializers/        JSON response helpers
  plugins/            Plugin framework + 7 built-in plugins (NVD, ExploitDB, Slack, Jira, CIS, PCI-DSS, STIG)

frontend/
  index.html          HTML shell
  src/main.js         Bootstrap, SSE notifications, session management
  src/router/         Hash-based router with auth/role guards
  src/state/          Centralized store, session persistence, permissions
  src/api/            API adapters (16 modules)
  src/features/       Feature modules (dashboard, vulnerabilities)
  src/views/          Page components (18 views)
  src/ui/             Shared primitives (el, modal, toast, loading, filters, layout)
  assets/styles/      CSS (base, layout, components, pages)

scripts/              Dev setup, DB update, artifact checks
docs/                 Architecture docs
```

## Testing

```bash
# Backend tests with coverage
pytest --cov=backend --cov-report=term-missing

# Single test
pytest backend/tests/test_auth.py::test_function_name -v

# Frontend smoke tests
node --test frontend/tests/**/*.test.js
```

See `TESTING_README.md` for the full testing guide.

### Repository Hygiene
```bash
./scripts/check-no-artifacts.sh   # CI enforces no .pyc / __pycache__
```

## CLI Commands

```bash
flask seed-admin --username admin --email admin@example.com --password changeme
flask run-plugins [--plugin-id ID] [--include-disabled] [--only-due]
flask run-notification-scan [--dry-run]
flask shell   # Interactive Python shell with app context
```

## v2 Improvements

Planned improvements across security, features, and visual design — organized into phases by impact and dependency order.

### Phase 1 — Quick Security Wins ✅
Small, high-impact fixes to harden what's already deployed.

- ~~S1: Fix hardcoded `debug=True` in entry point~~ (v2.0.1)
- ~~S3: Tighten rate limits on user creation/invite~~ (v2.0.2)
- ~~S5: Log CSRF validation failures~~ (v2.0.3)
- ~~S6: Add password complexity validation~~ (v2.0.4)
- ~~S8: Fix account enumeration via login timing~~ (v2.0.5)
- ~~S9: Rate-limit health endpoint~~ (v2.0.6)
- ~~F1: Remove remaining Alembic references~~ (v2.0.7)

### Phase 2 — Security Headers + Visual Foundation ✅
Set the stage for frontend improvements and close remaining security gaps.

- ~~S4 / F10: Add security response headers (CSP, X-Frame-Options, HSTS, etc.)~~ (v2.1.1)
- ~~V2: CSS custom properties / design tokens (unlocks all later visual work)~~ (v2.1.2)
- ~~V7: Hover & interactive states~~ (v2.1.3)
- ~~V8 + V9: Badge/pill CSS system + typography scale~~ (v2.1.4)

### Phase 3 — Backend Features ✅
Password reset flow, logging, and infrastructure hardening.

- ~~S2 + F2: Self-service password reset (replaces temp password in API response)~~ (v2.2.1)
- ~~F5: Structured JSON logging with request ID correlation~~ (v2.2.2)
- ~~F11: Database connection pool tuning~~ (v2.2.3)
- ~~S7: Add `pip-audit` to CI~~ (v2.2.4)

### Phase 4 — Frontend Visual Overhaul ✅
Bulk visual improvements, building on the Phase 2 CSS foundation.

- ~~V1: Extract inline styles from JS to CSS~~ (v2.3.1)
- ~~V3: Responsive / mobile layout~~ (v2.3.2)
- ~~V4: Consistent spacing system~~ (v2.3.3)
- ~~V5: Loading & empty states~~ (v2.3.4)

### Phase 5 — Larger Features
Production-readiness and platform capabilities.

- ~~F4: OpenAPI / Swagger documentation~~ (v3.0.0)
- ~~F6: Production deployment guide~~ (v4.0.0)
- ~~V6: Table / data grid component~~ (v5.0.0)
- ~~V10: Light theme option~~ (v6.0.0)
- ~~F7: Background job queue (Celery)~~ (v7.0.0)
- ~~F8: Application metrics & monitoring~~ (v8.0.0)
- ~~F9: Full-text search~~ (v9.0.0)
- ~~F12+F13: Caching layer + data retention~~ (v10.0.0)

See [SECURITY_FIXES.md](SECURITY_FIXES.md), [FEATURE_ROADMAP.md](FEATURE_ROADMAP.md), and [VISUAL_REWORK.md](VISUAL_REWORK.md) for full details on each item.

## Documentation

| Document | Description |
|----------|-------------|
| [docs/BACKEND.md](docs/BACKEND.md) | Backend architecture wiki — modules, models, services, auth |
| [docs/FRONTEND.md](docs/FRONTEND.md) | Frontend architecture wiki — pages, routes, state, API adapters |
| [SECURITY_FIXES.md](SECURITY_FIXES.md) | Security audit findings and fix plan |
| [FEATURE_ROADMAP.md](FEATURE_ROADMAP.md) | Missing features for production readiness |
| [VISUAL_REWORK.md](VISUAL_REWORK.md) | Frontend visual design improvement plan |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Production deployment guide — env vars, Docker, K8s, backups, runbook |
| [docs/TESTING_README.md](docs/TESTING_README.md) | Expanded testing guide |
| [docs/backend-architecture.md](docs/backend-architecture.md) | Model bounded context rules |
