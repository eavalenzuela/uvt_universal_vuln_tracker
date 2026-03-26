# Feature Roadmap

Missing features and improvements needed to bring UVT to production readiness, organized by priority.

---

## P0 — Production Blockers

### F1. Commit Alembic Migrations Directory
**Effort:** Small

Setup scripts reference Flask-Migrate and `flask db upgrade`, but the `migrations/` directory is not in the repo. Currently schema changes rely on `db.create_all()` and manual SQLite column backfills in `database.py`.

**What to do:**
- Run `flask db init` and `flask db migrate -m "initial schema"`
- Commit the `migrations/` directory
- Remove the SQLite backfill hack from `init_database()`
- Document the migration workflow in the README

### F2. Self-Service Password Reset
**Effort:** Medium

No forgot-password flow exists. Admins must manually reset passwords (and the temp password is returned in the API response — see SECURITY_FIXES.md S2).

**What to do:**
- `POST /api/auth/forgot-password` — accepts email, sends time-limited reset link
- `POST /api/auth/reset-password` — accepts token + new password
- Frontend: forgot-password page linked from login
- Rate-limit the forgot-password endpoint aggressively

### F3. Email Verification on Registration
**Effort:** Medium

New users (via registration or admin invite) are immediately active with no email verification.

**What to do:**
- Add `email_verified` flag to User model (migration)
- Send verification email on registration/invite
- Gate login on verified email (with grace period option)

### F4. OpenAPI / Swagger Documentation
**Effort:** Medium

The API has 24 blueprints with no machine-readable documentation. Consumers have to read source code to understand endpoints.

**What to do:**
- Add `flask-smorest` or `apispec` to generate OpenAPI 3.0 spec from blueprints
- Serve Swagger UI at `/api/docs`
- Include request/response schemas from serializers

### F5. Structured Logging
**Effort:** Small

Currently uses `logging.basicConfig(level=INFO)` with no structured output. Production deployments need parseable logs for aggregation.

**What to do:**
- JSON log formatter (e.g., `python-json-logger`)
- Request ID correlation (add to each log line)
- Configurable log level via env var
- Access log with timing, status, user ID

### F6. Production Deployment Guide
**Effort:** Small

README covers dev setup only. No documentation for production deployment, required env vars, scaling, or operational procedures.

**What to do:**
- Document all env vars with defaults and production recommendations
- Add Kubernetes manifest examples or Helm chart
- Document backup/restore procedures (the scripts exist but aren't documented)
- Runbook for common operational tasks

---

## P1 — Important for Production Use

### F7. Background Job Queue
**Effort:** Large

Heavy operations (plugin runs, report generation, notification scans, CVE enrichment) block request threads. Currently uses `ThreadPoolExecutor` for plugins but no proper task queue.

**What to do:**
- Add Celery + Redis (Redis already in docker-compose for rate limiting)
- Move plugin execution, report generation, bulk operations to async tasks
- Add task status endpoint (`GET /api/tasks/{id}`)
- Frontend: show progress indicators for long-running operations

### F8. Application Metrics & Monitoring
**Effort:** Medium

No Prometheus, StatsD, or application metrics. Health check returns only `{"ok": true}`.

**What to do:**
- Add `prometheus-flask-instrumentator` or similar
- Track: request latency, error rates, active users, vulnerability counts, plugin run durations
- Expand health check to include DB connectivity, Redis status
- Export metrics at `/metrics`

### F9. Full-Text Search
**Effort:** Medium

All search is column-level filtering. No way to search across vulnerability descriptions, comments, or product names simultaneously.

**What to do:**
- PostgreSQL: use `tsvector` / `GIN` indexes for FTS
- Add `GET /api/search?q=...` endpoint returning results across entities
- Frontend: global search bar in header

### F10. Security Response Headers
**Effort:** Small

No CSP, X-Frame-Options, HSTS, etc. (See SECURITY_FIXES.md S4 for details.)

### F11. Database Connection Tuning
**Effort:** Small

SQLAlchemy pool settings (`pool_size`, `pool_recycle`, `pool_pre_ping`) use defaults. Production PostgreSQL needs tuning.

**What to do:**
- Add pool configuration to `AppConfig` (env vars)
- Set `pool_pre_ping=True` to handle stale connections
- Document recommended settings for different deployment sizes

### F12. Caching Layer
**Effort:** Medium

Every request hits the database. Dashboard summary, product lists, and other slow queries could benefit from caching.

**What to do:**
- Redis cache for dashboard summary (30s TTL, already polled at that interval)
- Cache product/version lists (invalidate on write)
- ETag support for list endpoints

### F13. Data Retention & Archival
**Effort:** Medium

No automatic purging of old audit logs, notification delivery logs, plugin run records, or report artifacts. Database grows unbounded.

**What to do:**
- Add retention policy config (e.g., `AUDIT_LOG_RETENTION_DAYS=365`)
- CLI command or scheduled task to purge old records
- Archive to cold storage before deletion (optional)

---

## P2 — Valuable Enhancements

### F14. Inbound Webhook / Scanner Integration
**Effort:** Large

Currently only ingests data via SBOM upload and plugin feeds (NVD, ExploitDB). No way to receive results from Nessus, Qualys, Tenable, etc.

**What to do:**
- `POST /api/webhooks/ingest` — generic webhook receiver with format detection
- Adapter pattern for common scanner output formats
- Map scanner findings to normalized vulnerability model

### F15. Team / Project-Level Access Control
**Effort:** Large

All products are visible to all authenticated users. `ProductOwner` exists but doesn't restrict visibility.

**What to do:**
- Add Team model (name, members)
- Associate products with teams
- Filter product visibility by team membership
- Analyst/Viewer see only their team's products (Admin sees all)

### F16. User Preferences Page
**Effort:** Medium

No per-user settings. Users can't configure timezone, notification preferences, or default filters.

**What to do:**
- `UserPreference` model (JSON blob per user)
- `GET/PATCH /api/users/me/preferences`
- Frontend: settings page accessible from header dropdown
- Support: timezone, default vulnerability filter, notification channels

### F17. Improved PDF Reports
**Effort:** Medium

Current PDF generation is basic text-only. No charts, branding, or executive summary formatting.

**What to do:**
- Use WeasyPrint or ReportLab for styled PDF output
- Include severity distribution charts, trend graphs
- Configurable branding (logo, header, footer)
- Executive summary page with KPIs

### F18. API Versioning
**Effort:** Medium

Single `/api/*` namespace with no versioning strategy. Breaking changes will affect all consumers.

**What to do:**
- Version prefix: `/api/v1/*`
- Keep unversioned routes as aliases to current version
- Document deprecation policy

### F19. Bulk Scanner Import
**Effort:** Medium per scanner

Beyond SBOM, support direct import of common scanner formats.

**What to do (per scanner):**
- Nessus `.nessus` XML import
- Qualys CSV/XML import
- Trivy JSON import
- Map to normalized vulnerability model via plugin framework

### F20. Keyboard Shortcuts
**Effort:** Small

No hotkeys for power users navigating large vulnerability sets.

**What to do:**
- `j`/`k` for next/prev in lists
- `/` to focus search
- `e` to edit selected item
- `?` to show shortcut help modal

---

## Summary

| ID | Priority | Effort | Description |
|----|----------|--------|-------------|
| F1 | P0 | Small | Commit Alembic migrations directory |
| F2 | P0 | Medium | Self-service password reset |
| F3 | P0 | Medium | Email verification on registration |
| F4 | P0 | Medium | OpenAPI / Swagger documentation |
| F5 | P0 | Small | Structured logging |
| F6 | P0 | Small | Production deployment guide |
| F7 | P1 | Large | Background job queue (Celery) |
| F8 | P1 | Medium | Application metrics & monitoring |
| F9 | P1 | Medium | Full-text search |
| F10 | P1 | Small | Security response headers |
| F11 | P1 | Small | Database connection tuning |
| F12 | P1 | Medium | Caching layer |
| F13 | P1 | Medium | Data retention & archival |
| F14 | P2 | Large | Inbound webhook / scanner integration |
| F15 | P2 | Large | Team / project-level access control |
| F16 | P2 | Medium | User preferences page |
| F17 | P2 | Medium | Improved PDF reports |
| F18 | P2 | Medium | API versioning |
| F19 | P2 | Medium | Bulk scanner import |
| F20 | P2 | Small | Keyboard shortcuts |
