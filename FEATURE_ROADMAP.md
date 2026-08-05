# Feature Roadmap

Missing features and improvements needed to bring UVT to production readiness, organized by priority.

---

## P0 — Production Blockers

### ~~F1. Remove Alembic References~~ ✅ Done (v2.0.7)
Removed `flask_migrate` and `alembic` from setup scripts. Replaced migration commands with `db.create_all()`.

### ~~F2. Self-Service Password Reset~~ ✅ Done (v2.2.x)
`POST /api/auth/forgot-password` and `POST /api/auth/reset-password` with single-use, 60-minute, SHA-256-hashed tokens. Forgot-password and reset-password pages linked from login. Rate-limited under `RATE_LIMIT_SENSITIVE_LIMIT`. New `PasswordResetToken` model and `FRONTEND_URL` config var.

### ~~F3. Email Verification on Registration~~ ✅ Done (v2.21.0)
Opt-in via `REQUIRE_EMAIL_VERIFICATION` (default `false`, so behavior is unchanged until enabled). When on, publicly-registered users are created unverified and emailed a tokenized link (`EmailVerificationToken`, 24 h expiry, single-use, mirrors the F2 password-reset machinery); login is blocked with `403` until they confirm. Endpoints: `POST /api/auth/verify-email` and `POST /api/auth/resend-verification` (anti-enumeration `200`). The bootstrap Admin (first user) is exempt so a fresh install can never lock itself out before mail is configured. Re-uses the existing `email_delivery` service — no new external dependency.

### ~~F4. OpenAPI / Swagger Documentation~~ ✅ Done (v2.4.0)
Added `apispec` with Flask plugin for OpenAPI 3.0.3 spec generation, Swagger UI at `/api/docs`, spec at `/api/openapi.json`. All 100 paths (140 operations) documented with YAML docstrings, 32 component schemas, and security schemes.

### ~~F5. Structured Logging~~ ✅ Done (v2.2.x)
Replaced `logging.basicConfig()` with `python-json-logger`. Each request gets a unique ID (from `X-Request-ID` header or auto-generated), injected into all log records and returned in `X-Request-ID` response header. Access log records method, path, status, duration, and user ID. Config: `LOG_LEVEL` (default `INFO`), `LOG_FORMAT` (`json` or `text`).

### ~~F6. Production Deployment Guide~~ ✅ Done (v2.5.0)
Added `docs/DEPLOYMENT.md` covering all env vars with production recommendations, Docker Compose / standalone / Kubernetes deployment options, Gunicorn tuning, database backup/restore, logging and monitoring, operational runbook, and security checklist.

---

## P1 — Important for Production Use

### ~~F7. Background Job Queue~~ ✅ Done (v2.8.0)
Added Celery with Redis broker. Plugin execution, notification scans, and report generation run as background tasks when `CELERY_ENABLED=true`. Task status endpoint at `GET /api/tasks/{id}`. Celery worker and beat services in docker-compose. Falls back to ThreadPoolExecutor when Celery is disabled. Config: `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`, `CELERY_ENABLED`, `CELERY_WORKER_CONCURRENCY`, `CELERY_TASK_TIMEOUT`.

### ~~F8. Application Metrics & Monitoring~~ ✅ Done (v2.9.0)
Added `prometheus_client` with custom metrics: HTTP request count/latency/in-progress, vulnerability counts by severity, active users, plugin run count/duration. Metrics exported at `GET /metrics` in Prometheus text format. Health endpoint expanded to include DB connectivity and Redis status checks (returns 503 when degraded).

### ~~F9. Full-Text Search~~ ✅ Done (v2.10.0)
Added `GET /api/search?q=...` endpoint searching across vulnerabilities (title, cve_id, description), products (name, description), and comments (body). Results grouped by entity type with max 10 per type. Frontend global search bar in header with debounced typeahead dropdown and keyboard navigation. Works with both SQLite and PostgreSQL.

### ~~F10. Security Response Headers~~ ✅ Done (v2.2.x)
`after_request` hook in `uvt_app.py` sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on all responses. `Strict-Transport-Security` (2-year max-age, includeSubDomains) is added when `auth_cookie_secure` is enabled.

### ~~F11. Database Connection Tuning~~ ✅ Done (v2.2.x)
Added `DB_POOL_SIZE` (5), `DB_POOL_MAX_OVERFLOW` (10), `DB_POOL_RECYCLE` (1800s), and `DB_POOL_PRE_PING` (true) env vars. Pool settings apply to PostgreSQL deployments only; SQLite is unaffected.

### ~~F12. Caching Layer~~ ✅ Done (v2.11.0)
Added Redis-backed cache module (`backend/cache.py`) with JSON serialization, TTL, and automatic fallback when Redis is unavailable. Dashboard summary cached with configurable TTL (`CACHE_DASHBOARD_TTL`, default 30s). Product list cached (`CACHE_PRODUCTS_TTL`, default 60s) with invalidation on create/update/delete. Config: `CACHE_ENABLED`, `CACHE_DASHBOARD_TTL`, `CACHE_PRODUCTS_TTL`.

### ~~F13. Data Retention & Archival~~ ✅ Done (v2.11.0)
Added retention policy configuration and `flask purge-old-data` CLI command with `--dry-run` option. Purges audit logs, notification delivery logs, plugin runs, and report artifacts (including files on disk) based on configurable retention periods. Also available as Celery task (`uvt.purge_old_data`) for scheduled execution. Config: `RETENTION_AUDIT_LOG_DAYS` (365), `RETENTION_NOTIFICATION_LOG_DAYS` (90), `RETENTION_PLUGIN_RUN_DAYS` (90), `RETENTION_REPORT_ARTIFACT_DAYS` (180).

---

## P2 — Valuable Enhancements

### ~~F14. Inbound Webhook / Scanner Integration~~ ✅ Done (v2.13.0)
Added `WebhookEndpoint` model (token-authenticated, scoped) and `POST /api/webhooks/ingest/<token>` for receiving payloads. Format-detection adapter pipeline maps Nessus/Qualys/Trivy/generic JSON into the normalized vulnerability model via `webhook_ingest.py`.

### ~~F15. Team / Project-Level Access Control~~ ✅ Done (v2.15.0–v2.16.0)
Two-phase rollout. Phase 1 (v2.15.x) added `teams` + `user_teams` tables, `team_id` on Product/Vulnerability/notification rules/webhooks/saved filters/dashboard presets/report templates+schedules+artifacts/plugin runs/audit logs. Default-team posture stamps every existing row, and `services/team_scope.py` filters every query site so behavior is identical to pre-F15 until an Admin creates a second team. Phase 2 (v2.16.0) shipped `/admin/teams` for create/rename/delete + memberships, the top-nav team selector, and `X-UVT-Team-Id` plumbing.

### ~~F16. User Preferences Page~~ ✅ Done (v2.14.0)
Added `UserPreferences` model (per-user JSON blob), `GET/PATCH /api/users/me/preferences`, and a `/settings` page covering timezone, default vulnerability filter, and notification channel preferences.

### ~~F17. Improved PDF Reports~~ ✅ Done (v2.17.0–v2.19.0)
Three slices. Slice 1 (v2.17.0) replaced the hand-written 5-object PDF stream with WeasyPrint + Jinja2 (`backend/services/pdf_renderer.py` + `backend/templates/reports/`). Slice 2 (v2.18.0) added Matplotlib charts (`pdf_charts.py`), the `executive_summary` layout with KPI tiles + severity donut + SLA bar + appendix, and async rendering via Celery (`ReportArtifact.status`, `202 Accepted`, frontend polling via `waitForReportArtifact`). Slice 3 (v2.19.0) added `OrganizationBranding` (primary color + footer text + logo upload, admin-only) injected into all layouts.

### ~~F18. API Versioning~~ ✅ Done (v2.13.0)
Added `/api/v1/*` alias via WSGI middleware (`_V1AliasMiddleware` in `backend/api/__init__.py`). Single source of truth for routes, no double-registration in OpenAPI.

### ~~F19. Bulk Scanner Import~~ ✅ Done (v2.14.0)
`backend/services/scanner_imports.py` parses Nessus `.nessus` XML, Qualys CSV/XML, and Trivy JSON; admin upload via `/api/scanner-imports/<format>`. Maps scanner findings to the normalized vulnerability model with dedup against existing CVE records.

### ~~F20. Keyboard Shortcuts~~ ✅ Done (v2.13.0)
`j`/`k` (next/prev row), `/` (focus search), `e` (edit selected vuln on detail view), `?` (help modal). Implemented in `frontend/src/ui/keybindings/`.

---

## Summary

| ID | Priority | Effort | Description |
|----|----------|--------|-------------|
| ~~F1~~ | ~~P0~~ | ~~Small~~ | ~~Remove Alembic references~~ ✅ |
| ~~F2~~ | ~~P0~~ | ~~Medium~~ | ~~Self-service password reset~~ ✅ |
| ~~F3~~ | ~~P0~~ | ~~Medium~~ | ~~Email verification on registration~~ ✅ |
| ~~F4~~ | ~~P0~~ | ~~Medium~~ | ~~OpenAPI / Swagger documentation~~ ✅ |
| ~~F5~~ | ~~P0~~ | ~~Small~~ | ~~Structured logging~~ ✅ |
| ~~F6~~ | ~~P0~~ | ~~Small~~ | ~~Production deployment guide~~ ✅ |
| ~~F7~~ | ~~P1~~ | ~~Large~~ | ~~Background job queue (Celery)~~ ✅ |
| ~~F8~~ | ~~P1~~ | ~~Medium~~ | ~~Application metrics & monitoring~~ ✅ |
| ~~F9~~ | ~~P1~~ | ~~Medium~~ | ~~Full-text search~~ ✅ |
| ~~F10~~ | ~~P1~~ | ~~Small~~ | ~~Security response headers~~ ✅ |
| ~~F11~~ | ~~P1~~ | ~~Small~~ | ~~Database connection tuning~~ ✅ |
| ~~F12~~ | ~~P1~~ | ~~Medium~~ | ~~Caching layer~~ ✅ |
| ~~F13~~ | ~~P1~~ | ~~Medium~~ | ~~Data retention & archival~~ ✅ |
| ~~F14~~ | ~~P2~~ | ~~Large~~ | ~~Inbound webhook / scanner integration~~ ✅ |
| ~~F15~~ | ~~P2~~ | ~~Large~~ | ~~Team / project-level access control~~ ✅ |
| ~~F16~~ | ~~P2~~ | ~~Medium~~ | ~~User preferences page~~ ✅ |
| ~~F17~~ | ~~P2~~ | ~~Medium~~ | ~~Improved PDF reports~~ ✅ |
| ~~F18~~ | ~~P2~~ | ~~Medium~~ | ~~API versioning~~ ✅ |
| ~~F19~~ | ~~P2~~ | ~~Medium~~ | ~~Bulk scanner import~~ ✅ |
| ~~F20~~ | ~~P2~~ | ~~Small~~ | ~~Keyboard shortcuts~~ ✅ |

---

## P0 — Reopened by the v2.24.0 review

An adversarial review found that three "done" items were checkbox-complete but
not functionally complete, and that the schema had no upgrade path at all.

### ~~F21. Database Migrations~~ ✅ Done (v2.24.0)
F1 removed Alembic in favour of `db.create_all()`, which creates missing
*tables* but never adds a column to an existing one. Every release that added
a column therefore left upgraded deployments 500-ing while `/api/health` still
reported `ok`. Reinstated Flask-Migrate with a squashed `0001` baseline, added
`backend/schema_guard.py` (refuses to serve and names the reason when the
database is behind head), and `backend/tests/test_migrations.py`, which fails
the build if a model changes without a revision. `scripts/update-db.sh` no
longer runs a destructive `pg_restore --clean` on failure.

### ~~F22. SSE Worker Exhaustion~~ ✅ Done (v2.24.0)
`/api/notifications/stream` holds a connection per authenticated session and
Gunicorn ran 4 *sync* workers, so four open tabs took the whole service offline
— including the health check, which then restart-looped the container. Switched
to `gthread` (4 x 25), added a per-user stream cap and a maximum stream
lifetime, and taught the frontend to reconnect with backoff.

### ~~F23. Real Scope Enforcement~~ ✅ Done (v2.24.0)
API token scopes were checked only for paths matching a ten-entry prefix list;
everything else — teams, webhooks, audit logs, search, scanner imports —
skipped the check entirely, so a `products:read` token could create teams and
webhook endpoints. `ROUTE_SCOPES` is now explicit and closed, unmapped routes
fail closed, and `audit_route_scopes()` names any new endpoint at boot.

### ~~F24. Security Headers on the Document~~ ✅ Done (v2.24.0)
F10's headers were set by Flask, which only serves `/api/*` — so the strict CSP
landed on JSON responses while the HTML that loads and executes the app had
none. Moved to `docker/nginx.conf` with a policy the SPA can actually run
under.

### ~~F25. MFA~~ ✅ Done (v2.24.0)
TOTP with two-phase enrolment, hashed single-use recovery codes, and a signed
short-lived login challenge. The Admin → Users page had advertised "MFA
posture" while no second factor existed anywhere in the codebase.

### ~~F26. EPSS, Risk Acceptance, Attachments~~ ✅ Done (v2.24.0)
EPSS enrichment from FIRST.org alongside the existing KEV flag; risk acceptance
with a mandatory expiry, approver and reason (it was previously a bare status
string that never came back for review); evidence attachments on findings; and
severity/CVSS agreement checking.

---

## Summary

**Roadmap status:** F1–F26 shipped. New work is tracked in `docs/CHANGELOG.md`
and per-feature plans in `docs/plans/`.
