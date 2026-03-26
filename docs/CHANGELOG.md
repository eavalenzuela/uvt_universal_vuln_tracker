# Changelog

## v2.0.1

### Security
- **S1: Fix hardcoded debug mode** — `app.run(debug=True)` in `uvt_app.py` now gates on `FLASK_ENV=development` instead of being unconditionally enabled. Prevents Werkzeug interactive debugger and stack trace exposure in production.

## Unreleased

### Security
- **Secret key validation** — App now raises `RuntimeError` on startup if `SECRET_KEY` or `JWT_SECRET` still hold dev defaults outside of development/testing environments (`backend/uvt_app.py`)
- **Input validation hardening** — Replaced bare `int()` casts on user input with `parse_int()` in notification rule create/update endpoints, returning proper 400 errors instead of 500s
- **Security audit** — Created `SECURITY_FIXES.md` with 9 findings: critical debug=True in entry point, temp password exposure in API response, lenient rate limits on user creation, missing security headers, and more

### Added
- **CI test jobs** — Added `backend-tests` (Python 3.12, pytest with coverage) and `frontend-tests` (Node 20) jobs to `.github/workflows/repo-hygiene.yml`
- **Pagination** — Created shared `paginate_query()` helper in `backend/api/validation.py` with `?page=` and `?per_page=` query params (default 50, max 200); applied to notification rules, products, active users, saved filters, report templates, and report schedules
- **Database indexes** — Added indexes on `Vulnerability.status`, `Vulnerability.created_by`, `Vulnerability.assigned_to`, `AuditLog.user_id`, and a composite index on `SoftwareComponent(product_version_id, name)`
- **Docker support** — Multi-stage `Dockerfile` (Python 3.12-slim backend + nginx:alpine frontend), `docker-compose.yml` with backend/frontend/postgres/redis services, `docker/nginx.conf` for API proxying, and `.dockerignore`
- **Typed configuration** — Created `AppConfig` frozen dataclass in `backend/config.py`, replacing 45+ scattered `os.getenv()` calls with validated, typed config loaded at startup (B9)
- **Service layer extraction** — New `backend/services/product_service.py` and `backend/services/attack_vector_service.py` encapsulating business logic previously embedded in route handlers (B6)
- **Component correlation tests** — 12 tests for `services/component_correlation.py` covering PURL, CPE, SBOM CVE matching, dedup, and dependency path extraction (0% → 100% coverage)
- **OIDC mapping tests** — 16 tests for `services/oidc_mapping.py` covering role mapping, claim parsing, edge cases (78% → 100% coverage)
- **SBOM ingest tests** — 18 tests for `services/sbom_ingest.py` covering CycloneDX/SPDX parsing, component upsert, dependency graph, vulnerability mapping (59% → 96% coverage)
- **Backend architecture wiki** — `docs/BACKEND.md` documenting all modules, models, services, auth, plugins, rate limiting
- **Frontend architecture wiki** — `docs/FRONTEND.md` documenting all 18 pages/routes, state management, API adapters, UI primitives
- **Feature roadmap** — `FEATURE_ROADMAP.md` with 20 features across P0/P1/P2 priorities for production readiness
- **Visual rework plan** — `VISUAL_REWORK.md` with 10 improvements: CSS tokens, inline style extraction, responsive layout, loading states, data tables
- **PostgreSQL optional install** — New `requirements-postgres.txt` for PostgreSQL-only dependency; setup scripts auto-install when `DATABASE_URL` is postgres

### Fixed
- **N+1 query in SBOM ingest** — `correlate_vulnerability_to_components()` now accepts a `product_version_id` filter; `sbom_ingest.py` uses `yield_per(100)` for streaming instead of `.all()`
- **Exception logging** — Added `logger.exception()` to generic catch blocks in `auth_routes.py`, `vulnerabilities.py`, `products.py`, and the 500 error handler; narrowed `except Exception` to `except (TypeError, ValueError, OSError)` in `auth.py` token validation
- **Frontend stale caches** — Added 5-minute TTL to `cachedProductVersions`, `cachedAttackVectors`, and `cachedTerminalImpacts` in `vulnListView.js`
- **Frontend state bug** — `upsertNotification()` in `store.js` now calls `emit()` so subscribers are notified of changes
- **Deprecated datetime usage** — Replaced all `datetime.utcnow()` with timezone-aware `datetime.now(timezone.utc)` across 25+ backend files; added `TZDateTime` type decorator to ensure naive SQLite datetimes are tagged UTC on read (B3)
- **Reports API smoke test** — Fixed `reportsApi.test.js` to assert cookie-based auth (`credentials: "include"`) instead of nonexistent Bearer token `Authorization` header

### Changed
- **Centralized audit logging** — Extracted `record_audit()` convenience wrapper into `backend/services/audit.py`, replacing duplicated `_audit()` helpers across 5 API modules
- **Centralized serializers** — Moved inline serialization helpers into `backend/serializers/`: `product_serializers.py` (`product_json`, `version_json`), `control_serializers.py` (`control_json`), `notification_rule_serializers.py` (`rule_json`)
- **Route splitting** — Split three oversized API modules into focused blueprints (B4):
  - `vulnerabilities.py` (1017 lines) → `vuln_crud.py`, `vuln_comments.py`, `vuln_versions.py`, `vuln_bulk.py`
  - `reports.py` (855 lines) → `report_exports.py`, `report_templates.py`, `report_schedules.py`
  - `users.py` (499 lines) → `users_crud.py`, `users_tokens.py`, `audit_logs.py`
- **Error standardization** — Replaced all 63 inline `jsonify({"error": ...})` returns with `error_response()` helper across 7 API files (B5)
- **Frontend view splitting** — Split three oversized frontend view files into focused modules (F1):
  - `dashboardView.js` → `dashboardConstants.js`, `dashboardWidgets.js`, `dashboardView.js`
  - `vulnListView.js` → `vulnShared.js`, `vulnVersions.js`, `vulnAttackVectors.js`, `vulnTerminalImpacts.js`, `vulnCard.js`, `vulnListView.js`
  - `productsView.js` → `productCard.js`, `productsView.js`
- **API client splitting** — Extracted `ApiError` class and token refresh logic from `client.js` into `errors.js` and `authRetry.js` (F2)
- **Docker hardening** — Pinned base image digest, added non-root user, added healthcheck to Dockerfile (C3)
- **Docker externalized secrets** — Removed inline credentials from `docker-compose.yml`, using env vars with defaults (C2)
- **psycopg made optional** — Removed `psycopg[binary]` from `requirements.txt` (not needed for SQLite dev); Dockerfile and setup scripts updated to install from `requirements-postgres.txt` when PostgreSQL is in use (D1)
- **README rewritten** — Updated with capabilities overview, full configuration tables, project layout tree, CLI commands, and links to all documentation
- **Documentation reorganized** — Moved `BACKEND.md`, `FRONTEND.md`, `CHANGELOG.md`, `TESTING_README.md` into `docs/` directory
