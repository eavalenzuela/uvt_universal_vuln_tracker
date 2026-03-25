# Refactor Work

## Purpose
This app needs a re-assessment of its design, both front and backend. It will be re-factored in 2 ways:
* module-by-module (code analysis)
* webpage-by-webpage (screenshot visual design analysis)

## Goals
[ ] Document each backend source module (high level)
    [ ] Create a BACKEND.md wiki file
[ ] Document each webpage (high level)
    [ ] Create a FRONTEND.md wiki file
[ ] Remove any remaining alembic code
[ ] Improve containerization scheme
[ ] Identify security fixes and redesigns
    [ ] Create a SECURITY_FIXES.md plan
[ ] Identify missing features needed to bring this to a production-ready tool
    [ ] Create a detailed FEATURE_ROADMAP.md plan
[ ] Determine whether the current visual design of the app needs rework
    [ ] If so, design a VISUAL_REWORK.md plan
[ ] Lastly, update the README

---

## Backend Refactor Items

### B1. Remove Alembic / Flask-Migrate Dead Code — DONE
**Priority:** High | **Effort:** Small

Alembic and Flask-Migrate are in `requirements.txt` (lines 8-9) and initialized in `backend/database.py` (lines 2, 8, 12), but never used — no `migrations/` directory exists. Schema creation falls through to `db.create_all()` and raw `ALTER TABLE` statements in `ensure_sqlite_schema()`.

**Actions:**
- [x] Remove `Alembic` and `Flask-Migrate` from `requirements.txt`
- [x] Remove `from flask_migrate import Migrate`, `migrate = Migrate()`, and `migrate.init_app(app, db)` from `backend/database.py`
- [x] Decide: either implement proper migrations or document that `db.create_all()` is the intended approach
- [x] Clean up the `ensure_sqlite_schema()` function — the repeated `db.create_all()` / `inspect()` calls are fragile

### B2. Replace Raw SQL String Interpolation in database.py — DONE
**Priority:** High (security) | **Effort:** Small

Replaced the old f-string pattern with a controlled constant list — column names and definitions are defined in `_SQLITE_VULN_COLUMN_BACKFILL` and never sourced from user input. Removed the unused `AddColumn` import and dead `vuln_table` variable.

### B3. Migrate datetime.utcnow() to Timezone-Aware UTC — DONE
**Priority:** Medium | **Effort:** Medium-Large

Replaced all `datetime.utcnow()` (108 occurrences) with `datetime.now(timezone.utc)` across backend code and tests. Added a `TZDateTime` TypeDecorator in `database.py` that tags naive datetimes from SQLite with `tzinfo=UTC` on read, ensuring consistent timezone-aware comparisons. Also replaced `utcfromtimestamp()` with `fromtimestamp(..., tz=utc)` in auth token validation.

**Actions:**
- [x] Replace `datetime.utcnow()` with `datetime.now(datetime.timezone.utc)` across all backend code
- [x] Replace `datetime.utcnow()` in SQLAlchemy model defaults with `lambda: datetime.now(timezone.utc)` and use `TZDateTime` column type
- [x] Update `backend/tests/conftest.py:104` which also uses the deprecated form

### B4. Split Oversized Route Files — DONE
**Priority:** Medium | **Effort:** Medium

Split the three largest route files into focused modules:

- [x] `api/vulnerabilities.py` (1,017 lines) → `vuln_crud.py` (611), `vuln_comments.py` (112), `vuln_versions.py` (128), `vuln_bulk.py` (217)
- [x] `api/reports.py` (855 lines) → `report_exports.py` (570), `report_templates.py` (159), `report_schedules.py` (218)
- [x] `api/users.py` (499 lines) → `users_crud.py` (384), `users_tokens.py` (82), `audit_logs.py` (53)
- [x] Updated `api/__init__.py` to register all new blueprints
- [x] Updated test monkeypatch references to new module paths

### B5. Standardize Error Response Pattern — DONE
**Priority:** Medium | **Effort:** Medium

- [x] Replaced all 63 inline `jsonify({"error": ...})` calls across 7 files with `error_response()` from `validation.py`
- [x] Zero inline error responses remain in the API layer
- [x] All error responses now use a consistent shape: `{"error": ..., "field": ..., "details": ...}`

### B6. Enforce Service Layer Boundaries — DONE
**Priority:** Medium | **Effort:** Large

- [x] Created `services/product_service.py` — all CRUD + version operations extracted from routes
- [x] Created `services/attack_vector_service.py` — all CRUD + vulnerability mapping operations extracted
- [x] Rewrote `api/products.py` (235→110 lines) and `api/attack_vectors.py` (208→110 lines) as thin route handlers
- [x] `api/vulnerabilities.py` already delegated to `vulnerability_service.py` and `vulnerability_query.py` for core operations

### B7. Standardize Audit Logging — DONE
**Priority:** Medium | **Effort:** Small

- [x] Replaced local `_audit()` wrappers in `users.py` and `vulnerabilities.py` with centralized `record_audit()` from `services/audit.py`
- [x] Added audit logging to DELETE routes in `attack_vectors.py` and `terminal_impacts.py`

### B8. Standardize Database Exception Handling — DONE
**Priority:** Medium | **Effort:** Small

Replaced bare `except Exception` with specific SQLAlchemy exceptions in DB-facing try/except blocks:
- [x] `vulnerabilities.py` — `IntegrityError` for create, `SQLAlchemyError` for batch update
- [x] `products.py` — `IntegrityError` for create/update version
- [x] Left `vuln_ingest.py` as `except Exception` (intentional — catches validation errors for transactional rollback)
- [x] Left `auth_routes.py` OIDC handler as `except Exception` (not a DB operation)

### B9. Centralize Configuration with Validation — DONE
**Priority:** Low-Medium | **Effort:** Medium

- [x] Created `backend/config.py` with typed `AppConfig` dataclass — all 48 env vars read and validated in one place
- [x] `load_config()` reads env vars at boot, `apply_config()` pushes values into Flask `app.config`
- [x] Fail fast on missing `SECRET_KEY`/`JWT_SECRET` in production (dev defaults rejected)
- [x] Replaced 45+ scattered `os.getenv()` calls in `uvt_app.py` with single `load_config()` call

---

## Frontend Refactor Items

### F1. Split Oversized View Files
**Priority:** Medium | **Effort:** Medium

| File | Lines | Notes |
|------|-------|-------|
| `features/vulnerabilities/view/vulnListView.js` | 1,416 | Filter logic, table rendering, bulk actions, caching all in one file |
| `features/dashboard/view/dashboardView.js` | 1,328 | Charts, layout, data fetching, metric calculations mixed |
| `views/products/productsView.js` | 753 | CRUD, list, detail rendering combined |

Each should be decomposed into smaller, focused modules (e.g., separate filter panel, table, and bulk-action components).

### F2. Split API Client
**Priority:** Low | **Effort:** Small

`frontend/src/api/client.js` (238 lines) mixes HTTP transport, token refresh retry logic, and error handling. Split into focused modules (core transport, auth retry, error types).

---

## Containerization Improvements

### C1. Use a Production WSGI Server — DONE
**Priority:** High | **Effort:** Small

Replaced Flask dev server with gunicorn in Dockerfile. Added `gunicorn>=22.0,<24.0` to `requirements.txt`.

### C2. Externalize Secrets from docker-compose.yml — DONE
**Priority:** High | **Effort:** Small

- [x] Replaced all hardcoded secrets with `${VAR:-default}` substitution in `docker-compose.yml`
- [x] Added `env_file: .env` to backend service
- [x] Created `.env.example` with placeholder values
- [x] Added `.env` to `.gitignore`

### C3. Multi-Stage Build Improvements — DONE
**Priority:** Low-Medium | **Effort:** Small

- [x] Pin the Python base image digest for reproducible builds
- [x] Add a non-root user in the backend stage (`RUN useradd -m app && USER app`)
- [x] Add health check to the backend stage (uses existing `/api/health` endpoint)
- [x] Health endpoint already exists — no changes needed
- [x] Added healthchecks to docker-compose for backend and frontend services

---

## Testing Improvements

### T1. Add Missing Test Coverage — DONE
**Priority:** Medium | **Effort:** Large

Added dedicated test files for all previously untested API modules:
- [x] `api/test_attack_vectors.py` — CRUD, validation, role enforcement, vulnerability mappings
- [x] `api/test_terminal_impacts.py` — CRUD, validation, role enforcement, vulnerability mappings
- [x] `api/test_controls.py` — CRUD, validation, audit logging, role enforcement
- [x] `api/test_sla_policy.py` — get/update, normalization, audit logging, role enforcement
- [x] `api/test_vulnerability_filters.py` — CRUD, default flag, visibility enforcement, role checks
- [x] `api/test_notification_delivery.py` — list/filter attempts, retry/replay, role enforcement
- [x] `api/test_components.py` — list components, dependency graph, SBOM validation, compare

Remaining low-coverage services (not yet addressed):
- `services/component_correlation.py`
- `services/oidc_mapping.py` (78%)
- `services/sbom_ingest.py` (59%)

### T2. Organize Test Directory — DONE
**Priority:** Low | **Effort:** Small

Reorganized from flat layout into:
```
backend/tests/
  conftest.py              # shared fixtures (unchanged)
  sample_import_plugin.py
  api/                     # route-level tests (16 files)
  services/                # service/unit tests (11 files)
```

---

## Dependency Cleanup

### D1. Remove Unused Dependencies — DONE
**Priority:** Low | **Effort:** Small

- [x] Remove `Alembic` and `Flask-Migrate` once B1 is done
- [ ] Audit whether `psycopg[binary]` is needed in dev (SQLite is the default); consider making it an optional extra

### D2. Unpin pytest-cov — DONE
**Priority:** Low | **Effort:** Trivial

`pytest-cov==4.1.0` was hard-pinned while everything else uses ranges. Changed to `pytest-cov>=4.0,<6.0`.
