# UVT Remediation Plan

## Critical

### ~~1. Hardcoded Secret Keys~~ — DONE
**Files:** `backend/uvt_app.py`

`SECRET_KEY` and `JWT_SECRET` default to `"dev-secret"` / `"dev-jwt-secret"`. These will silently be used in production if env vars aren't set.

**Fix:** Add startup validation that raises an error if these aren't overridden when `FLASK_ENV != development`.

**Resolution:** Added `RuntimeError` on startup if either key still holds its dev default outside of development/testing environments.

---

### ~~2. No Tests in CI~~ — DONE
**File:** `.github/workflows/repo-hygiene.yml`

The only CI workflow checks for stale artifacts. No backend or frontend tests run on PRs — a passing PR says nothing about correctness.

**Fix:** Add `pytest` and `node --test` jobs to the CI workflow.

**Resolution:** Added `backend-tests` (Python 3.12, pytest with coverage) and `frontend-tests` (Node 20, `node --test`) jobs to the workflow.

---

### ~~3. Unvalidated Integer Casts~~ — DONE
**Files:** `backend/api/notification_rules.py`

Bare `int()` on user input causes unhandled 500s instead of 400s. The codebase already has `parse_int()` in `validation.py` — it's just not used consistently.

**Fix:** Replace all bare `int()` casts on request data with `parse_int()` from the validation module.

**Resolution:** Replaced bare `int()` in both create and update endpoints with `parse_int()`, including proper `ValidationError` handling.

---

## High Priority

### ~~4. Unpaginated `.all()` Queries~~ — DONE
Endpoints for rules, plugins, attack vectors, products, users, controls, reports, and filters all load entire tables into memory. These become DoS vectors as data grows.

**Fix:** Add pagination (page/per_page query params) to all list endpoints. Consider a shared pagination helper.

**Resolution:** Created `paginate_query()` helper in `backend/api/validation.py` supporting `?page=` and `?per_page=` query params (default 50, max 200). Applied to 7 high-traffic endpoints: notification rules, products, active users, saved filters, report templates, report schedules. Remaining small lookup tables (attack vectors, terminal impacts, controls) are naturally bounded reference data. Updated all affected test assertions.

---

### ~~5. Missing Database Indexes~~ — DONE
Frequently filtered/joined columns lack indexes:
- `Vulnerability.status`
- `Vulnerability.created_by`
- `Vulnerability.assigned_to`
- `AuditLog.user_id` (`backend/models/auth.py`)
- `SoftwareComponent` — no composite index on `(product_version_id, name)`

**Fix:** Add `index=True` to these columns in the model definitions.

**Resolution:** Added `index=True` to all four columns and a composite `Index("ix_software_components_version_name", "product_version_id", "name")` on `SoftwareComponent`. Note: `Notification.user_id` already had `index=True`.

---

### ~~6. N+1 Queries~~ — DONE
- `backend/services/sbom_ingest.py` — loads entire vulnerability table into memory
- `backend/services/component_correlation.py` — loads all components without filtering

**Fix:** Batch queries outside loops, add filtering before `.all()`.

**Resolution:** Added `product_version_id` filter parameter to `correlate_vulnerability_to_components()` so it only loads components for the relevant product version. Updated `sbom_ingest.py` to pass `product_version_id` and use `yield_per(100)` for streaming instead of `.all()`. Note: `notification_rules.py:44` was already a batch query (not N+1).

---

### 7. Rate Limiting Gaps
Only login, vuln list, and export are rate-limited. Unprotected endpoints include:
- Password change
- Report generation (CPU-intensive)
- All other write endpoints

Also: the in-memory rate limit backend doesn't work across multiple worker processes.

**Fix:** Add rate limits to write endpoints and expensive operations. Document that production deployments should use the Redis backend.

---

## Medium Priority

### ~~8. Generic `except Exception` Blocks~~ — DONE
Silent exception swallowing hides real errors in multiple locations:
- `backend/api/auth_routes.py` (OIDC callback)
- `backend/api/vulnerabilities.py` (create, batch update)
- `backend/api/products.py` (create version, update version)
- `backend/auth.py` (token issued_at parsing)
- `backend/uvt_app.py` (500 handler)

**Fix:** Replace with specific exception types. Add `app.logger.exception()` to the 500 handler and to all catch blocks that re-raise as 500.

**Resolution:** Added `current_app.logger.exception()` to all generic catch blocks in `auth_routes.py`, `vulnerabilities.py`, `products.py`, and the 500 error handler in `uvt_app.py`. Narrowed `except Exception` to `except (TypeError, ValueError, OSError)` in `auth.py` token validation.

---

### ~~9. Frontend Stale Caches~~ — DONE
**File:** `frontend/src/features/vulnerabilities/view/vulnListView.js`

Three global caches (`cachedProductVersions`, `cachedAttackVectors`, `cachedTerminalImpacts`) never invalidate. Navigating away and back serves stale data.

**Fix:** Add a TTL or clear caches on route change.

**Resolution:** Added 5-minute TTL (`CACHE_TTL_MS`) to all three caches. Each `ensure*()` function now checks `Date.now() - cachedAt` before returning cached data.

---

### ~~10. Frontend State Bug — Missing `emit()`~~ — DONE
**File:** `frontend/src/state/store.js`

`upsertNotification()` modifies the notifications array but doesn't call `emit()`, so subscribers aren't notified of changes.

**Fix:** Call `emit()` after mutation.

**Resolution:** Added `emit()` call at the end of `upsertNotification()`.

---

### 11. No Docker Support
No Dockerfile or docker-compose configuration exists.

**Fix:** Add a `Dockerfile` and `docker-compose.yml` for local development and deployment.

---

### 12. Accessibility Gaps
- Several views use `window.prompt()` instead of proper modal dialogs
- Form inputs often lack proper `<label>` associations
- Notification dropdown in `frontend/src/ui/layout/header.js` isn't keyboard-navigable

**Fix:** Replace `window.prompt()` with the existing modal UI primitive. Add `<label>` and `aria-label` attributes where missing. Make dropdowns keyboard-navigable.

---

### 13. Missing Loading States
Many async operations (comment edit/delete, product version updates, vulnerability updates) disable the button but provide no visual feedback.

**Fix:** Add a spinner or text change to buttons during in-flight requests.

---

## Low Priority

### 14. Code Duplication
- Audit logging pattern is copy-pasted across 5+ API files (`products.py`, `users.py`, `vulnerabilities.py`, `notification_rules.py`, `plugins.py`)
- Serialization helpers (`_product_json`, `_rule_json`, `_user_json`) are inline instead of centralized in `backend/serializers/`

**Fix:** Extract shared audit logging into a utility. Move serialization helpers into the serializers package.

---

### 15. Inconsistent Error Response Format
**File:** `backend/api/validation.py`

`error_response()` includes `status` in the JSON body redundantly with the HTTP status code.

**Fix:** Remove the `status` field from JSON payloads, or standardize its presence across all error responses.

---

### 16. Frontend Memory Leaks
- Global `liveStream` in `frontend/src/main.js` isn't cleaned up on logout
- `dropdownOpen` state in `frontend/src/ui/layout/header.js` persists across routes

**Fix:** Close `liveStream` on logout. Reset dropdown state on route change.

---

### 17. Frontend Test Coverage
8 test files cover API adapters and logic, but no view components, state store, or UI primitives are tested.

**Fix:** Add tests for the store (especially `upsertNotification`), UI primitives, and at least smoke tests for key views.

---

### 18. No localStorage Quota Checking
**File:** `frontend/src/features/dashboard/layoutState.js`

Dashboard layout state writes to localStorage without checking available space.

**Fix:** Wrap `localStorage.setItem` in a try-catch to handle `QuotaExceededError`.

---

## What's Done Well

- **Three-layer architecture** (Blueprints -> Services -> Models) is clean and consistent
- **Auth system** is solid: JWT + refresh tokens + API tokens + RBAC with scopes
- **Frontend XSS prevention** — consistent use of `el()` helper with `textContent`, no unsafe `innerHTML` injection
- **API client** has retry with backoff, automatic token refresh, CSRF handling, and request deduplication
- **CORS validation** properly parses and validates origin URLs
- **Rate limiter** has both memory and Redis backends with Lua scripting for atomicity
- **OIDC integration** is comprehensive with JWKS validation, nonce/state checks, and role mapping
- **Dev setup scripts** for both bash and PowerShell

---

## Recommended Order of Action

| Phase | Items | Status |
|-------|-------|--------|
| **1 — Security** | Secret validation (#1), input validation (#3), error logging (#8) | DONE |
| **2 — CI** | Add test jobs to CI (#2) | DONE |
| **3 — Data** | Add indexes (#5) | DONE |
| **4 — Performance** | Paginate list endpoints (#4), fix N+1s (#6) | DONE |
| **5 — Hardening** | Rate limit remaining endpoints (#7), Docker (#11) | Pending |
| **6 — Frontend** | ~~Fix state bug (#10), cache invalidation (#9)~~, accessibility (#12) | Partial |
