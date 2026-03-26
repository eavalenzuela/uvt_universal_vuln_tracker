# Testing Guide

This project includes a backend-heavy pytest suite plus lightweight frontend smoke tests.

## Setup

1. Create and activate a virtual environment.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure Node.js is available for frontend smoke tests (`node --version`).

## Backend unit/integration coverage

Run the full backend test suite with coverage:

```bash
pytest --cov=backend --cov-report=term-missing
```

What this covers:
- API contract and validation branches across auth, reporting, ingest, catalogs, and dashboards.
- Service-level behavior (batch upsert/rollback semantics, ingest edge handling).
- In-memory SQLite lifecycle per test via shared fixtures (`backend/tests/conftest.py`).

## Frontend smoke tests

Run lightweight smoke checks for router guard behavior and API adapter contracts:

```bash
node --test frontend/tests/**/*.test.js
```

Smoke tests focus on:
- Route guard behavior (`requireAuth` / `requireRole`) with minimal state wiring.
- API adapter behavior (query-string composition and auth header forwarding).

## Optional slow/perf tests

The repository does not currently ship dedicated perf benchmarks by default. If you add them, keep them optional and separate from fast CI checks (for example under `tests/perf/` or behind a marker) so core unit/integration and smoke runs stay fast.

## Notes

- Public registration is enabled during tests to bootstrap the initial admin user.
- JWT tokens in tests are generated using the same helper functions used by runtime code.
- Shared fixtures for representative users/products/vulnerabilities are preferred over repetitive inline setup.
