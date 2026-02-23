# Universal Vulnerability Tracker (UVT)

Universal Vulnerability Tracker (UVT) is a Flask + vanilla JavaScript application for tracking products, versions, and vulnerabilities. It includes:
- A Python API backend (Flask + SQLAlchemy)
- A static frontend (ES modules, no bundler required)
- Built-in auth, catalog management, and vulnerability workflow endpoints

## Table of contents
- [Project layout](#project-layout)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Common workflows](#common-workflows)
- [Testing](#testing)
- [Repository hygiene](#repository-hygiene)
- [Backend architecture](#backend-architecture)

## Project layout
- `backend/` – Flask app factory, API blueprints, services, and models
- `frontend/` – Static HTML/CSS/JS client
- `scripts/` – Repo utility scripts
- `requirements.txt` – Python dependencies
- `TESTING_README.md` – Expanded testing guide

## Quick start

### 1) Backend setup
Prerequisites:
- Python 3.11+
- Optional: Postgres (default is local SQLite)

Install dependencies:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the API:
```bash
export FLASK_APP=backend.uvt_app
flask run --debug
```

By default, the API is available at `http://127.0.0.1:5000` and provides a health check at `/api/health`.

### 2) Frontend setup
Serve the `frontend/` directory with any static server:
```bash
cd frontend
python -m http.server 5173
```

Frontend default URL: `http://127.0.0.1:5173`

### 3) (Optional) Seed an admin user
```bash
flask seed-admin --username admin --email admin@example.com --password changeme
```

## Configuration

### Core environment variables
- `DATABASE_URL` – DB connection string (default: `sqlite:///uvt.db`)
- `SECRET_KEY` – Flask session secret (default: `dev-secret`)
- `JWT_SECRET` – Token signing secret (default: `dev-jwt-secret`)
- `ALLOW_PUBLIC_REGISTRATION` – Set `true` to allow `/api/auth/register` (default: `false`)

### CORS
- `CORS_ALLOWED_ORIGINS` – Comma-separated list of allowed origins for `/api/*`
  - Example: `http://localhost:5173,https://uvt.example.com`
  - Must be full origins (`http://` or `https://` only; no paths/query/fragments)
  - If unset, UVT allows common local dev origins:
    - `http://127.0.0.1:5173`
    - `http://localhost:5173`
    - `http://127.0.0.1:5000`
    - `http://localhost:5000`

### Auth cookie / OIDC settings
- `AUTH_COOKIE_SECURE` – `Secure` cookie flag (production-like default: `true`, otherwise `false`)
- `AUTH_COOKIE_SAMESITE` – One of `Lax`, `Strict`, or `None` (default: `Lax`)
- `AUTH_COOKIE_DOMAIN` – Optional cookie domain override

## Common workflows

### Point frontend to a different API base
Set a global before `src/main.js` loads:
```html
<script>
  window.__UVT_API_BASE__ = "http://127.0.0.1:5000";
</script>
```

### Useful entry points
- `backend/uvt_app.py` – App factory and extension wiring
- `backend/models/` – Core SQLAlchemy models organized by bounded context
- `frontend/src/main.js` – Frontend bootstrap and routing

### Flask shell for local inspection
```bash
flask --app backend.uvt_app shell
```

## Testing

See `TESTING_README.md` for full details.

Common commands:
```bash
pytest --cov=backend --cov-report=term-missing
node --test frontend/tests/**/*.test.js
```

## Repository hygiene
- Do not commit Python cache/build artifacts.
- Validate with:
  ```bash
  ./scripts/check-no-artifacts.sh
  ```
- Clean local Python cache files if needed:
  ```bash
  find . -type d -name '__pycache__' -prune -exec rm -rf {} +
  find . -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '*.pyd' \) -delete
  ```


## Backend architecture

See `docs/backend-architecture.md` for bounded context ownership and model placement rules.
