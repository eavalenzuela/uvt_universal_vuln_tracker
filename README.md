# Universal Vulnerability Tracker (UVT)

Universal Vulnerability Tracker (UVT) is a simple Flask + vanilla JS application for tracking products, their versions, and associated vulnerabilities. The project ships with a lightweight API backend and an unbundled frontend you can serve with any static file host.

## Project structure
- `backend/` – Flask application, SQLAlchemy models, and API blueprints
- `frontend/` – Static HTML, CSS, and JavaScript that talks to the API via fetch
- `requirements.txt` – Python dependencies for the backend

## Backend quickstart

### Prerequisites
- Python 3.11+
- (Optional) A Postgres database if you do not want to use the default SQLite file

### Setup
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Environment variables
- `DATABASE_URL` – Database connection string; defaults to `sqlite:///uvt.db`
- `SECRET_KEY` – Flask session secret; defaults to `dev-secret`
- `JWT_SECRET` – Secret used to sign auth tokens; defaults to `dev-jwt-secret`
- `ALLOW_PUBLIC_REGISTRATION` – Set to `true` to allow `/api/auth/register`; defaults to `false`

### Running the API server
The Flask app factory lives at `backend.uvt_app:create_app`. Use the Flask CLI so extensions (Migrate, custom commands) are available:
```bash
export FLASK_APP=backend.uvt_app
flask run --debug
```
The server listens on port 5000 by default and exposes a simple health check at `/api/health`.

### Database & admin user
The default SQLite database initializes tables on first run when no migration scripts are present. If you use a different database backend, you can still wire up Flask-Migrate in your own environment. Seed an admin account (safe to run multiple times):
```bash
flask seed-admin --username admin --email admin@example.com --password changeme
```

### API highlights
- Auth endpoints under `/api/auth` for login, optional registration, and a `/me` user profile check
- Product and version management under `/api/products`
- Vulnerability CRUD under `/api/vulnerabilities`, plus attack vector and terminal impact mappings
- Controls and attack-vector catalog management under `/api/controls` and `/api/attack_vectors`
- Plugin catalog and run triggers under `/api/plugins`
- User administration under `/api/users`

## Frontend quickstart
The frontend is plain ES modules—no bundler required. Serve the `frontend/` directory with any static file server so the browser can resolve module imports:
```bash
cd frontend
python -m http.server 5173
```

Point the UI at a different API base by defining a global before `src/main.js` loads (CORS is already configured for `http://localhost:5173` in development):
```html
<script>
  window.__UVT_API_BASE__ = "http://127.0.0.1:5000";
</script>
```

## Useful entry points
- `backend/uvt_app.py` – Flask app factory and CORS configuration
- `backend/models.py` – SQLAlchemy models for users, products, versions, vulnerabilities, notifications, and audit logs
- `frontend/src/main.js` – Frontend bootstrapper that renders the shell and initializes routing

## Development tips
- Use `flask --app backend.uvt_app shell` for quick database inspection via `db` and models
- Default CORS allowlist already includes `http://localhost:5000` and `http://localhost:5173`
- Update `frontend/src/config.js` if you prefer a hard-coded API base instead of the global variable

## Repository hygiene
- Python cache/build artifacts should never be committed. CI enforces this via `scripts/check-no-artifacts.sh`.
- Before committing, you can run:
  ```bash
  ./scripts/check-no-artifacts.sh
  ```
- If you need to clean local cache artifacts:
  ```bash
  find . -type d -name '__pycache__' -prune -exec rm -rf {} +
  find . -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '*.pyd' \) -delete
  ```
