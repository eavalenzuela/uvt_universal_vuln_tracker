# Production Deployment Guide

Operational documentation for deploying and running the Universal Vulnerability Tracker (UVT) in production.

---

## Quick Start (Docker Compose)

```bash
# 1. Clone and enter the repo
git clone https://github.com/eavalenzuela/uvt_universal_vuln_tracker.git
cd uvt_universal_vuln_tracker

# 2. Create .env from the template
cp .env.example .env
# Edit .env — at minimum, set real values for SECRET_KEY, JWT_SECRET, POSTGRES_PASSWORD

# 3. Build and start
docker compose up -d --build

# 4. Seed the first admin user
docker compose exec backend flask seed-admin \
  --username admin --email admin@example.com --password '<strong-password>'

# 5. Verify
curl http://localhost:5000/api/health   # {"ok": true}
open http://localhost:5173               # Frontend
open http://localhost:5000/api/docs      # Swagger UI
```

---

## Architecture Overview

```
                 ┌──────────────┐
  Browser ──────►│ nginx:5173   │
                 │  (frontend)  │
                 │  /api/* ─────┼──► backend:5000 (Gunicorn + Flask)
                 └──────────────┘          │              │
                                     ┌─────┘              └─────┐
                                     ▼                          ▼
                              postgres:5432               redis:6379
                              (primary DB)              (rate limiting)
```

| Service | Image | Purpose |
|---------|-------|---------|
| **backend** | `python:3.12-slim` + Gunicorn | Flask API, 4 sync workers |
| **frontend** | `nginx:alpine` | SPA static files + reverse proxy to `/api/` |
| **postgres** | `postgres:16-alpine` | Primary data store |
| **redis** | `redis:7-alpine` | Distributed rate limiting backend |

All services include health checks; `backend` and `frontend` use `restart: unless-stopped`.

---

## Environment Variables

### Secrets (required in production)

The app **refuses to start** if these are left at their dev defaults.

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Flask session signing key. Use `python -c "import secrets; print(secrets.token_urlsafe(64))"` to generate. |
| `JWT_SECRET` | JWT token signing key. Generate the same way, use a different value. |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///uvt.db` | SQLAlchemy connection string. **Use PostgreSQL in production:** `postgresql+psycopg://user:pass@host:5432/dbname` |
| `POSTGRES_USER` | `uvt_user` | Docker Compose only — passed to the postgres container |
| `POSTGRES_PASSWORD` | `uvt_pass` | Docker Compose only — **change this** |
| `POSTGRES_DB` | `uvt` | Docker Compose only — database name |
| `DB_POOL_SIZE` | `5` | Connection pool size (PostgreSQL only) |
| `DB_POOL_MAX_OVERFLOW` | `10` | Extra connections allowed beyond pool_size |
| `DB_POOL_RECYCLE` | `1800` | Recycle connections after N seconds (prevents stale TCP) |
| `DB_POOL_PRE_PING` | `true` | Test connections before use |

**Pool sizing guidance:** For most deployments, the defaults work well. With 4 Gunicorn workers, the max simultaneous connections are `workers * (pool_size + max_overflow)` = 60. Ensure your PostgreSQL `max_connections` accommodates this.

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOW_PUBLIC_REGISTRATION` | `false` | Set `true` only if you want open sign-ups. First registered user automatically becomes Admin. |
| `REFRESH_TOKEN_LIFETIME_DAYS` | `30` | How long refresh tokens remain valid |
| `AUTH_COOKIE_SECURE` | `true` (prod) | Set `false` only if not using HTTPS (not recommended) |
| `AUTH_COOKIE_SAMESITE` | `Lax` | Cookie SameSite policy (`Lax`, `Strict`, or `None`) |
| `AUTH_COOKIE_DOMAIN` | unset | Override cookie domain for subdomain sharing |

### OIDC / SSO (optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_ENABLED` | `false` | Enable OIDC authentication |
| `OIDC_ISSUER` | — | Provider issuer URL (e.g., `https://idp.example.com/realms/uvt`) |
| `OIDC_CLIENT_ID` | — | OAuth2 client ID |
| `OIDC_CLIENT_SECRET` | — | OAuth2 client secret |
| `OIDC_REDIRECT_URL` | — | Callback URL: `https://your-domain.com/api/auth/oidc/callback` |
| `OIDC_SCOPES` | `openid profile email` | Space-separated scopes |
| `OIDC_GROUPS_CLAIM` | `groups` | JWT claim containing user groups |
| `OIDC_DEFAULT_ROLE` | `Viewer` | Role for users not matching any group mapping |
| `OIDC_ROLE_MAPPING` | — | JSON object: `{"group-name": "Admin", "analysts": "Analyst"}` |

### CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ALLOWED_ORIGINS` | `http://127.0.0.1:5173,...` | Comma-separated allowed origins. Set to your actual frontend domain in production. |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_ENABLED` | `true` | Master switch |
| `RATE_LIMIT_BACKEND` | `memory` | Use `redis` for multi-worker/multi-instance deployments |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `RATE_LIMIT_AUTH_LOGIN_LIMIT` | `5` | Login attempts per window |
| `RATE_LIMIT_AUTH_LOGIN_WINDOW_SECONDS` | `60` | Login window (seconds) |
| `RATE_LIMIT_SENSITIVE_LIMIT` | `10` | Sensitive ops (password reset, etc.) per window |
| `RATE_LIMIT_SENSITIVE_WINDOW_SECONDS` | `60` | Sensitive window |
| `RATE_LIMIT_WRITE_LIMIT` | `30` | Write operations per window |
| `RATE_LIMIT_WRITE_WINDOW_SECONDS` | `60` | Write window |
| `RATE_LIMIT_VULN_LIST_LIMIT` | `60` | Vulnerability list queries per window |
| `RATE_LIMIT_VULN_LIST_WINDOW_SECONDS` | `60` | Vulnerability list window |
| `RATE_LIMIT_VULN_EXPORT_LIMIT` | `20` | Report exports per window |
| `RATE_LIMIT_VULN_EXPORT_WINDOW_SECONDS` | `60` | Export window |
| `RATE_LIMIT_HEALTH_LIMIT` | `120` | Health check requests per window |
| `RATE_LIMIT_HEALTH_WINDOW_SECONDS` | `60` | Health window |

> **Important:** The `memory` backend tracks limits per-process. With multiple Gunicorn workers (or multiple instances), users can exceed limits by landing on different workers. Use `redis` for production.

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `LOG_FORMAT` | `json` | `json` (structured, for aggregation) or `text` (human-readable) |

### Other

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | `production` | Set to `development` for dev mode. Controls secret validation and cookie defaults. |
| `FRONTEND_URL` | `http://127.0.0.1:5173` | Used in password reset emails. Set to your actual frontend URL. |
| `PLUGIN_IMPORT_PATHS` | — | Comma-separated Python module paths for custom plugins |

---

## Deployment Options

### Option 1: Docker Compose (recommended for small/medium)

The included `docker-compose.yml` runs all four services. Suitable for single-server deployments.

**Production checklist for Docker Compose:**

1. Copy `.env.example` to `.env` and set all secrets
2. Set `CORS_ALLOWED_ORIGINS` to your actual domain
3. Set `FRONTEND_URL` to your actual frontend URL
4. Set `RATE_LIMIT_BACKEND=redis`
5. Consider placing an external reverse proxy (Caddy, Traefik, or cloud LB) in front for TLS termination
6. Use a named volume or external PostgreSQL for data durability

**TLS termination example with Caddy:**

```
# Caddyfile
your-domain.com {
    reverse_proxy localhost:5173
}
```

Then set `CORS_ALLOWED_ORIGINS=https://your-domain.com` and `AUTH_COOKIE_SECURE=true`.

### Option 2: Standalone (no Docker)

```bash
# Prerequisites: Python 3.11+, PostgreSQL 14+, Redis 7+

# Backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-postgres.txt
export DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/uvt"
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')"
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')"
export RATE_LIMIT_BACKEND=redis
export REDIS_URL=redis://localhost:6379/0
export FLASK_APP=backend.uvt_app:create_app

# Create tables and seed admin
flask seed-admin --username admin --email admin@example.com --password '<strong-password>'

# Run with Gunicorn
gunicorn --bind 0.0.0.0:5000 \
  --workers 4 \
  --timeout 120 \
  --max-requests 1000 \
  --max-requests-jitter 50 \
  --access-logfile - \
  "backend.uvt_app:create_app()"

# Frontend — serve with any static file server or CDN
# The frontend/ directory is a static SPA; no build step needed.
cd frontend && python -m http.server 5173
# Or use nginx, Caddy, S3+CloudFront, etc.
```

### Option 3: Kubernetes

A minimal Kubernetes deployment uses four resources: a Deployment for the backend, a Deployment for the frontend, and external PostgreSQL + Redis (managed services recommended).

<details>
<summary>Example Kubernetes manifests</summary>

**Secret:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: uvt-secrets
type: Opaque
stringData:
  SECRET_KEY: "<generate-me>"
  JWT_SECRET: "<generate-me>"
  DATABASE_URL: "postgresql+psycopg://user:pass@postgres-host:5432/uvt"
  REDIS_URL: "redis://redis-host:6379/0"
```

**Backend Deployment + Service:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: uvt-backend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: uvt-backend
  template:
    metadata:
      labels:
        app: uvt-backend
    spec:
      containers:
        - name: backend
          image: your-registry/uvt-backend:latest
          ports:
            - containerPort: 5000
          envFrom:
            - secretRef:
                name: uvt-secrets
          env:
            - name: FLASK_ENV
              value: production
            - name: RATE_LIMIT_BACKEND
              value: redis
            - name: CORS_ALLOWED_ORIGINS
              value: "https://your-domain.com"
            - name: FRONTEND_URL
              value: "https://your-domain.com"
          livenessProbe:
            httpGet:
              path: /api/health
              port: 5000
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /api/health
              port: 5000
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: "1"
              memory: 512Mi
---
apiVersion: v1
kind: Service
metadata:
  name: uvt-backend
spec:
  selector:
    app: uvt-backend
  ports:
    - port: 5000
      targetPort: 5000
```

**Frontend Deployment + Service:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: uvt-frontend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: uvt-frontend
  template:
    metadata:
      labels:
        app: uvt-frontend
    spec:
      containers:
        - name: frontend
          image: your-registry/uvt-frontend:latest
          ports:
            - containerPort: 5173
          livenessProbe:
            httpGet:
              path: /
              port: 5173
            periodSeconds: 30
          resources:
            requests:
              cpu: 50m
              memory: 32Mi
            limits:
              cpu: 200m
              memory: 64Mi
---
apiVersion: v1
kind: Service
metadata:
  name: uvt-frontend
spec:
  selector:
    app: uvt-frontend
  ports:
    - port: 5173
      targetPort: 5173
```

**Ingress:**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: uvt-ingress
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - your-domain.com
      secretName: uvt-tls
  rules:
    - host: your-domain.com
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: uvt-backend
                port:
                  number: 5000
          - path: /
            pathType: Prefix
            backend:
              service:
                name: uvt-frontend
                port:
                  number: 5173
```

</details>

---

## Gunicorn Tuning

The Dockerfile runs Gunicorn with 4 sync workers. For production, consider tuning:

```bash
gunicorn \
  --bind 0.0.0.0:5000 \
  --workers "${GUNICORN_WORKERS:-4}" \
  --timeout 120 \
  --max-requests 1000 \
  --max-requests-jitter 50 \
  --access-logfile - \
  "backend.uvt_app:create_app()"
```

| Setting | Recommendation |
|---------|---------------|
| `--workers` | `(2 * CPU_cores) + 1`. For a 2-core VM, use 5. |
| `--timeout` | `120` — prevents slow queries from killing workers silently |
| `--max-requests` | `1000` — restart workers periodically to prevent memory leaks |
| `--max-requests-jitter` | `50` — stagger restarts so not all workers recycle at once |

To customize the Docker image, override the CMD:

```yaml
# docker-compose.override.yml
services:
  backend:
    command: >
      gunicorn --bind 0.0.0.0:5000
      --workers 8 --timeout 120
      --max-requests 1000 --max-requests-jitter 50
      --access-logfile -
      "backend.uvt_app:create_app()"
```

---

## Database Operations

### Initial Setup

Tables are created automatically on app startup (`db.create_all()`). For a fresh deployment:

```bash
# Docker Compose
docker compose exec backend flask seed-admin \
  --username admin --email admin@example.com --password '<strong-password>'

# Standalone
flask seed-admin --username admin --email admin@example.com --password '<strong-password>'
```

The `seed-admin` command is idempotent — safe to run multiple times.

### Backup

**PostgreSQL (recommended):**

```bash
# From the Docker host
docker compose exec postgres pg_dump -U uvt_user -Fc uvt > uvt-$(date +%Y%m%d-%H%M%S).dump

# Standalone
pg_dump -Fc -d "$DATABASE_URL" -f uvt-$(date +%Y%m%d-%H%M%S).dump
```

**Automated backup with cron:**

```bash
# /etc/cron.d/uvt-backup — daily at 02:00
0 2 * * * root docker compose -f /path/to/docker-compose.yml exec -T postgres \
  pg_dump -U uvt_user -Fc uvt > /backups/uvt-$(date +\%Y\%m\%d).dump
```

**SQLite (development only):**

```bash
cp instance/uvt.db instance/uvt.db.$(date +%Y%m%d-%H%M%S).bak
```

### Restore

```bash
# PostgreSQL
pg_restore --clean --if-exists -d "$DATABASE_URL" uvt-20260327.dump

# Docker Compose
docker compose exec -T postgres pg_restore --clean --if-exists \
  -U uvt_user -d uvt < uvt-20260327.dump
```

### Schema Upgrades

The `scripts/update-db.sh` script handles migrations with automatic backup and rollback on failure:

```bash
# From repo root
./scripts/update-db.sh
./scripts/update-db.sh --database-url "postgresql+psycopg://user:pass@host:5432/uvt"
```

This script:
1. Creates a backup (pg_dump for PostgreSQL, file copy for SQLite)
2. Runs the migration
3. Automatically restores from backup if the migration fails

---

## Logging and Monitoring

### Structured Logging

UVT outputs JSON-structured logs by default. Each log line includes:

```json
{
  "timestamp": "2026-03-27 12:00:00,000",
  "level": "INFO",
  "name": "backend.uvt_app",
  "message": "POST /api/auth/login 200",
  "method": "POST",
  "path": "/api/auth/login",
  "status": 200,
  "duration_ms": 45.2,
  "user_id": 1,
  "remote_addr": "10.0.0.1",
  "request_id": "a1b2c3d4e5f6"
}
```

**Request ID correlation:** Every request gets a unique ID (or inherits from the `X-Request-ID` header). The ID is returned in the `X-Request-ID` response header for tracing.

**Log aggregation:** Pipe stdout to your preferred collector (Fluentd, Filebeat, CloudWatch agent, etc.). The JSON format is compatible with most log platforms out of the box.

### Health Check

```
GET /api/health → {"ok": true}
```

Use this endpoint for load balancer health checks, Kubernetes probes, and uptime monitoring.

### Key Events to Alert On

| Log Pattern | Meaning |
|-------------|---------|
| `"level": "ERROR"` | Application errors — investigate |
| `"status": 500` | Server errors — check stack traces |
| `"status": 401"` + high frequency | Possible brute-force attack |
| `"status": 429"` | Rate limit triggered |
| Health check failures | Backend is down or overloaded |

---

## Operational Runbook

### Seed or Reset an Admin User

```bash
docker compose exec backend flask seed-admin \
  --username admin --email admin@example.com --password '<new-password>'
```

Safe to re-run — updates the existing user if the username or email matches.

### Run Plugins Manually

```bash
# Run all enabled plugins that are due
docker compose exec backend flask run-plugins --only-due

# Run a specific plugin
docker compose exec backend flask run-plugins --plugin-id nvd-feed

# Run all plugins including disabled ones
docker compose exec backend flask run-plugins --include-disabled
```

### Run Notification Scan

```bash
# Dry run — show what would be sent
docker compose exec backend flask run-notification-scan --dry-run

# Actually send notifications
docker compose exec backend flask run-notification-scan
```

### View Logs

```bash
# All services
docker compose logs -f

# Backend only, last 100 lines
docker compose logs -f --tail 100 backend

# Filter for errors (with jq)
docker compose logs backend --no-log-prefix 2>&1 | jq 'select(.level == "ERROR")'
```

### Restart a Service

```bash
docker compose restart backend    # graceful restart
docker compose up -d --build backend   # rebuild and restart
```

### Scale Backend Workers

For Docker Compose, override the Gunicorn command (see [Gunicorn Tuning](#gunicorn-tuning)). For Kubernetes, increase replicas:

```bash
kubectl scale deployment uvt-backend --replicas=4
```

### Check Database Connectivity

```bash
docker compose exec backend python -c "
from backend.uvt_app import create_app
app = create_app()
with app.app_context():
    from backend.database import db
    db.session.execute(db.text('SELECT 1'))
    print('Database OK')
"
```

---

## Security Checklist

- [ ] `SECRET_KEY` and `JWT_SECRET` set to unique, random values (not dev defaults)
- [ ] `POSTGRES_PASSWORD` set to a strong password
- [ ] `CORS_ALLOWED_ORIGINS` restricted to your actual frontend domain
- [ ] `ALLOW_PUBLIC_REGISTRATION=false` (unless you want open sign-ups)
- [ ] `AUTH_COOKIE_SECURE=true` (automatic when `FLASK_ENV != development`)
- [ ] TLS termination configured (reverse proxy, cloud LB, or Caddy)
- [ ] `RATE_LIMIT_BACKEND=redis` for multi-worker deployments
- [ ] Database backups scheduled and tested
- [ ] Log aggregation configured (JSON logs are production-ready)
- [ ] Health check monitoring active on `/api/health`
- [ ] Admin user seeded with a strong password
- [ ] Default ports changed or firewalled (PostgreSQL 5432, Redis 6379 should not be public)
