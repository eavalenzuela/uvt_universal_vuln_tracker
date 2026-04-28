# Backend Architecture

High-level documentation for the UVT Python/Flask backend.

---

## App Factory (`uvt_app.py`)

`create_app()` bootstraps the Flask application:

1. Loads typed config via `load_config()` / `apply_config()`
2. Initializes CORS (credentials, custom headers)
3. Registers CLI commands (`seed-admin`, `run-plugins`, `run-notification-scan`)
4. Initializes SQLAlchemy via `init_database(app)`
5. Loads plugin registry via `init_plugin_registry(app)`
6. Registers all API blueprints via `register_api(app)`
7. Installs `before_request` scope enforcement and CSRF validation
8. Adds error handlers (ValidationError, 404, 500) and `/api/health`

---

## Configuration (`config.py`)

Frozen `AppConfig` dataclass loaded from environment variables.

| Group | Key Settings |
|-------|-------------|
| Secrets | `SECRET_KEY`, `JWT_SECRET` (fail-fast in production if dev defaults) |
| Auth | `ALLOW_PUBLIC_REGISTRATION`, refresh token lifetime, cookie security |
| OIDC | issuer, client ID/secret, redirect URL, scopes, groups claim, role mapping |
| CORS | `CORS_ALLOWED_ORIGINS` (comma-separated) |
| Database | `DATABASE_URL` (default: `sqlite:///uvt.db`, supports PostgreSQL) |
| Rate Limiting | per-endpoint limits & windows, memory or Redis backend |
| Plugins | `PLUGIN_IMPORT_PATHS` for custom plugin modules |

---

## Three-Layer Design

```
Blueprints (routes)  ->  Services (business logic)  ->  Models (data)
```

### API Blueprints (`api/`)

31 route modules organized by domain. Every route is also reachable under `/api/v1/*` via WSGI alias middleware (F18).

| Module | Prefix | Purpose |
|--------|--------|---------|
| `auth_routes.py` | `/api/auth` | Login, refresh, logout, register, OIDC SSO, CSRF token, password reset |
| `products.py` | `/api/products` | Product CRUD, versions |
| `components.py` | `/api` | SBOM upload, component listing, dependency graphs, version comparison |
| `controls.py` | `/api/controls` | Security control CRUD |
| `attack_vectors.py` | `/api/attack_vectors` | Attack vector CRUD + vulnerability mapping |
| `terminal_impacts.py` | `/api/terminal_impacts` | Terminal impact CRUD + vulnerability mapping |
| `vuln_crud.py` | `/api/vulnerabilities` | Vulnerability CRUD, merge, enrich, activity/history |
| `vuln_comments.py` | `/api/vulnerabilities` | Comment threads on vulnerabilities |
| `vuln_versions.py` | `/api/vulnerabilities` | Affected product version associations |
| `vuln_bulk.py` | `/api/vulnerabilities` | Batch/bulk updates, watchers |
| `vulnerability_filters.py` | `/api/vulnerabilities/filters` | Saved filter presets |
| `users_crud.py` | `/api/users` | User CRUD, invite, impersonate, toggle active, export |
| `users_tokens.py` | `/api/users` | API token management (personal + admin) |
| `user_preferences.py` | `/api/users/me/preferences` | Per-user settings (timezone, default filter, channels) |
| `audit_logs.py` | `/api/audit-logs` | Audit log listing |
| `plugins.py` | `/api/plugins` | Plugin listing, run, config, artifact download, import |
| `notification_rules.py` | `/api/notification-rules` | Notification rule CRUD, test-send, delivery logs |
| `notification_delivery.py` | `/api` | Delivery attempt retry/replay |
| `notifications.py` | `/api/notifications` | In-app notification CRUD, read-all |
| `live_notifications.py` | `/api/notifications/stream` | SSE real-time event stream |
| `sla_policy.py` | `/api/sla_policy` | SLA policy get/set |
| `report_exports.py` | `/api/reports` | Vulnerability/dashboard export (CSV/JSON/PDF), artifact status + download, risk trends |
| `report_templates.py` | `/api/reports/templates` | Report template CRUD |
| `report_schedules.py` | `/api/reports/schedules` | Report schedule CRUD + manual run |
| `dashboard_layout_presets.py` | `/api/dashboard/layout-presets` | Dashboard layout preset CRUD |
| `webhooks.py` | `/api/webhooks` | Inbound webhook receiver + endpoint CRUD (F14) |
| `scanner_imports.py` | `/api/scanner-imports` | Nessus / Qualys / Trivy bulk import (F19) |
| `teams.py` | `/api/teams`, `/api/me/teams` | Team CRUD + memberships, current-user team list (F15) |
| `branding.py` | `/api/admin/branding` | PDF report branding settings + logo upload (F17 Slice 3, admin-only) |
| `tasks.py` | `/api/tasks` | Background Celery task status |
| `search.py` | `/api/search` | Cross-entity full-text search (F9) |

Helpers: `validation.py` — `ValidationError`, `error_response()`, request parsing. `vulnerability_query.py` — service-level query builder (no blueprint).

### Services (`services/`)

| Service | Responsibility |
|---------|---------------|
| `vulnerability_service.py` | Vulnerability CRUD with validation and SLA recomputation |
| `vulnerability_query.py` | Dynamic query builder for vulnerability filtering |
| `vuln_ingest.py` | Normalized vulnerability ingestion from any source |
| `product_service.py` | Product CRUD, versions, owners, control associations |
| `sbom_ingest.py` | CycloneDX/SPDX SBOM parsing, component + dependency creation |
| `component_correlation.py` | Links vulnerabilities to affected components (PURL/CPE matching) |
| `component_diff.py` | Compares component lists between product versions |
| `controls_ingest.py` | Security control framework ingestion and upsert |
| `cve_enrichment.py` | Upstream CVE data enrichment |
| `dedup.py` | Vulnerability deduplication and merge |
| `sla.py` | SLA due-date computation from severity-based policy |
| `audit.py` | Audit log recording with model snapshots and secret filtering |
| `notification_rules.py` | Rule evaluation, scheduled notification scan, multi-channel delivery |
| `dashboard_live_metrics.py` | Publishes SSE events for real-time dashboard updates |
| `email_delivery.py` | SMTP email delivery |
| `slack_alerts.py` | Slack webhook message delivery |
| `jira_sync.py` | Jira API integration (create/update issues) |
| `oidc.py` | OIDC authorization flow, user creation from claims |
| `oidc_mapping.py` | Maps OIDC group claims to UVT roles |
| `password_reset.py` | Forgot-password / reset-password token lifecycle |
| `reporting_service.py` | Aggregates vulnerability data for reports — `dashboard_aggregate()`, `risk_trends()`, `executive_summary()` (KPIs + severity + SLA buckets) |
| `pdf_renderer.py` | F17 Slice 1: WeasyPrint + Jinja2 renderer. Auto-loads `OrganizationBranding` row, exposes `render_pdf(layout_name, context) -> bytes` |
| `pdf_charts.py` | F17 Slice 2: Matplotlib (`Agg` backend) chart helpers — `severity_donut()`, `sla_bar()` returning base64 PNG data URIs |
| `team_scope.py` | F15: `team_scope(query, model, user, allow_null_team=False)` filters every query site to the user's team membership; Admin and Default-team posture handled centrally |
| `webhook_ingest.py` | F14: dispatches inbound webhook payloads to format adapters and into the normalized vulnerability model |
| `scanner_imports.py` | F19: parses Nessus `.nessus` XML, Qualys CSV/XML, and Trivy JSON into vulnerability records (CVE-deduped) |

### Models (`models/`)

Organized by bounded context. All use SQLAlchemy ORM with UTC-aware timestamps (`TZDateTime`).

**Auth** (`models/auth.py`, `models/password_reset.py`):
- `User` — username, email, password_hash, role, token_version
- `ApiToken` — hashed secret, scopes, expiry, usage tracking
- `RefreshToken` — hashed token, expiry, revocation
- `AuditLog` — action, table, record, old/new values (JSON), team_id
- `PasswordResetToken` — single-use, hashed, 60-minute TTL (F2)

**Teams** (`models/teams.py`, F15):
- `Team` — name, slug, description, `is_default` (singleton-Default-team enforced via partial unique index)
- `UserTeam` — user↔team membership with `is_default` (per-user active team)

**Products** (`models/products.py`):
- `Product` — name, description, owners, versions, controls
- `ProductVersion` — version string, release date, active flag, components
- `ProductOwner` — product-to-user ownership link
- `Control` — security control with framework affiliation
- `ControlSource` — external source tracking for controls
- `ProductControl` — product-to-control link with implementation status
- `SoftwareComponent` — SBOM component (name, version, PURL, CPE, ecosystem)
- `ComponentDependency` — parent/child dependency edges with depth tracking

**Vulnerabilities** (`models/vulnerabilities.py`):
- `Vulnerability` — CVE ID, severity, CVSS, status, SLA, merge support, assignment
- `VulnerabilityVersion` — affected product version link with mitigation status
- `VulnerabilityComment` — threaded comments with edit tracking
- `VulnerabilityWatcher` — per-user watch subscriptions
- `VulnerabilityComponent` — component correlation links (match type, dependency path)
- `VulnerabilitySource` — external source tracking with raw JSON
- `AttackVector` / `VulnerabilityAttackVector` — attack vector associations
- `TerminalImpact` / `VulnerabilityTerminalImpact` — terminal impact associations
- `SlaPolicy` — severity-based SLA policy (JSON)
- `SavedVulnerabilityFilter` — saved filter presets (private/team)
- `DashboardLayoutPreset` — dashboard widget layout presets

**Notifications** (`models/notifications.py`):
- `Notification` — per-user in-app notifications
- `NotificationRule` — delivery rules (adapter, severity, scope, escalation)
- `NotificationDeliveryLog` — delivery attempt records
- `NotificationDeliveryCheckpoint` — per-rule per-vuln notification state

**Plugins** (`models/plugins.py`):
- `PluginConfig` — plugin settings, schedule, enabled flag
- `PluginRun` — execution records with status and stats
- `PluginRunArtifact` — files produced by plugin runs
- `PluginRunArtifactLink` — links artifacts to vulns/product versions
- `ExternalSourceState` — incremental sync cursors per plugin

**Reports** (`models/reports.py`):
- `ReportTemplate` — saved report configurations (fields, filters, delivery)
- `ReportSchedule` — scheduled report execution with retry tracking
- `ReportArtifact` — generated report files with checksums; F17 Slice 2 added `status` (`pending`/`ready`/`failed`), `error`, `celery_task_id` for the async PDF lifecycle

**Branding** (`models/branding.py`, F17 Slice 3):
- `OrganizationBranding` — singleton row with `primary_color`, `footer_text`, `logo_path`. `logo_data_uri()` helper inlines the logo as base64 so WeasyPrint never needs filesystem access from templates.

**Webhooks** (`models/webhooks.py`, F14):
- `WebhookEndpoint` — token-authenticated inbound endpoint (scoped per format)
- `WebhookDeliveryLog` — per-payload ingest results

**User Preferences** (`models/user_preferences.py`, F16):
- `UserPreferences` — JSON blob per user: timezone, default vulnerability filter, notification channel preferences

### Serializers (`serializers/`)

JSON response helpers per domain: `product_serializers.py`, `vulnerability_serializers.py`, `users_serializers.py`, `control_serializers.py`, `notification_rule_serializers.py`, `plugin_serializers.py`, `report_serializers.py`.

---

## Authentication & Authorization

### Auth Module (`auth.py`)

- **JWT tokens**: HS256, 12h expiry, claims include user ID, role, token_version
- **Cookie auth**: `uvt_auth_token` cookie with CSRF validation (`X-CSRF-Token` header vs `uvt_csrf_token` cookie)
- **API tokens**: SHA256-hashed `uvt_*` format, scoped, revocable, tracks last_used_at
- **Refresh tokens**: Hashed, rotated on use, configurable lifetime (default 30 days)
- **Token revocation**: Incrementing `token_version` invalidates all prior JWTs
- **Password hashing**: Werkzeug `generate_password_hash` / `check_password_hash`
- **Request auth**: `authenticate_request()` checks Bearer header then auth cookie
- **Decorators**: `@login_required`, `@admin_required`, `@role_required(*roles)`

### Permissions (`permissions.py`)

Three roles with 16 scopes across 8 resource types:

| Role | Access |
|------|--------|
| **Admin** | All scopes (read + write for all resources) |
| **Analyst** | All except `users:write` |
| **Viewer** | Read-only (all `:read` scopes) |

`scope_for_request(path, method)` maps each request to its required scope.
`enforce_scopes(app)` runs as a `before_request` hook.

### Team Scope (`services/team_scope.py`, F15)

A second access layer on top of roles. Every query that returns team-scoped data passes through `team_scope(query, model, user, allow_null_team=False)`, which:

- Lets Admins see every row.
- For non-Admins, restricts to rows where `model.team_id` is in the user's `UserTeam` set, optionally including `team_id IS NULL` (e.g. CVE intel that's globally visible).
- Reads the active team from the `X-UVT-Team-Id` request header (set by the frontend's top-nav team selector), falling back to the user's default team.

Default-team posture (Phase 1 of F15) stamps every existing row with the auto-created Default team so behavior is identical to pre-F15 until an Admin creates a second team.

---

## Plugin Framework (`plugins/`)

### Architecture

- **BasePlugin** — abstract base with `plugin_id`, `display_name`, `version`, `capabilities`, `config_schema`
- **VulnerabilityFeedPlugin** — `run()` yields normalized vulnerability dicts
- **ControlsImportPlugin** — `run()` yields normalized control dicts
- **PluginRegistry** — registers, lists, and instantiates plugins by ID
- **Runner** — executes plugins, records `PluginRun` + artifacts, respects schedules

### Built-in Plugins

| Plugin ID | Type | Description |
|-----------|------|-------------|
| `nvd` | VulnerabilityFeed | NVD CVE feed |
| `exploitdb` | VulnerabilityFeed | ExploitDB feed |
| `slack` | Integration | Slack webhook notifications |
| `jira` | Integration | Jira issue sync |
| `cis_controls` | ControlsImport | CIS controls framework |
| `pci_dss_controls` | ControlsImport | PCI-DSS controls framework |
| `stig_controls` | ControlsImport | STIG controls framework |

Custom plugins loaded via `PLUGIN_IMPORT_PATHS` env var.

---

## Infrastructure Modules

### Rate Limiting (`rate_limiter.py`)

Sliding-window rate limiting with pluggable backends:
- **MemoryRateLimitStore** — in-memory deque (thread-safe)
- **RedisRateLimitStore** — atomic Lua script for distributed deployments

Per-endpoint limits configured in `AppConfig` (auth: 5/60s, vuln list: 60/60s, exports: 20/60s, writes: 30/60s, sensitive: 10/60s).

### Live Notifications (`live_notifications.py`)

SSE (Server-Sent Events) real-time push:
- **LiveNotificationHub** — thread-safe pub/sub with per-user queues
- 25s heartbeat, used for dashboard metric updates
- Endpoint: `GET /api/notifications/stream`

### Database (`database.py`)

- **TZDateTime** — custom SQLAlchemy type ensuring UTC timezone-aware datetimes
- **init_database(app)** — creates tables, backfills columns for SQLite dev databases
- Default: SQLite; production: PostgreSQL

### CLI (`cli.py`)

- `flask seed-admin` — create/update admin user
- `flask run-plugins` — execute plugins (with filtering options)
- `flask run-notification-scan` — evaluate and deliver scheduled notifications
- `flask purge-old-data` — apply retention policies (audit logs, plugin runs, report artifacts)

---

## PDF Reports (F17)

Three components work together to produce branded PDFs:

1. **`services/pdf_renderer.py`** — `render_pdf(layout_name, context)` looks up `backend/templates/reports/<layout_name>.html`, renders it with Jinja2, and pipes the HTML through WeasyPrint. Auto-loads the `OrganizationBranding` row when no explicit `branding` key is in the context.
2. **`services/pdf_charts.py`** — Matplotlib helpers for severity donut and SLA bar that emit base64-encoded PNG data URIs (so templates stay self-contained).
3. **`templates/reports/`** — Jinja layouts:
   - `default.html` — parity with the pre-F17 output (vuln table or dashboard summary), branded header rule and footer.
   - `executive_summary.html` — KPI tiles (open / critical open / SLA compliance / new in period), severity donut + SLA bar, full vulnerability appendix on its own page.

### Sync vs. async path

`/api/reports/{vulnerabilities,dashboard}/export?format=pdf&pdf_layout={default,executive_summary}`:

- When `CELERY_ENABLED=false` (default in dev / tests): renders inline and returns `200` with a ready artifact.
- When `CELERY_ENABLED=true`: creates a `pending` `ReportArtifact`, dispatches `uvt.generate_report` with `artifact_id`, returns **`202 Accepted`**. The worker calls `_finalize_pdf_artifact()`, which re-applies `team_scope()` using `artifact.created_by` (no request context), renders, writes the file, and flips status to `ready` (or `failed` with an `error` message ≤ 500 chars).

The frontend polls `GET /api/reports/artifacts/<id>` until `status == "ready"`, then downloads via the signed download URL. `GET /artifacts/<id>/download` returns `409 Conflict` if the artifact is still pending.

CSV and JSON export paths are always synchronous regardless of `CELERY_ENABLED`.
