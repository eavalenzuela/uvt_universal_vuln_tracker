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

24 route modules organized by domain:

| Module | Prefix | Purpose |
|--------|--------|---------|
| `auth_routes.py` | `/api/auth` | Login, refresh, logout, register, OIDC SSO, CSRF token |
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
| `vulnerability_query.py` | — | Query builder (service, no blueprint) |
| `users_crud.py` | `/api/users` | User CRUD, invite, impersonate, toggle active, export |
| `users_tokens.py` | `/api/users` | API token management (personal + admin) |
| `audit_logs.py` | `/api/audit-logs` | Audit log listing |
| `plugins.py` | `/api/plugins` | Plugin listing, run, config, artifact download, import |
| `notification_rules.py` | `/api/notification-rules` | Notification rule CRUD, test-send, delivery logs |
| `notification_delivery.py` | `/api` | Delivery attempt retry/replay |
| `notifications.py` | `/api/notifications` | In-app notification CRUD, read-all |
| `live_notifications.py` | `/api/notifications/stream` | SSE real-time event stream |
| `sla_policy.py` | `/api/sla_policy` | SLA policy get/set |
| `report_exports.py` | `/api/reports` | Vulnerability/dashboard export, risk trends, artifact download |
| `report_templates.py` | `/api/reports/templates` | Report template CRUD |
| `report_schedules.py` | `/api/reports/schedules` | Report schedule CRUD + manual run |
| `dashboard_layout_presets.py` | `/api/dashboard/layout-presets` | Dashboard layout preset CRUD |

Helper: `validation.py` — `ValidationError`, `error_response()`, request parsing utilities.

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
| `reporting_service.py` | Aggregates vulnerability data for reports |

### Models (`models/`)

Organized by bounded context. All use SQLAlchemy ORM with UTC-aware timestamps (`TZDateTime`).

**Auth** (`models/auth.py`):
- `User` — username, email, password_hash, role, token_version
- `ApiToken` — hashed secret, scopes, expiry, usage tracking
- `RefreshToken` — hashed token, expiry, revocation
- `AuditLog` — action, table, record, old/new values (JSON)

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
- `ReportArtifact` — generated report files with checksums

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
