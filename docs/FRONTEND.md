# Frontend Architecture

High-level documentation for the UVT vanilla JavaScript frontend.

---

## Overview

Single-page application — vanilla JS with ES modules, hash-based routing, no framework or bundler. Dark theme, responsive layout.

---

## Bootstrap

**`index.html`** — HTML shell with zones for header, sidebar, main content, toast, and modal overlays. Loads four CSS files and boots via `src/main.js`.

**`src/main.js`** — Initializes router, renders shell (header + sidebar), manages session, sets up SSE live notification stream (mentions, rule triggers, escalations), periodically refreshes session.

**`src/config.js`** — Reads API base from `window.__UVT_API_BASE__` (default: `""` — same-origin via nginx). Set the global before the app boots when running the SPA against a separate backend (e.g. dev mode without nginx, or the screenshot tool which injects it via Playwright `add_init_script`).

---

## Router (`src/router/`)

| File | Purpose |
|------|---------|
| `router.js` | Hash-based router, listens to `hashchange`, parses dynamic params (`:id`), enforces guards |
| `routes.js` | Route table mapping hashes to views with guards |
| `guards.js` | `requireAuth()` and `requireRole(role)` guard functions |

---

## Pages & Routes

### Public

| Route | View | Description |
|-------|------|-------------|
| `/login` | LoginView | Username/password form, SSO button if OIDC enabled |

### Authenticated (all users)

| Route | View | Description |
|-------|------|-------------|
| `/` | DashboardView | Multi-widget executive summary with configurable layout |
| `/vulnerabilities` | VulnListView | Filtered list with bulk operations, saved presets, export |
| `/vulnerabilities/:id` | VulnDetailView | Full detail: metadata, versions, vectors, impacts, comments, watchers, merge |
| `/products` | ProductsView | Product catalog as cards with create/edit/delete |
| `/products/:id` | ProductDetailView | Product metadata, versions, components per version |
| `/products/component-diff` | ProductComponentDiffView | Side-by-side component comparison between two versions |
| `/products/:id/versions/:pvId/dependency-graph` | ProductDependencyGraphView | Interactive dependency tree with severity coloring |
| `/controls` | ControlsView | Security control catalog with framework filter |
| `/notifications` | NotificationsView | Paginated inbox with mark read/archive actions |
| `/settings` | SettingsView | User preferences: timezone, default vulnerability filter, notification channels (F16) |
| `/admin/api-tokens` | AdminApiTokensView | Personal API token management (create, revoke, copy) |

### Admin Only

| Route | View | Description |
|-------|------|-------------|
| `/admin/users` | AdminUsersView | User list with invite, impersonate, toggle active, export CSV |
| `/admin/logs` | AdminLogsView | Paginated audit logs with action/table filters |
| `/admin/plugins` | AdminPluginsView | Plugin config, enable/disable, run, import from sources |
| `/admin/notification-rules` | AdminNotificationRulesView | Notification rule CRUD, test-send, delivery logs |
| `/admin/notification-delivery` | AdminNotificationDeliveryView | Delivery attempt table with retry/replay |
| `/admin/reports` | AdminReportsView | Report templates and scheduled report management |
| `/admin/teams` | AdminTeamsView | Team CRUD + memberships (F15 Phase 2) |
| `/admin/branding` | AdminBrandingView | PDF report branding: primary color, footer text, logo upload (F17 Slice 3) |

### Catch-all

| Route | View | Description |
|-------|------|-------------|
| `*` | NotFoundView | 404 page |

---

## Page Details

### Dashboard (`/`)

Seven default widgets, all configurable:

| Widget | Content |
|--------|---------|
| Risk Overview | KPI cards by severity/status with trend sparklines |
| Recently Updated | Vulnerabilities changed in last 7 days |
| SLA / Due Soon | Vulns approaching SLA deadlines |
| Top Affected Assets | Products with most vulnerabilities |
| Risk Trends | Line chart over time (day/week/month grouping) |
| Top Risk Products | Highest weighted risk product versions |
| My Work | Vulnerabilities assigned to current user |

Features: drag-to-reorder, toggle visibility, save/load layout presets (local + server), per-widget filters, export summary as CSV/JSON/PDF. Polls every 30 seconds.

### Vulnerability List (`/vulnerabilities`)

Filters: search (title/CVE), status, severity, attack complexity, CIA impact, component ecosystem/name/depth. Cards with expandable details and inline editing. Bulk toolbar for batch severity/status/assignee/SLA updates. Saved filter presets, pagination, sortable, export.

### Vulnerability Detail (`/vulnerabilities/:id`)

Sections: metadata editing, affected product versions, attack vectors (per version), terminal impacts, threaded comments, watchers, activity/history log, merge candidates with merge action.

### Products (`/products`, `/products/:id`)

Card-based catalog. Detail page shows versions table, components per version with SBOM data, linked vulnerabilities.

### Component Diff (`/products/component-diff`)

Select two product versions, compare added/removed/modified components and dependencies.

### Dependency Graph (`/products/:id/versions/:pvId/dependency-graph`)

Interactive tree visualization with severity-colored nodes, zoom/pan, click-to-highlight paths, depth tracking.

### Admin: Users (`/admin/users`)

Stats cards (total/active/pending/disabled), search + filter, invite modal, impersonate with reason, toggle active, export CSV.

### Admin: Notification Rules (`/admin/notification-rules`)

Per-rule: adapter (slack/email/webhook/jira), severity threshold, event triggers, frequency/escalation cadence, channels/recipients, product scope, test-send.

### Admin: Reports (`/admin/reports`)

Templates (type, format, delivery channel, visibility, recipients) and schedules (frequency, timezone, template link, manual run).

### Admin: Teams (`/admin/teams`, F15 Phase 2)

Create / rename / delete teams; add or remove members. Combined with the top-nav team selector (visible to multi-team users and Admins), the active team is persisted in `localStorage` and attached to every API call as `X-UVT-Team-Id`.

### Admin: PDF Branding (`/admin/branding`, F17 Slice 3)

Theme card (primary-color picker + hex input, footer text) and logo card (upload PNG/SVG/JPEG, ≤ 1 MB, with remove). Applies to every rendered PDF (default and executive_summary layouts).

### Settings (`/settings`, F16)

Per-user preferences: timezone, default vulnerability filter, notification channels.

---

## State Management (`src/state/`)

| File | Purpose |
|------|---------|
| `store.js` | Centralized reactive store with pub/sub. Holds session, liveNotifications (30-item ring), notifications (50-item list + pagination) |
| `session.js` | Persists/loads user session from `localStorage` (`uvt_session_v1`) |
| `permissions.js` | Helpers: `isAuthed()`, `role()`, `canWrite()`, `isAdmin()` |

---

## API Adapters (`src/api/`)

| File | Domain |
|------|--------|
| `client.js` | Core `apiFetch()` — cookie auth, CSRF, retry (3x on 502/503/504), 15s timeout, abort support |
| `errors.js` | `ApiError` class |
| `authRetry.js` | Token refresh with mutex, auto-logout on failure |
| `auth.js` | Login, refresh, logout, register, OIDC providers, `/me` |
| `vulnerabilities.js` | CRUD, bulk, versions, attack vectors, terminal impacts, comments, watchers, merge, activity |
| `products.js` | Product + version CRUD |
| `components.js` | Component listing, SBOM import, version diff, dependency graph |
| `controls.js` | Control CRUD |
| `notifications.js` | List, mark read/unread, mark all read, delete |
| `notificationRules.js` | Rule CRUD, test-send, delivery logs |
| `notificationDelivery.js` | Delivery attempts, retry, replay |
| `users.js` | User CRUD, invite, impersonate, toggle active, export, API tokens, active user list |
| `auditLogs.js` | Audit log listing with filters |
| `plugins.js` | Plugin listing, config, import sources, validate, register |
| `reports.js` | Export vulns/dashboard (CSV/JSON/PDF), `waitForReportArtifact()` polling helper, templates, schedules, dashboard summary, risk trends |
| `dashboardLayoutPresets.js` | Layout preset CRUD |
| `teams.js` | Team CRUD + member management (F15) |
| `branding.js` | PDF branding GET/PUT + logo upload/delete (F17 Slice 3) |
| `userPreferences.js` | Per-user preferences GET/PATCH (F16) |
| `search.js` | Cross-entity search (F9) |

---

## UI Primitives (`src/ui/`)

| File | Purpose |
|------|---------|
| `dom/el.js` | Lightweight DOM builder: `el(tag, attrs, ...children)` |
| `components/modal.js` | `promptModal()` — centered dialog with input, confirm/cancel, escape key |
| `components/toast.js` | `toast()` — temporary notification (2.6s auto-dismiss) |
| `components/loading.js` | `withLoading()` — disables button during async operations |
| `primitives/filters.js` | `createFilterRow()` — flex row with controls and actions |
| `primitives/table.js` | `createTableHeader()`, `createEmptyState()` |

---

## Layout (`src/ui/layout/`)

| File | Purpose |
|------|---------|
| `shell.js` | Renders header + sidebar together |
| `header.js` | Brand, notification dropdown (5 latest, mark read, keyboard nav), user display, logout |
| `sidebar.js` | Navigation links (all users + admin section), live notification inbox (last 5 SSE events) |

---

## Styling (`assets/styles/`)

Four CSS files: `base.css` (reset, dark theme vars), `layout.css` (grid, responsive), `components.css` (buttons, inputs, cards, badges), `pages.css` (page-specific, tables, modals).

Theme: dark background (#0b0d12), light text (#e6e8ee), blue accent (#2563eb).

---

## Key Patterns

- **Cookie auth** — `credentials: "include"` on all API calls, CSRF token from cookie
- **Lazy views** — dynamic imports per route, no global bundle
- **Reactive state** — pub/sub store drives header/sidebar updates
- **SSE notifications** — `EventSource` for real-time dashboard and notification updates
- **Closure-free widgets** — dashboard widgets receive `ctx = { user, writable }` as parameter
- **Re-export shims** — `views/` re-exports from `features/` to avoid router changes after module splits
- **Active team header** — when a non-Default team is selected in the top nav, `apiFetch()` reads `session.currentTeamId` and attaches it as `X-UVT-Team-Id`. The backend resolves it in `auth._populate_current_team` before scope checks.
- **Async PDF polling** — for large PDF exports, the backend may return `202 Accepted` with a pending artifact. Use `waitForReportArtifact(artifactId)` from `api/reports.js` to poll `/api/reports/artifacts/<id>` until status is `ready` (or `failed`), then trigger the file download. The existing CSV/JSON paths stay synchronous.
