# F15 — Team / Project-Level Access Control — Implementation Plan

## 1. Data model decision

**Recommended: option (a) Team-as-scope.** UVT's natural grouping is the product (and all of its descendants: versions, components, dependencies, vulnerabilities-via-mapping). The resource count scales with products, not vulns, so putting the scope on `Product` keeps the row that owns the FK small and the cascade natural. Per-product ACL (b) would force a join through `product_owners` on every query — more write paths to get wrong and more index pressure. "Owner groups" (c) is team-as-scope with one extra indirection that we don't currently need (no third-party group source yet). Keep `ProductOwner` as it is today (direct individual assignees, used for notifications and watching) — it's orthogonal to the team scope and shouldn't be collapsed into it.

## 2. Schema changes

New tables and columns (SQLAlchemy DDL expressed in Postgres terms — mirror with TZDateTime like the rest of `backend/models/`):

```sql
CREATE TABLE teams (
  id           SERIAL PRIMARY KEY,
  name         VARCHAR(120) NOT NULL,
  slug         VARCHAR(64)  NOT NULL UNIQUE,
  description  TEXT,
  is_default   BOOLEAN NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ix_teams_single_default ON teams ((is_default)) WHERE is_default;

CREATE TABLE user_teams (
  id            SERIAL PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  team_id       INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  role_in_team  VARCHAR(20),             -- nullable now, space for per-team role later
  is_default    BOOLEAN NOT NULL DEFAULT FALSE,  -- user's "active team on login"
  joined_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT unique_user_team UNIQUE (user_id, team_id)
);
CREATE UNIQUE INDEX ix_user_teams_one_default ON user_teams (user_id) WHERE is_default;

ALTER TABLE products ADD COLUMN team_id INTEGER
  REFERENCES teams(id) ON DELETE RESTRICT;
CREATE INDEX ix_products_team_id ON products(team_id);

ALTER TABLE vulnerabilities ADD COLUMN team_id INTEGER
  REFERENCES teams(id) ON DELETE SET NULL;
CREATE INDEX ix_vulnerabilities_team_id ON vulnerabilities(team_id);

ALTER TABLE notification_rules     ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL;
ALTER TABLE webhook_endpoints      ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL;
ALTER TABLE saved_vulnerability_filters  ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL;
ALTER TABLE dashboard_layout_presets     ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL;
ALTER TABLE report_templates       ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL;
ALTER TABLE report_schedules       ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL;
ALTER TABLE report_artifacts       ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL;
ALTER TABLE plugin_runs            ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL;
ALTER TABLE audit_logs             ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL;
```

**Derivation vs. denormalization for `Vulnerability.team_id`**: vulnerabilities can exist without any product attachment (ingest, CVE enrichment) so a pure derivation via `VulnerabilityComponent → SoftwareComponent → ProductVersion → Product` is not always possible. Store `team_id` on `Vulnerability` directly and define the rule:

- If the vuln is created in the context of a product, set `team_id = product.team_id` at creation.
- If the vuln is ingested unattached, set `team_id = NULL` → treated as **shared/global pool** visible to every authenticated user with `vulnerabilities:read`. Rationale: CVE feeds and NVD entries are public information; pretending they're team-private would break intel reuse. Once a vuln is linked to a product, if `team_id` is still NULL we upgrade it on the first link to the owning product's team. If it's later linked to a product in a different team, see §6.

`VulnerabilityComment`, `VulnerabilityWatcher`, `VulnerabilityVersion`, `VulnerabilityComponent`, `VulnerabilityAttackVector`, `VulnerabilityTerminalImpact`, `VulnerabilitySource`: visibility is inherited via their parent `Vulnerability.team_id` — no column needed.

`SoftwareComponent` and `ComponentDependency`: inherit from `ProductVersion.product.team_id` via join; no column needed.

`Notification`: already user-scoped (`user_id`). Enforcement is "user only sees own notifications" — no extra column needed. But `NotificationDeliveryLog` joins to `NotificationRule.team_id` for visibility.

## 3. Retrofit path — the critical risk

Every query site that currently returns rows for **any** authenticated user must get `.filter(team_scope(...))` applied. **Shared helper signature**:

```python
# backend/services/team_scope.py
def team_scope(query, model, user, *, allow_null_team: bool = False) -> Query:
    """Add a WHERE clause restricting `query` to rows whose team_id is in the
    user's memberships. Admins bypass. When allow_null_team is True, rows with
    team_id IS NULL are also included (used for shared-pool vulnerabilities)."""
```

Plus a `team_scope_product_ids(user)` helper that returns a subquery of `product_id`s, for joining on models whose scope is derived (components, product_versions, comments).

**Exhaustive enumeration of list/read query sites to patch** (file:line):

| Resource | File : line | Model filter |
|---|---|---|
| Products list | `backend/services/product_service.py:31` | `Product.team_id` |
| Product get / patch / delete | `backend/api/products.py:139,172,227` | `Product.team_id` |
| Product versions list | `backend/api/products.py:261` | via `Product` join |
| Product version create/patch | `backend/api/products.py:296,361` | via `Product` |
| Product version list (flat) | `backend/api/vuln_crud.py:84` | via `Product` join |
| Vulnerabilities list | `backend/api/vuln_crud.py:158` | `Vulnerability.team_id` (include NULL) |
| Vuln detail / history / activity / merge-candidates / merge / delete | `backend/api/vuln_crud.py:485,608,665,747,837` | `Vulnerability.team_id` |
| Vuln comments list / mutate | `backend/api/vuln_comments.py:26,65,140,218` | via parent vuln |
| Vuln versions mutate | `backend/api/vuln_versions.py:16,94,213` | via parent vuln and product |
| Vuln bulk ops | `backend/api/vuln_bulk.py:35,125,265,329,368,444` | via parent vuln |
| Vuln watchers | `backend/api/vuln_bulk.py:329,368,444` | via parent vuln |
| Attack-vector mappings on a vuln | `backend/api/attack_vectors.py:220,255,315` | via parent vuln |
| Terminal-impact mappings on a vuln | `backend/api/terminal_impacts.py:238,274,353` | via parent vuln |
| Components list / compare / graph | `backend/api/components.py:16,153,200` | via `product_version→product` |
| Notification rules list / crud | `backend/api/notification_rules.py:21,76,188,344,387` | `NotificationRule.team_id` |
| Notification delivery logs / attempts | `backend/api/notification_rules.py:458`, `backend/api/notification_delivery.py:69` | via `rule.team_id` |
| Notifications list (per-user) | `backend/api/notifications.py:33` | user-scoped; no change |
| Plugin runs / artifacts | `backend/api/plugins.py:329,482,520` | `PluginRun.team_id` |
| Plugin configs | `backend/api/plugins.py:179` | admin-only; no change (keep global) |
| Webhook endpoints & deliveries | `backend/api/webhooks.py:87,164,191` | `WebhookEndpoint.team_id` |
| Saved filters | `backend/api/vulnerability_filters.py:34,46` | owner OR `team_id IN user_teams` |
| Dashboard layout presets | `backend/api/dashboard_layout_presets.py:34,46` | owner OR team |
| Report templates | `backend/api/report_templates.py:48`, `backend/api/report_exports.py:452` | owner OR team |
| Report schedules | `backend/api/report_schedules.py:189` | team_id |
| Report artifacts | `backend/api/report_exports.py:629,679` | team_id |
| Report exports (vuln/dashboard/trends) | `backend/api/report_exports.py:469,555,706,764` | via vuln query + team scope |
| Global search | `backend/api/search.py:90,104,116` | scope each of three queries |
| Audit logs list | `backend/api/audit_logs.py:75` | Admin-only today; add optional `team_id` filter surface |
| SBOM ingest target lookup | `backend/api/components.py:83` | caller must have team access to the product version |

**Test pattern (one parametrized pytest module)**: `backend/tests/test_team_isolation.py`. For each resource above, seed two teams with one product each and one vuln each, create a user who is a member of team A only, assert: (i) GET list returns only team-A rows, (ii) GET detail on a team-B id returns 404 (not 403, to avoid existence oracle), (iii) write endpoints against team-B id return 404, (iv) Admin sees both. Run it with pytest parametrize over the table above so adding a new resource forces a row.

## 4. Admin override

**Admin bypasses `team_scope` entirely.** A user with `role == "Admin"` sees all teams' data; this keeps incident response simple and matches existing "Admin" semantics. No "view-as-team X" mode in v1 — that's a filter, the UI can pass `?team_id=N` for admins.

**Audit integrity**: every `record_audit()` call must stamp a `team_id`. Source it from:
1. the entity being mutated (e.g. editing a product → `product.team_id`), else
2. `request.current_team_id` (the active team from the session header, see §9), else
3. NULL for genuinely cross-cutting actions (login, user-admin).

Add `team_id` to `AuditLog` and to the serialized audit payload so admins investigating cross-team events see the context line. `backend/services/audit.py:record_audit` needs a `team_id=` kwarg.

## 5. Write-path semantics

- **Product creation (`POST /api/products`)**: body accepts `team_id`; if absent, use `request.current_team_id`; if Admin and no active team, error 400 "team_id required". Reject `team_id`s the caller is not a member of (unless Admin).
- **Vulnerability creation via UI (`POST /api/vulnerabilities`)**: if `product_version_id` provided → `team_id = product_version.product.team_id`; else inherit `request.current_team_id`. Creating an unattached vuln with no active team is disallowed (forces a choice; avoids accidental global pollution).
- **SBOM ingest (`POST /api/product_versions/{id}/sbom`)**: correlated vulns created by `sbom_ingest.py` get `team_id = product_version.product.team_id`. Existing shared-pool vulns that get linked stay `team_id=NULL` (shared) — see §6.
- **CVE enrichment (`backend/services/cve_enrichment.py`)**: creates/updates pure-CVE rows without a product context → `team_id = NULL` (shared pool). If enrichment happens as part of handling a specific product vuln, the calling site is responsible for stamping the team.
- **Plugin runs (`backend/plugins/builtins.py`, `backend/services/vuln_ingest.py`)**: extend `PluginConfig` with an optional `team_id` column. On run: `PluginRun.team_id = config.team_id`; vulns created during the run get `team_id = config.team_id` if set, else NULL (shared). This lets an admin say "the Jira-import plugin only produces vulns in team X" or leave it unset for global CVE feeds like NVD.
- **Webhook ingest (`backend/api/webhooks.py:229`)**: `WebhookEndpoint.team_id` is the authoritative stamp. If `product_version_id` is also set, the two must agree (validation at endpoint-create time).

## 6. Cross-team behaviors (shared vulns)

**One vuln record, shared across teams, is the right call.** A single Log4j CVE should not be duplicated — that breaks merge, breaks the "have we seen this?" query, and scales poorly.

- A vuln's `team_id` is the team that "owns" it; `NULL` means "shared pool, visible to all".
- The moment a shared vuln (`team_id IS NULL`) is linked to a product, it stays shared — adding a product linkage does **not** demote a shared vuln to a single team. Alternative rule (own-on-first-link) is tempting but wrong: as soon as team B also finds they're affected, you'd have to re-promote to shared, thrash the audit log, and possibly leak the first team's triage comments.
- Comments, status, and merge on a shared vuln are globally visible and editable by any user with `vulnerabilities:write`. This is acceptable because all members of an org share the CVE intelligence view; per-team private triage on a shared CVE is a v2 concern (add `VulnerabilityTeamView` rows if needed later).
- Merge semantics: a cross-team merge of two shared vulns is unchanged. Merging a team-owned vuln into a shared one is allowed; merging across two different team-owned vulns requires Admin.
- Close/resolve on a shared vuln: anyone with write scope can close it; reopening rules unchanged.

## 7. Notification rules across teams

Rules become team-scoped. `NotificationRule.team_id` required (not null after migration for new rules; nullable only for legacy migration, then backfilled). A rule fires only for vulnerabilities in its team, with shared-pool vulns (`team_id IS NULL`) matched by any team's rule **only if** the rule opts in via a `include_shared` flag (new boolean on `NotificationRule`, default true for backward compat).

A rule's creator must be a member of the rule's team. Admins can create rules for any team. `backend/services/notification_rules.py`'s dispatch loop must filter checkpoints and vuln-rule pairing by team_id.

## 8. Migration plan

Single Alembic revision, forward-only in spirit (reverse is destructive — call this out in the revision docstring):

1. Create `teams`, `user_teams`.
2. Insert one row `teams (name='Default', slug='default', is_default=true)`.
3. Add `team_id` columns **nullable** everywhere listed in §2.
4. Data migration: `UPDATE products SET team_id = <default>`. `UPDATE vulnerabilities SET team_id = <product's team>` when at least one product-linked version exists, else leave NULL (shared). `UPDATE notification_rules, webhook_endpoints, plugin_runs, report_schedules, report_artifacts, saved_vulnerability_filters, dashboard_layout_presets, report_templates, audit_logs SET team_id = <default>`.
5. Insert a `user_teams` row for every existing `users.id` pointing at the Default team with `is_default=true`.
6. Make `products.team_id` `NOT NULL` (other tables stay nullable by design — NULL=shared).

This is irreversible once enforcement is on; a downgrade would have to drop the filtering without dropping the columns.

## 9. Frontend changes

Additions (no detailed UI design):

- `frontend/src/state/store.js`: add `session.teams: [{id, slug, name}]` and `session.currentTeamId`; persist active team in `session.js`.
- New header `X-UVT-Team-Id` sent on every API request when current team is set; backend reads this into `request.current_team_id` in `auth.py:enforce_scopes` after authentication.
- Team selector component in the top-nav for users in >1 team.
- `/teams` admin route (Admin-only): list / create / edit / archive teams, manage memberships. Add `requireRole("Admin")` in `frontend/src/router/guards.js`.
- Surface `team_id` in product create form, in product list filter, and in the vulnerabilities filter bar (`frontend/src/features/vulnerabilities/`).
- Show the owning team on a product detail and on a vulnerability detail (chip).

## 10. Rollout strategy

**Two-phase, no feature flag.**

- Phase 1 (one release): ship all schema changes and the migration above. Every user lands in the Default team; every product/rule/webhook/etc. is stamped Default. `team_scope(...)` is merged into the codebase but **permits all rows for which the user is a member of the owning team** — since everyone is in Default, behavior is identical to today.
- Phase 2 (next release): ship the team admin UI; once an admin creates a second team and moves products into it, enforcement is naturally live because the filter is already there. No flag flip needed; enforcement is load-bearing from day one.

Rationale against a feature flag: the filter is the correctness contract. A flag adds a "disabled = leak" failure mode. The Default-team-only posture in Phase 1 is the flag, done in data.

## 11. Non-goals for v1

Explicitly out of scope:
- Per-vulnerability ACLs (row-level grants).
- Team hierarchies, parent/child teams, or inherited visibility.
- OIDC group → team mapping (belongs with OIDC work in `backend/services/oidc_mapping.py`; separate feature).
- Cross-team notifications for shared vulns beyond the single `include_shared` flag.
- Per-team role overrides (`user_teams.role_in_team` is reserved but not honored — global `User.role` still governs what actions a user can perform; team membership only governs visibility).
- Team-private comments / partial vuln visibility within a shared vuln.
- Quota / billing per team.
