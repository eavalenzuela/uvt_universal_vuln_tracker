# Planned Improvements — v2.23.0 work plan

Ten improvements + five features for this pass. Items 1–5 are the follow-ups
explicitly deferred in the v2.22.0 changelog notes.

## Improvements

1. **Webhook ingest HMAC: sign with the raw secret, not its hash.** The server
   currently verifies HMACs keyed on the stored SHA-256 *hash* of the secret — a
   value an external client never receives (the tests read it out of the DB).
   Real integrations holding only the one-time raw secret can never produce a
   valid signature. New/rotated endpoints now store the secret and verify
   raw-secret-keyed HMACs; pre-existing endpoints keep legacy verification
   until rotated.
2. **SSRF guard for outbound notification deliveries.** Slack / Jira / generic
   webhook delivery URLs are operator-supplied; validate them (scheme, host,
   loopback/private/link-local IP-literal and local-hostname rejection) via a
   new `services/url_guard.py`, with `OUTBOUND_ALLOW_PRIVATE_URLS` opt-out for
   intranet deployments.
3. **Plugin `file_path` confinement.** Feed/controls plugins read arbitrary
   filesystem paths from admin-editable config; confine them to a configurable
   `PLUGIN_DATA_DIR` (empty = legacy unrestricted, so existing installs are
   unaffected until opted in — same gating posture as F3/F15).
4. **Short-lived, marked impersonation tokens.** Impersonation currently mints
   a normal 12-hour JWT indistinguishable from a login token; issue a
   short-lived token (`IMPERSONATION_TOKEN_MINUTES`, default 15) carrying
   `impersonation` / `impersonated_by` claims for traceability.
5. **Replace native `window.confirm` / `window.prompt` with the in-app modal.**
   ~17 call sites still use blocking native dialogs that ignore theming,
   focus-trapping, and reduced-motion work; add `confirmModal()` beside
   `promptModal()` and convert them all.
6. **Webhook ingest honors `RATE_LIMIT_TRUSTED_PROXIES`.** The ingest
   rate-limit key and the delivery-log `client_ip` use raw `remote_addr`,
   bypassing the v2.22.0 trusted-proxy fix behind a reverse proxy; reuse the
   rate limiter's client-IP resolution.
7. **Feed ingest stops dropping CVSS vector / CWE / references.** The
   Vulnerability model has `cvss_vector`, `cvss_version`, `cwe_id`, and
   `references_json`, but `NormalizedVuln` can't carry them, so NVD feed data
   is silently discarded; extend the dataclass, the NVD mapper, and the upsert.
8. **Password validation beyond bare length.** Reject passwords containing the
   username or email local-part and a small worst-passwords denylist —
   length-only checks accept `changeme-changeme`.
9. **Delete dead `backend/middleware.py.txt`.** A tracked scaffold file of
   empty `pass` stubs that misleads readers about where middleware lives.
10. **Docs refresh.** CHANGELOG v2.23.0 entry, README version bump, `dev.env` +
    `docs/DEPLOYMENT.md` coverage for the new env vars, and webhook signing
    documentation.

## New Features

11. **CISA KEV feed plugin + known-exploited flag.** New `vuln-feed-kev`
    plugin maps the KEV catalog; `Vulnerability.known_exploited` +
    `kev_date_added` columns (SQLite backfill), exposed in list/detail JSON,
    filterable via `known_exploited=true`, badged in the UI. Exploited-in-the-
    wild is the highest-signal triage bit a vuln tracker can show.
12. **Watched-vulnerability notifications.** The `notify_on_watched_vuln_update`
    preference and watcher plumbing exist end-to-end, but nothing ever
    notifies watchers; create in-app notifications (+ live events) for
    watchers on update/status/assignment events.
13. **Audit-log CSV export.** `GET /api/audit-logs/export.csv` (Admin,
    filter-aware, rate-limited) + an Export CSV button on the admin logs view
    — compliance reviews need audit trails outside the API.
14. **Remediation metrics.** `Vulnerability.resolved_at` stamped on transition
    into Resolved/Closed (cleared on reopen) + `GET
    /api/reports/remediation-metrics` returning MTTR by severity and open-age
    buckets — the dashboard shows state, not remediation velocity.
15. **Global search covers software components.** Search matches component
    name/ecosystem (team-scoped via product) and the header dropdown gains a
    Components group linking to the owning product — components are the one
    first-class entity search can't find.
