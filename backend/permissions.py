"""Roles, scopes, and the route→scope map that API tokens are checked against.

Scope resolution used to be a ten-entry path-prefix list that returned ``None``
for anything unmatched — and ``None`` meant "no scope required", so an API
token minted with ``["products:read"]`` could still reach every route that
wasn't on the list: teams, webhooks, audit logs, search, scanner imports.
Those routes are decorated with ``@admin_required``, so the token inherited its
*owner's* role and could create teams and webhook endpoints.

The mapping is now explicit and closed:

* Every registered route resolves to a scope via :data:`ROUTE_SCOPES`, matched
  longest-prefix-first so specific rules beat general ones.
* Anything unmatched resolves to :data:`SCOPE_UNMAPPED`, which no role and no
  token holds — an unmapped route is denied, not waved through.
* :func:`audit_route_scopes` runs at boot and logs any route without an
  explicit mapping, so new endpoints are caught in development rather than
  discovered in production.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

ROLE_ADMIN = "Admin"
ROLE_ANALYST = "Analyst"
ROLE_VIEWER = "Viewer"

ALL_ROLES = {ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER}

SCOPE_PRODUCTS_READ = "products:read"
SCOPE_PRODUCTS_WRITE = "products:write"
SCOPE_VULNS_READ = "vulnerabilities:read"
SCOPE_VULNS_WRITE = "vulnerabilities:write"
SCOPE_USERS_READ = "users:read"
SCOPE_USERS_WRITE = "users:write"
SCOPE_CONTROLS_READ = "controls:read"
SCOPE_CONTROLS_WRITE = "controls:write"
SCOPE_ATTACK_VECTORS_READ = "attack_vectors:read"
SCOPE_ATTACK_VECTORS_WRITE = "attack_vectors:write"
SCOPE_TERMINAL_IMPACTS_READ = "terminal_impacts:read"
SCOPE_TERMINAL_IMPACTS_WRITE = "terminal_impacts:write"
SCOPE_PLUGINS_READ = "plugins:read"
SCOPE_PLUGINS_WRITE = "plugins:write"
SCOPE_REPORTS_READ = "reports:read"
SCOPE_REPORTS_WRITE = "reports:write"

# Feature areas that previously had no scope at all.
SCOPE_TEAMS_READ = "teams:read"
SCOPE_TEAMS_WRITE = "teams:write"
SCOPE_NOTIFICATIONS_READ = "notifications:read"
SCOPE_NOTIFICATIONS_WRITE = "notifications:write"
SCOPE_WEBHOOKS_READ = "webhooks:read"
SCOPE_WEBHOOKS_WRITE = "webhooks:write"
SCOPE_AUDIT_READ = "audit:read"
SCOPE_SETTINGS_READ = "settings:read"
SCOPE_SETTINGS_WRITE = "settings:write"

# Held by every authenticated principal. Covers "who am I / my own stuff"
# routes — preferences, own teams, own API tokens — which must not require the
# organisation-wide users:read that only Admins hold.
SCOPE_SELF = "self"

# Sentinel for routes with no explicit mapping. Deliberately in no role's set
# and impossible to grant to a token, so an unmapped route fails closed.
SCOPE_UNMAPPED = "__unmapped__"

# Scopes a user may attach to an API token they create. SCOPE_SELF is implicit
# and not grantable; SCOPE_UNMAPPED is not a real scope.
GRANTABLE_SCOPES = frozenset({
    SCOPE_PRODUCTS_READ, SCOPE_PRODUCTS_WRITE,
    SCOPE_VULNS_READ, SCOPE_VULNS_WRITE,
    SCOPE_USERS_READ, SCOPE_USERS_WRITE,
    SCOPE_CONTROLS_READ, SCOPE_CONTROLS_WRITE,
    SCOPE_ATTACK_VECTORS_READ, SCOPE_ATTACK_VECTORS_WRITE,
    SCOPE_TERMINAL_IMPACTS_READ, SCOPE_TERMINAL_IMPACTS_WRITE,
    SCOPE_PLUGINS_READ, SCOPE_PLUGINS_WRITE,
    SCOPE_REPORTS_READ, SCOPE_REPORTS_WRITE,
    SCOPE_TEAMS_READ, SCOPE_TEAMS_WRITE,
    SCOPE_NOTIFICATIONS_READ, SCOPE_NOTIFICATIONS_WRITE,
    SCOPE_WEBHOOKS_READ, SCOPE_WEBHOOKS_WRITE,
    SCOPE_AUDIT_READ,
    SCOPE_SETTINGS_READ, SCOPE_SETTINGS_WRITE,
})

_READ_EVERYTHING = {
    SCOPE_PRODUCTS_READ, SCOPE_VULNS_READ, SCOPE_CONTROLS_READ,
    SCOPE_ATTACK_VECTORS_READ, SCOPE_TERMINAL_IMPACTS_READ,
    SCOPE_PLUGINS_READ, SCOPE_REPORTS_READ, SCOPE_TEAMS_READ,
    SCOPE_NOTIFICATIONS_READ, SCOPE_SETTINGS_READ, SCOPE_SELF,
}

ROLE_SCOPES = {
    ROLE_ADMIN: GRANTABLE_SCOPES | {SCOPE_SELF},
    ROLE_ANALYST: _READ_EVERYTHING | {
        SCOPE_PRODUCTS_WRITE, SCOPE_VULNS_WRITE, SCOPE_CONTROLS_WRITE,
        SCOPE_ATTACK_VECTORS_WRITE, SCOPE_TERMINAL_IMPACTS_WRITE,
        SCOPE_PLUGINS_WRITE, SCOPE_REPORTS_WRITE,
        SCOPE_NOTIFICATIONS_WRITE,
    },
    ROLE_VIEWER: set(_READ_EVERYTHING),
}


def _rw(read_scope: str, write_scope: str) -> tuple[str, str]:
    return (read_scope, write_scope)


# Path prefix -> (read scope, write scope). Matched longest-first, so
# "/api/users/me" wins over "/api/users".
ROUTE_SCOPES: dict[str, tuple[str, str]] = {
    # --- self-service: every authenticated principal ------------------------
    "/api/me": _rw(SCOPE_SELF, SCOPE_SELF),
    "/api/users/me": _rw(SCOPE_SELF, SCOPE_SELF),
    "/api/auth": _rw(SCOPE_SELF, SCOPE_SELF),
    "/api/tasks": _rw(SCOPE_SELF, SCOPE_SELF),

    # --- core domain --------------------------------------------------------
    "/api/vulnerabilities": _rw(SCOPE_VULNS_READ, SCOPE_VULNS_WRITE),
    "/api/vulns": _rw(SCOPE_VULNS_READ, SCOPE_VULNS_WRITE),
    "/api/product_versions": _rw(SCOPE_PRODUCTS_READ, SCOPE_PRODUCTS_WRITE),
    "/api/products": _rw(SCOPE_PRODUCTS_READ, SCOPE_PRODUCTS_WRITE),
    "/api/components": _rw(SCOPE_PRODUCTS_READ, SCOPE_PRODUCTS_WRITE),
    "/api/controls": _rw(SCOPE_CONTROLS_READ, SCOPE_CONTROLS_WRITE),
    "/api/attack_vectors": _rw(SCOPE_ATTACK_VECTORS_READ, SCOPE_ATTACK_VECTORS_WRITE),
    "/api/terminal_impacts": _rw(SCOPE_TERMINAL_IMPACTS_READ, SCOPE_TERMINAL_IMPACTS_WRITE),

    # --- search spans vulnerabilities, products and comments, so it needs the
    # --- broadest read of the three, not the weakest.
    "/api/search": _rw(SCOPE_VULNS_READ, SCOPE_VULNS_WRITE),

    # --- ingest creates vulnerabilities -------------------------------------
    "/api/imports": _rw(SCOPE_VULNS_READ, SCOPE_VULNS_WRITE),
    "/api/scanner-imports": _rw(SCOPE_VULNS_READ, SCOPE_VULNS_WRITE),

    # --- users / directory --------------------------------------------------
    "/api/users/active": _rw(SCOPE_SELF, SCOPE_USERS_WRITE),
    "/api/users": _rw(SCOPE_USERS_READ, SCOPE_USERS_WRITE),

    # --- previously unmapped ------------------------------------------------
    "/api/teams": _rw(SCOPE_TEAMS_READ, SCOPE_TEAMS_WRITE),
    "/api/webhooks": _rw(SCOPE_WEBHOOKS_READ, SCOPE_WEBHOOKS_WRITE),
    "/api/audit-logs": _rw(SCOPE_AUDIT_READ, SCOPE_AUDIT_READ),
    "/api/notifications": _rw(SCOPE_NOTIFICATIONS_READ, SCOPE_NOTIFICATIONS_WRITE),
    "/api/notification-rules": _rw(SCOPE_NOTIFICATIONS_READ, SCOPE_NOTIFICATIONS_WRITE),
    "/api/notification-delivery-logs": _rw(SCOPE_NOTIFICATIONS_READ, SCOPE_NOTIFICATIONS_WRITE),
    "/api/notification-delivery-attempts": _rw(SCOPE_NOTIFICATIONS_READ, SCOPE_NOTIFICATIONS_WRITE),
    "/api/plugins": _rw(SCOPE_PLUGINS_READ, SCOPE_PLUGINS_WRITE),
    "/api/reports": _rw(SCOPE_REPORTS_READ, SCOPE_REPORTS_WRITE),
    "/api/dashboard": _rw(SCOPE_VULNS_READ, SCOPE_SELF),
    "/api/sla_policy": _rw(SCOPE_SETTINGS_READ, SCOPE_SETTINGS_WRITE),
    "/api/admin/branding": _rw(SCOPE_SETTINGS_READ, SCOPE_SETTINGS_WRITE),
}

# Sorted longest-first once at import time so lookup is a simple scan.
_SORTED_ROUTES: list[tuple[str, tuple[str, str]]] = sorted(
    ROUTE_SCOPES.items(), key=lambda kv: len(kv[0]), reverse=True
)

# Endpoints that authenticate by their own mechanism, or that exist precisely
# to be reached without a session. Listed exactly rather than by prefix so
# adding an endpoint under /api/auth does not make it public by accident —
# /api/auth/logout_all and the MFA management routes are *not* here.
UNAUTHENTICATED_PATHS = (
    "/api/health",
    "/api/openapi.json",
    "/api/docs",
    "/api/webhooks/ingest/",       # HMAC-signed, no user principal
    # Pre-session auth flows.
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/refresh",           # bearer is the refresh token in the body
    "/api/auth/logout",            # must succeed even with an expired session
    "/api/auth/csrf",
    "/api/auth/providers",
    "/api/auth/oidc/",
    "/api/auth/forgot-password",
    "/api/auth/reset-password",
    "/api/auth/verify-email",
    "/api/auth/resend-verification",
    "/api/auth/mfa/verify",        # completes login; challenge token is the credential
)

_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def scope_for_request(path: str, method: str) -> str | None:
    """Resolve the scope a request requires.

    Returns ``None`` only for endpoints that are intentionally unauthenticated.
    Every other path resolves to a real scope, or to :data:`SCOPE_UNMAPPED`
    when no rule matches — which denies.
    """
    for prefix in UNAUTHENTICATED_PATHS:
        if path.startswith(prefix):
            return None

    if not path.startswith("/api/"):
        return None

    for prefix, (read_scope, write_scope) in _SORTED_ROUTES:
        if path == prefix or path.startswith(prefix + "/") or path.startswith(prefix + "?"):
            return read_scope if method in _READ_METHODS else write_scope

    return SCOPE_UNMAPPED


def role_has_scope(role: str, scope: str) -> bool:
    if scope == SCOPE_UNMAPPED:
        return False
    return scope in ROLE_SCOPES.get(role, set())


def token_has_scope(token_scopes, scope: str) -> bool:
    """Whether an API token may exercise ``scope``.

    ``SCOPE_SELF`` is implicit: a token always acts as its owner, so it can
    read that owner's own profile and preferences regardless of the scope list.
    """
    if scope == SCOPE_UNMAPPED:
        return False
    if scope == SCOPE_SELF:
        return True
    return scope in set(token_scopes or ())


def audit_route_scopes(app) -> list[str]:
    """Log every registered API route that has no explicit scope mapping.

    Called at boot. New endpoints therefore announce themselves the first time
    the app starts, instead of silently defaulting to something permissive.
    """
    unmapped: list[str] = []
    for rule in app.url_map.iter_rules():
        path = str(rule.rule)
        if not path.startswith("/api/"):
            continue
        if any(path.startswith(p) for p in UNAUTHENTICATED_PATHS):
            continue
        methods = rule.methods - {"HEAD", "OPTIONS"}
        for method in methods:
            if scope_for_request(path, method) == SCOPE_UNMAPPED:
                unmapped.append(f"{method} {path}")
                break

    if unmapped:
        logger.error(
            "%d API route(s) have no scope mapping and will be denied. "
            "Add them to ROUTE_SCOPES in backend/permissions.py:", len(unmapped),
        )
        for item in sorted(unmapped):
            logger.error("  unmapped route: %s", item)
    return sorted(unmapped)
