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

ROLE_SCOPES = {
    ROLE_ADMIN: {
        SCOPE_PRODUCTS_READ,
        SCOPE_PRODUCTS_WRITE,
        SCOPE_VULNS_READ,
        SCOPE_VULNS_WRITE,
        SCOPE_USERS_READ,
        SCOPE_USERS_WRITE,
        SCOPE_CONTROLS_READ,
        SCOPE_CONTROLS_WRITE,
        SCOPE_ATTACK_VECTORS_READ,
        SCOPE_ATTACK_VECTORS_WRITE,
        SCOPE_TERMINAL_IMPACTS_READ,
        SCOPE_TERMINAL_IMPACTS_WRITE,
        SCOPE_PLUGINS_READ,
        SCOPE_PLUGINS_WRITE,
        SCOPE_REPORTS_READ,
        SCOPE_REPORTS_WRITE,
    },
    ROLE_ANALYST: {
        SCOPE_PRODUCTS_READ,
        SCOPE_PRODUCTS_WRITE,
        SCOPE_VULNS_READ,
        SCOPE_VULNS_WRITE,
        SCOPE_CONTROLS_READ,
        SCOPE_CONTROLS_WRITE,
        SCOPE_ATTACK_VECTORS_READ,
        SCOPE_ATTACK_VECTORS_WRITE,
        SCOPE_TERMINAL_IMPACTS_READ,
        SCOPE_TERMINAL_IMPACTS_WRITE,
        SCOPE_PLUGINS_READ,
        SCOPE_PLUGINS_WRITE,
        SCOPE_REPORTS_READ,
        SCOPE_REPORTS_WRITE,
    },
    ROLE_VIEWER: {
        SCOPE_PRODUCTS_READ,
        SCOPE_VULNS_READ,
        SCOPE_CONTROLS_READ,
        SCOPE_ATTACK_VECTORS_READ,
        SCOPE_TERMINAL_IMPACTS_READ,
        SCOPE_PLUGINS_READ,
        SCOPE_REPORTS_READ,
    },
}

PATH_SCOPE_PREFIXES = (
    ("/api/vulns", "vulnerabilities"),
    ("/api/products", "products"),
    ("/api/vulnerabilities", "vulnerabilities"),
    ("/api/product_versions", "vulnerabilities"),
    ("/api/users", "users"),
    ("/api/plugins", "plugins"),
    ("/api/controls", "controls"),
    ("/api/attack_vectors", "attack_vectors"),
    ("/api/terminal_impacts", "terminal_impacts"),
    ("/api/reports", "reports"),
)


def scope_for_request(path: str, method: str):
    for prefix, resource in PATH_SCOPE_PREFIXES:
        if path.startswith(prefix):
            action = "read" if method in {"GET", "HEAD", "OPTIONS"} else "write"
            return f"{resource}:{action}"
    return None


def role_has_scope(role: str, scope: str) -> bool:
    return scope in ROLE_SCOPES.get(role, set())
