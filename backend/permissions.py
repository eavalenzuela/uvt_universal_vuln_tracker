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

ROLE_SCOPES = {
    ROLE_ADMIN: {
        SCOPE_PRODUCTS_READ,
        SCOPE_PRODUCTS_WRITE,
        SCOPE_VULNS_READ,
        SCOPE_VULNS_WRITE,
        SCOPE_USERS_READ,
        SCOPE_USERS_WRITE,
    },
    ROLE_ANALYST: {
        SCOPE_PRODUCTS_READ,
        SCOPE_PRODUCTS_WRITE,
        SCOPE_VULNS_READ,
        SCOPE_VULNS_WRITE,
    },
    ROLE_VIEWER: {
        SCOPE_PRODUCTS_READ,
        SCOPE_VULNS_READ,
    },
}

PATH_SCOPE_PREFIXES = (
    ("/api/vulns", "vulnerabilities"),
    ("/api/products", "products"),
    ("/api/vulnerabilities", "vulnerabilities"),
    ("/api/product_versions", "vulnerabilities"),
    ("/api/users", "users"),
)


def scope_for_request(path: str, method: str):
    for prefix, resource in PATH_SCOPE_PREFIXES:
        if path.startswith(prefix):
            action = "read" if method in {"GET", "HEAD", "OPTIONS"} else "write"
            return f"{resource}:{action}"
    return None


def role_has_scope(role: str, scope: str) -> bool:
    return scope in ROLE_SCOPES.get(role, set())
