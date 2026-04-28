"""Centralized configuration with validation.

All environment variables are read here and exposed as typed fields on
``AppConfig``.  Call ``load_config()`` at boot to get a validated instance,
then push values into ``app.config`` via ``apply_config(app, cfg)``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def _str(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _cookie_samesite(default: str = "Lax") -> str:
    raw = os.getenv("AUTH_COOKIE_SAMESITE", default).strip().lower()
    allowed = {"lax": "Lax", "strict": "Strict", "none": "None"}
    return allowed.get(raw, default)


def _parse_cors_origins() -> list[str]:
    default_origins = [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:5000",
        "http://localhost:5000",
    ]
    raw = os.getenv("CORS_ALLOWED_ORIGINS")
    if raw is None:
        return default_origins

    parsed_origins: list[str] = []
    invalid_origins: list[str] = []

    for item in raw.split(","):
        origin = item.strip()
        if not origin:
            continue
        p = urlparse(origin)
        if (
            p.scheme not in ("http", "https")
            or not p.netloc
            or p.path not in ("", "/")
            or p.params
            or p.query
            or p.fragment
        ):
            invalid_origins.append(origin)
            continue
        parsed_origins.append(f"{p.scheme}://{p.netloc}")

    if invalid_origins:
        raise ValueError(
            "Invalid CORS_ALLOWED_ORIGINS value(s): "
            f"{', '.join(invalid_origins)}. "
            "Expected a comma-separated list of origin URLs like http://localhost:5173"
        )

    if not parsed_origins:
        import logging
        logging.warning(
            "CORS_ALLOWED_ORIGINS is set but empty; falling back to local development defaults."
        )
        return default_origins

    return parsed_origins


def _parse_plugin_paths() -> list[str]:
    return [
        p.strip()
        for p in os.getenv("PLUGIN_IMPORT_PATHS", "").split(",")
        if p.strip()
    ]


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------

@dataclass
class AppConfig:
    """Typed, validated application configuration."""

    # Runtime environment
    runtime_env: str = ""

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # Secrets
    secret_key: str = "dev-secret"
    jwt_secret: str = "dev-jwt-secret"

    # Auth
    refresh_token_lifetime_days: int = 30
    allow_public_registration: bool = False
    auth_cookie_secure: bool = False
    auth_cookie_samesite: str = "Lax"
    auth_cookie_domain: str | None = None

    # OIDC / SSO
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_url: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_groups_claim: str = "groups"
    oidc_default_role: str = "Viewer"
    oidc_role_mapping: str = ""

    # CORS
    cors_origins: list[str] = field(default_factory=list)

    # Database
    database_url: str = "sqlite:///uvt.db"
    db_pool_size: int = 5
    db_pool_max_overflow: int = 10
    db_pool_recycle: int = 1800
    db_pool_pre_ping: bool = True

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_backend: str = "memory"
    redis_url: str = "redis://localhost:6379/0"
    rate_limit_auth_login_limit: int = 5
    rate_limit_auth_login_window_seconds: int = 60
    rate_limit_vuln_list_limit: int = 60
    rate_limit_vuln_list_window_seconds: int = 60
    rate_limit_vuln_export_limit: int = 20
    rate_limit_vuln_export_window_seconds: int = 60
    rate_limit_write_limit: int = 30
    rate_limit_write_window_seconds: int = 60
    rate_limit_sensitive_limit: int = 10
    rate_limit_sensitive_window_seconds: int = 60
    rate_limit_health_limit: int = 120
    rate_limit_health_window_seconds: int = 60

    # Caching
    cache_enabled: bool = False
    cache_dashboard_ttl: int = 30
    cache_products_ttl: int = 60

    # Data retention (days, 0 = keep forever)
    retention_audit_log_days: int = 365
    retention_notification_log_days: int = 90
    retention_plugin_run_days: int = 90
    retention_report_artifact_days: int = 180

    # Celery / background tasks
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    celery_enabled: bool = False
    celery_worker_concurrency: int = 4
    celery_task_timeout: int = 3600
    celery_task_soft_timeout: int = 3300
    # Recycle worker after N tasks to release WeasyPrint/Matplotlib memory
    # held across PDF renders. 100 keeps RSS under ~500 MB on typical loads.
    celery_worker_max_tasks_per_child: int = 100

    # Frontend
    frontend_url: str = "http://127.0.0.1:5173"

    # Plugins
    plugin_import_paths: list[str] = field(default_factory=list)

    @property
    def is_production(self) -> bool:
        return self.runtime_env in ("prod", "production")

    @property
    def is_dev(self) -> bool:
        return self.runtime_env in ("development", "dev", "testing", "test")


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config() -> AppConfig:
    """Read all env vars, validate, and return a frozen config object."""
    runtime_env = os.getenv("FLASK_ENV", os.getenv("ENV", "production")).strip().lower()
    auth_cookie_secure_default = runtime_env in ("prod", "production")

    cfg = AppConfig(
        runtime_env=runtime_env,
        secret_key=_str("SECRET_KEY", "dev-secret"),
        jwt_secret=_str("JWT_SECRET", "dev-jwt-secret"),
        refresh_token_lifetime_days=_int("REFRESH_TOKEN_LIFETIME_DAYS", 30),
        allow_public_registration=_bool("ALLOW_PUBLIC_REGISTRATION", False),
        auth_cookie_secure=_bool("AUTH_COOKIE_SECURE", auth_cookie_secure_default),
        auth_cookie_samesite=_cookie_samesite(),
        auth_cookie_domain=os.getenv("AUTH_COOKIE_DOMAIN") or None,
        oidc_enabled=_bool("OIDC_ENABLED", False),
        oidc_issuer=_str("OIDC_ISSUER"),
        oidc_client_id=_str("OIDC_CLIENT_ID"),
        oidc_client_secret=_str("OIDC_CLIENT_SECRET"),
        oidc_redirect_url=_str("OIDC_REDIRECT_URL"),
        oidc_scopes=_str("OIDC_SCOPES", "openid profile email"),
        oidc_groups_claim=_str("OIDC_GROUPS_CLAIM", "groups"),
        oidc_default_role=_str("OIDC_DEFAULT_ROLE", "Viewer"),
        oidc_role_mapping=_str("OIDC_ROLE_MAPPING"),
        cors_origins=_parse_cors_origins(),
        database_url=_str("DATABASE_URL", "sqlite:///uvt.db"),
        db_pool_size=_int("DB_POOL_SIZE", 5),
        db_pool_max_overflow=_int("DB_POOL_MAX_OVERFLOW", 10),
        db_pool_recycle=_int("DB_POOL_RECYCLE", 1800),
        db_pool_pre_ping=_bool("DB_POOL_PRE_PING", True),
        rate_limit_enabled=_bool("RATE_LIMIT_ENABLED", True),
        rate_limit_backend=_str("RATE_LIMIT_BACKEND", "memory"),
        redis_url=_str("REDIS_URL", "redis://localhost:6379/0"),
        rate_limit_auth_login_limit=_int("RATE_LIMIT_AUTH_LOGIN_LIMIT", 5),
        rate_limit_auth_login_window_seconds=_int("RATE_LIMIT_AUTH_LOGIN_WINDOW_SECONDS", 60),
        rate_limit_vuln_list_limit=_int("RATE_LIMIT_VULN_LIST_LIMIT", 60),
        rate_limit_vuln_list_window_seconds=_int("RATE_LIMIT_VULN_LIST_WINDOW_SECONDS", 60),
        rate_limit_vuln_export_limit=_int("RATE_LIMIT_VULN_EXPORT_LIMIT", 20),
        rate_limit_vuln_export_window_seconds=_int("RATE_LIMIT_VULN_EXPORT_WINDOW_SECONDS", 60),
        rate_limit_write_limit=_int("RATE_LIMIT_WRITE_LIMIT", 30),
        rate_limit_write_window_seconds=_int("RATE_LIMIT_WRITE_WINDOW_SECONDS", 60),
        rate_limit_sensitive_limit=_int("RATE_LIMIT_SENSITIVE_LIMIT", 10),
        rate_limit_sensitive_window_seconds=_int("RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", 60),
        rate_limit_health_limit=_int("RATE_LIMIT_HEALTH_LIMIT", 120),
        rate_limit_health_window_seconds=_int("RATE_LIMIT_HEALTH_WINDOW_SECONDS", 60),
        retention_audit_log_days=_int("RETENTION_AUDIT_LOG_DAYS", 365),
        retention_notification_log_days=_int("RETENTION_NOTIFICATION_LOG_DAYS", 90),
        retention_plugin_run_days=_int("RETENTION_PLUGIN_RUN_DAYS", 90),
        retention_report_artifact_days=_int("RETENTION_REPORT_ARTIFACT_DAYS", 180),
        cache_enabled=_bool("CACHE_ENABLED", False),
        cache_dashboard_ttl=_int("CACHE_DASHBOARD_TTL", 30),
        cache_products_ttl=_int("CACHE_PRODUCTS_TTL", 60),
        celery_broker_url=_str("CELERY_BROKER_URL", "redis://localhost:6379/1"),
        celery_result_backend=_str("CELERY_RESULT_BACKEND", "redis://localhost:6379/2"),
        celery_enabled=_bool("CELERY_ENABLED", False),
        celery_worker_concurrency=_int("CELERY_WORKER_CONCURRENCY", 4),
        celery_task_timeout=_int("CELERY_TASK_TIMEOUT", 3600),
        celery_task_soft_timeout=_int("CELERY_TASK_SOFT_TIMEOUT", 3300),
        celery_worker_max_tasks_per_child=_int("CELERY_WORKER_MAX_TASKS_PER_CHILD", 100),
        frontend_url=_str("FRONTEND_URL", "http://127.0.0.1:5173"),
        plugin_import_paths=_parse_plugin_paths(),
    )

    # Fail fast: production must not use dev defaults for secrets
    if not cfg.is_dev:
        for attr, dev_default in [("secret_key", "dev-secret"), ("jwt_secret", "dev-jwt-secret")]:
            if getattr(cfg, attr) == dev_default:
                env_key = attr.upper()
                raise RuntimeError(
                    f"{env_key} is still set to its development default. "
                    f"Set the {env_key} environment variable before running in production."
                )

    return cfg


# ---------------------------------------------------------------------------
# Flask integration
# ---------------------------------------------------------------------------

def apply_config(app, cfg: AppConfig) -> None:
    """Push config values into Flask's ``app.config`` dict."""
    app.config["SECRET_KEY"] = cfg.secret_key
    app.config["JWT_SECRET"] = cfg.jwt_secret
    app.config["REFRESH_TOKEN_LIFETIME_DAYS"] = cfg.refresh_token_lifetime_days
    app.config["ALLOW_PUBLIC_REGISTRATION"] = cfg.allow_public_registration

    app.config["OIDC_ENABLED"] = cfg.oidc_enabled
    app.config["OIDC_ISSUER"] = cfg.oidc_issuer
    app.config["OIDC_CLIENT_ID"] = cfg.oidc_client_id
    app.config["OIDC_CLIENT_SECRET"] = cfg.oidc_client_secret
    app.config["OIDC_REDIRECT_URL"] = cfg.oidc_redirect_url
    app.config["OIDC_SCOPES"] = cfg.oidc_scopes
    app.config["OIDC_GROUPS_CLAIM"] = cfg.oidc_groups_claim
    app.config["OIDC_DEFAULT_ROLE"] = cfg.oidc_default_role
    app.config["OIDC_ROLE_MAPPING"] = cfg.oidc_role_mapping

    app.config["AUTH_COOKIE_SECURE"] = cfg.auth_cookie_secure
    app.config["AUTH_COOKIE_SAMESITE"] = cfg.auth_cookie_samesite
    app.config["AUTH_COOKIE_DOMAIN"] = cfg.auth_cookie_domain

    app.config["RATE_LIMIT_ENABLED"] = cfg.rate_limit_enabled
    app.config["RATE_LIMIT_BACKEND"] = cfg.rate_limit_backend
    app.config["REDIS_URL"] = cfg.redis_url
    app.config["RATE_LIMIT_AUTH_LOGIN_LIMIT"] = cfg.rate_limit_auth_login_limit
    app.config["RATE_LIMIT_AUTH_LOGIN_WINDOW_SECONDS"] = cfg.rate_limit_auth_login_window_seconds
    app.config["RATE_LIMIT_VULN_LIST_LIMIT"] = cfg.rate_limit_vuln_list_limit
    app.config["RATE_LIMIT_VULN_LIST_WINDOW_SECONDS"] = cfg.rate_limit_vuln_list_window_seconds
    app.config["RATE_LIMIT_VULN_EXPORT_LIMIT"] = cfg.rate_limit_vuln_export_limit
    app.config["RATE_LIMIT_VULN_EXPORT_WINDOW_SECONDS"] = cfg.rate_limit_vuln_export_window_seconds
    app.config["RATE_LIMIT_WRITE_LIMIT"] = cfg.rate_limit_write_limit
    app.config["RATE_LIMIT_WRITE_WINDOW_SECONDS"] = cfg.rate_limit_write_window_seconds
    app.config["RATE_LIMIT_SENSITIVE_LIMIT"] = cfg.rate_limit_sensitive_limit
    app.config["RATE_LIMIT_SENSITIVE_WINDOW_SECONDS"] = cfg.rate_limit_sensitive_window_seconds
    app.config["RATE_LIMIT_HEALTH_LIMIT"] = cfg.rate_limit_health_limit
    app.config["RATE_LIMIT_HEALTH_WINDOW_SECONDS"] = cfg.rate_limit_health_window_seconds

    app.config["RETENTION_AUDIT_LOG_DAYS"] = cfg.retention_audit_log_days
    app.config["RETENTION_NOTIFICATION_LOG_DAYS"] = cfg.retention_notification_log_days
    app.config["RETENTION_PLUGIN_RUN_DAYS"] = cfg.retention_plugin_run_days
    app.config["RETENTION_REPORT_ARTIFACT_DAYS"] = cfg.retention_report_artifact_days

    app.config["CACHE_ENABLED"] = cfg.cache_enabled
    app.config["CACHE_DASHBOARD_TTL"] = cfg.cache_dashboard_ttl
    app.config["CACHE_PRODUCTS_TTL"] = cfg.cache_products_ttl

    app.config["CELERY_BROKER_URL"] = cfg.celery_broker_url
    app.config["CELERY_RESULT_BACKEND"] = cfg.celery_result_backend
    app.config["CELERY_ENABLED"] = cfg.celery_enabled
    app.config["CELERY_WORKER_CONCURRENCY"] = cfg.celery_worker_concurrency
    app.config["CELERY_TASK_TIMEOUT"] = cfg.celery_task_timeout
    app.config["CELERY_TASK_SOFT_TIMEOUT"] = cfg.celery_task_soft_timeout
    app.config["CELERY_WORKER_MAX_TASKS_PER_CHILD"] = cfg.celery_worker_max_tasks_per_child

    app.config["FRONTEND_URL"] = cfg.frontend_url

    app.config["SQLALCHEMY_DATABASE_URI"] = cfg.database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Connection pool tuning (applies to PostgreSQL; SQLite ignores pool settings)
    if not cfg.database_url.startswith("sqlite"):
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "pool_size": cfg.db_pool_size,
            "max_overflow": cfg.db_pool_max_overflow,
            "pool_recycle": cfg.db_pool_recycle,
            "pool_pre_ping": cfg.db_pool_pre_ping,
        }
    app.config["PLUGIN_IMPORT_PATHS"] = cfg.plugin_import_paths
