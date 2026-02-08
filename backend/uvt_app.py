import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS

from .database import init_database
from .api import register_api
from . import models  # ensures migrations can discover models
from .cli import run_notification_scan_cli, run_plugins_cli, seed_admin
from .auth import enforce_scopes
from .plugins import init_plugin_registry
from .api.validation import ValidationError, error_response


def _env_to_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_cookie_samesite(default: str = "Lax") -> str:
    raw = os.getenv("AUTH_COOKIE_SAMESITE", default).strip().lower()
    allowed = {"lax": "Lax", "strict": "Strict", "none": "None"}
    return allowed.get(raw, default)

def create_app():
    app = Flask(__name__)

    # CORS headers
    CORS(
        app,
        resources={r"/api/*": {"origins": [
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "http://127.0.0.1:5000",
            "http://localhost:5000",
        ]}},
        supports_credentials=True,
        allow_headers=["Authorization", "Content-Type"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )

    # Config (SQLite by default so it boots instantly)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
    app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", "dev-jwt-secret")
    app.config["REFRESH_TOKEN_LIFETIME_DAYS"] = int(os.getenv("REFRESH_TOKEN_LIFETIME_DAYS", "30"))
    app.config["ALLOW_PUBLIC_REGISTRATION"] = os.getenv("ALLOW_PUBLIC_REGISTRATION", "false").lower() in ("1", "true", "yes")

    app.config["OIDC_ENABLED"] = os.getenv("OIDC_ENABLED", "false").lower() in ("1", "true", "yes")
    app.config["OIDC_ISSUER"] = os.getenv("OIDC_ISSUER", "")
    app.config["OIDC_CLIENT_ID"] = os.getenv("OIDC_CLIENT_ID", "")
    app.config["OIDC_CLIENT_SECRET"] = os.getenv("OIDC_CLIENT_SECRET", "")
    app.config["OIDC_REDIRECT_URL"] = os.getenv("OIDC_REDIRECT_URL", "")
    app.config["OIDC_SCOPES"] = os.getenv("OIDC_SCOPES", "openid profile email")
    app.config["OIDC_GROUPS_CLAIM"] = os.getenv("OIDC_GROUPS_CLAIM", "groups")
    app.config["OIDC_DEFAULT_ROLE"] = os.getenv("OIDC_DEFAULT_ROLE", "Viewer")
    app.config["OIDC_ROLE_MAPPING"] = os.getenv("OIDC_ROLE_MAPPING", "")

    runtime_env = os.getenv("FLASK_ENV", os.getenv("ENV", "production")).strip().lower()
    auth_cookie_secure_default = runtime_env in ("prod", "production")
    app.config["AUTH_COOKIE_SECURE"] = _env_to_bool("AUTH_COOKIE_SECURE", auth_cookie_secure_default)
    app.config["AUTH_COOKIE_SAMESITE"] = _env_cookie_samesite(default="Lax")
    app.config["AUTH_COOKIE_DOMAIN"] = os.getenv("AUTH_COOKIE_DOMAIN") or None

    app.config["RATE_LIMIT_ENABLED"] = os.getenv("RATE_LIMIT_ENABLED", "true").lower() in ("1", "true", "yes")
    app.config["RATE_LIMIT_BACKEND"] = os.getenv("RATE_LIMIT_BACKEND", "memory")
    app.config["REDIS_URL"] = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    app.config["RATE_LIMIT_AUTH_LOGIN_LIMIT"] = int(os.getenv("RATE_LIMIT_AUTH_LOGIN_LIMIT", "5"))
    app.config["RATE_LIMIT_AUTH_LOGIN_WINDOW_SECONDS"] = int(os.getenv("RATE_LIMIT_AUTH_LOGIN_WINDOW_SECONDS", "60"))
    app.config["RATE_LIMIT_VULN_LIST_LIMIT"] = int(os.getenv("RATE_LIMIT_VULN_LIST_LIMIT", "60"))
    app.config["RATE_LIMIT_VULN_LIST_WINDOW_SECONDS"] = int(os.getenv("RATE_LIMIT_VULN_LIST_WINDOW_SECONDS", "60"))
    app.config["RATE_LIMIT_VULN_EXPORT_LIMIT"] = int(os.getenv("RATE_LIMIT_VULN_EXPORT_LIMIT", "20"))
    app.config["RATE_LIMIT_VULN_EXPORT_WINDOW_SECONDS"] = int(os.getenv("RATE_LIMIT_VULN_EXPORT_WINDOW_SECONDS", "60"))
    db_url = os.getenv("DATABASE_URL", "sqlite:///uvt.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["PLUGIN_IMPORT_PATHS"] = [
        path.strip()
        for path in os.getenv("PLUGIN_IMPORT_PATHS", "").split(",")
        if path.strip()
    ]
    app.cli.add_command(seed_admin)
    app.cli.add_command(run_plugins_cli)
    app.cli.add_command(run_notification_scan_cli)

    # Logging
    logging.basicConfig(level=logging.INFO)
    app.logger.setLevel(logging.INFO)

    # DB + migrations
    init_database(app)

    # Plugin registry
    init_plugin_registry(app)

    # API routes
    register_api(app)

    # Auth scope enforcement
    enforce_scopes(app)

    # Simple health endpoint
    @app.get("/api/health")
    def health():
        return jsonify({"ok": True})

    # Error handlers
    @app.errorhandler(ValidationError)
    def validation_error(err: ValidationError):
        return error_response(err.error, field=err.field, details=err.details, status_code=err.status_code)

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(_e):
        return jsonify({"error": "Server error"}), 500

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
