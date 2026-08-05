import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS

from .config import load_config, apply_config
from .database import init_database
from .logging_config import configure_logging
from .api import register_api
from . import models  # ensures all models are registered before create_all()
from .cli import run_notification_scan_cli, run_plugins_cli, seed_admin, purge_old_data_cli
from .auth import enforce_scopes
from .permissions import audit_route_scopes
from .plugins import init_plugin_registry
from .api.validation import ValidationError, error_response
from .openapi import init_openapi
from .rate_limiter import rate_limit
from .celery_app import init_celery
from .metrics import init_metrics
from .schema_guard import install_schema_guard, verify_schema

# Content-Security-Policy for the SPA document.
#
# The previous policy was ``default-src 'none'``, which the frontend cannot run
# under at all — it was only ever applied to JSON responses, where it had
# nothing to restrict. This one is scoped to what the app actually loads:
# same-origin ES modules and stylesheets, inline styles (the views set
# element.style directly), data: images for the branding logo, and same-origin
# XHR/SSE. No 'unsafe-inline' for scripts and no 'unsafe-eval'.
HTML_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "object-src 'none'; "
    "frame-ancestors 'none'"
)


def create_app():
    app = Flask(__name__)

    cfg = load_config()
    apply_config(app, cfg)

    # CORS headers
    CORS(
        app,
        resources={r"/api/*": {"origins": cfg.cors_origins}},
        supports_credentials=True,
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-UVT-Team-Id"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )

    app.cli.add_command(seed_admin)
    app.cli.add_command(run_plugins_cli)
    app.cli.add_command(run_notification_scan_cli)
    app.cli.add_command(purge_old_data_cli)

    # Structured logging with request ID correlation
    configure_logging(app)

    # DB + Alembic
    init_database(app)

    # Verify the database matches the models before serving anything. A schema
    # that is behind head (or drifted from it) makes the app return 503 with a
    # named reason instead of 500-ing on the first query that touches a missing
    # column.
    schema_status = verify_schema(app, auto_upgrade_fresh=cfg.db_auto_upgrade_fresh)
    install_schema_guard(app, schema_status)

    # F15: ensure the Default team exists and every user is a member.
    # Idempotent and cheap; runs once per boot. Skipped on a bad schema —
    # it writes, and the tables it needs may not be there yet.
    if schema_status.ok:
        from .services.team_scope import ensure_default_team
        with app.app_context():
            ensure_default_team()

    # Celery background task queue
    init_celery(app)

    # Plugin registry
    init_plugin_registry(app)

    # API routes
    register_api(app)

    # Auth scope enforcement. The audit runs after every blueprint is
    # registered and names any route missing a scope mapping — those now fail
    # closed, so a new endpoint announces itself at boot rather than quietly
    # inheriting permissive behaviour.
    enforce_scopes(app)
    audit_route_scopes(app)

    # Prometheus metrics
    init_metrics(app)

    # Security response headers.
    #
    # These matter most on the HTML document, which nginx serves — see
    # docker/nginx.conf, which sets the same set plus a CSP the SPA can
    # actually run under. Keeping them here too covers standalone/dev runs
    # where Flask serves everything, and defends the API if it is ever
    # exposed without the proxy in front.
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
        # API responses render nothing, so the strictest policy is correct here.
        # Anything serving HTML gets the document policy instead.
        if response.mimetype == "text/html":
            response.headers.setdefault("Content-Security-Policy", HTML_CSP)
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            )
        if cfg.auth_cookie_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )
        return response

    # Health endpoint with DB and Redis connectivity checks
    @app.get("/api/health")
    @rate_limit("RATE_LIMIT_HEALTH_LIMIT", "RATE_LIMIT_HEALTH_WINDOW_SECONDS", identifier="health")
    def health():
        """Health check endpoint.
        ---
        get:
          summary: Health check
          responses:
            200:
              description: Service is healthy
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      ok:
                        type: boolean
                      checks:
                        type: object
                        properties:
                          database:
                            type: string
                            enum: [ok, error]
                          redis:
                            type: string
                            enum: [ok, error, disabled]
            503:
              description: Service is degraded
              content:
                application/json:
                  schema:
                    type: object
        """
        checks = {}
        healthy = True

        # Database connectivity
        try:
            from .database import db
            db.session.execute(db.text("SELECT 1"))
            checks["database"] = "ok"
        except Exception:
            checks["database"] = "error"
            healthy = False

        # Schema version. A connectable database running an outdated schema is
        # not healthy — that state used to present as random 500s on the first
        # page a user opened.
        status = app.config.get("SCHEMA_STATUS")
        if status is not None:
            checks["schema"] = status.as_dict()
            if not status.ok:
                healthy = False

        # Redis connectivity
        if cfg.rate_limit_backend == "redis" or cfg.celery_enabled:
            try:
                import redis as redis_lib
                r = redis_lib.from_url(cfg.redis_url, socket_timeout=2)
                r.ping()
                checks["redis"] = "ok"
            except Exception:
                checks["redis"] = "error"
                healthy = False
        else:
            checks["redis"] = "disabled"

        status_code = 200 if healthy else 503
        return jsonify({"ok": healthy, "checks": checks}), status_code

    # Error handlers
    @app.errorhandler(ValidationError)
    def validation_error(err: ValidationError):
        return error_response(err.error, field=err.field, details=err.details, status_code=err.status_code)

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Unhandled 500 error: %s", e)
        return jsonify({"error": "Server error"}), 500

    # OpenAPI spec + Swagger UI (after all routes are registered)
    init_openapi(app)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")),
            debug=os.getenv("FLASK_ENV") == "development")
