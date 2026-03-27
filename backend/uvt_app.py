import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS

from .config import load_config, apply_config
from .database import init_database
from .logging_config import configure_logging
from .api import register_api
from . import models  # ensures all models are registered before create_all()
from .cli import run_notification_scan_cli, run_plugins_cli, seed_admin
from .auth import enforce_scopes
from .plugins import init_plugin_registry
from .api.validation import ValidationError, error_response
from .openapi import init_openapi
from .rate_limiter import rate_limit


def create_app():
    app = Flask(__name__)

    cfg = load_config()
    apply_config(app, cfg)

    # CORS headers
    CORS(
        app,
        resources={r"/api/*": {"origins": cfg.cors_origins}},
        supports_credentials=True,
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )

    app.cli.add_command(seed_admin)
    app.cli.add_command(run_plugins_cli)
    app.cli.add_command(run_notification_scan_cli)

    # Structured logging with request ID correlation
    configure_logging(app)

    # DB
    init_database(app)

    # Plugin registry
    init_plugin_registry(app)

    # API routes
    register_api(app)

    # Auth scope enforcement
    enforce_scopes(app)

    # Security response headers
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        if cfg.auth_cookie_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )
        return response

    # Simple health endpoint
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
                    $ref: '#/components/schemas/Ok'
        """
        return jsonify({"ok": True})

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
