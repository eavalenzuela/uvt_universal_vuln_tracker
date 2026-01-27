import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS

from .database import init_database
from .api import register_api
from . import models  # ensures migrations can discover models
from .cli import run_plugins_cli, seed_admin
from .auth import enforce_scopes
from .plugins import init_plugin_registry

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
        supports_credentials=False,
        allow_headers=["Authorization", "Content-Type"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )

    # Config (SQLite by default so it boots instantly)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
    app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", "dev-jwt-secret")
    app.config["ALLOW_PUBLIC_REGISTRATION"] = os.getenv("ALLOW_PUBLIC_REGISTRATION", "false").lower() in ("1", "true", "yes")

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
