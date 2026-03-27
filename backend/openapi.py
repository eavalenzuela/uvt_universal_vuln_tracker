"""OpenAPI 3.0 specification builder and Swagger UI integration."""

from apispec import APISpec
from apispec.utils import deepupdate
from apispec_webframeworks.flask import FlaskPlugin
from flask_swagger_ui import get_swaggerui_blueprint
from flask import jsonify


SPEC_VERSION = "3.0.3"
API_TITLE = "Universal Vulnerability Tracker API"
API_VERSION = "3.0.0"

SWAGGER_URL = "/api/docs"
OPENAPI_JSON_URL = "/api/openapi.json"


def _build_spec():
    spec = APISpec(
        title=API_TITLE,
        version=API_VERSION,
        openapi_version=SPEC_VERSION,
        info={
            "description": (
                "REST API for the Universal Vulnerability Tracker (UVT) — "
                "a full-stack vulnerability management platform.\n\n"
                "**Authentication:** Most endpoints require a JWT Bearer token "
                "obtained via `POST /api/auth/login`. Pass it in the "
                "`Authorization: Bearer <token>` header."
            ),
            "contact": {"name": "UVT Project"},
            "license": {"name": "MIT"},
        },
        plugins=[FlaskPlugin()],
    )

    # --- Security schemes ---
    spec.components.security_scheme("BearerAuth", {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": "JWT access token from POST /api/auth/login",
    })
    spec.components.security_scheme("CookieAuth", {
        "type": "apiKey",
        "in": "cookie",
        "name": "uvt_auth_token",
        "description": "HTTP-only auth cookie (set automatically on login)",
    })

    # --- Tags ---
    tags = [
        ("Auth", "Authentication, sessions, OIDC, password reset"),
        ("Users", "User management (Admin only)"),
        ("API Tokens", "Personal and admin-managed API tokens"),
        ("Products", "Products and product versions"),
        ("Vulnerabilities", "Vulnerability CRUD, enrichment, merge"),
        ("Vulnerability Comments", "Comments on vulnerabilities"),
        ("Vulnerability Versions", "Product-version mappings for vulnerabilities"),
        ("Vulnerability Bulk", "Batch/bulk operations and watchers"),
        ("Vulnerability Filters", "Saved vulnerability filter presets"),
        ("Components", "Software components, SBOM import, dependency graph"),
        ("Controls", "Security controls (frameworks, mappings)"),
        ("Attack Vectors", "Attack vector definitions and vulnerability mappings"),
        ("Terminal Impacts", "Terminal impact definitions and vulnerability mappings"),
        ("SLA Policy", "SLA policy configuration"),
        ("Audit Logs", "Audit trail (Admin only)"),
        ("Notifications", "User notification inbox"),
        ("Notification Rules", "Notification rule management (Admin only)"),
        ("Notification Delivery", "Delivery attempt inspection and retry (Admin only)"),
        ("Live Notifications", "Server-Sent Events notification stream"),
        ("Reports", "Report exports, dashboard summary, risk trends"),
        ("Report Templates", "Report template management"),
        ("Report Schedules", "Scheduled report management"),
        ("Dashboard Layout Presets", "Dashboard widget layout presets"),
        ("Plugins", "Plugin management, runs, artifacts, import"),
        ("Health", "Health check"),
    ]
    for name, desc in tags:
        spec.tag({"name": name, "description": desc})

    # --- Reusable schemas ---
    _register_schemas(spec)

    return spec


def _register_schemas(spec):
    spec.components.schema("Error", {
        "type": "object",
        "properties": {
            "error": {"type": "string", "description": "Human-readable error message"},
            "field": {"type": "string", "description": "Field that caused the error", "nullable": True},
            "details": {"type": "object", "description": "Additional error details", "nullable": True},
        },
        "required": ["error"],
    })

    spec.components.schema("Ok", {
        "type": "object",
        "properties": {
            "ok": {"type": "boolean", "example": True},
        },
    })

    spec.components.schema("OkMessage", {
        "type": "object",
        "properties": {
            "ok": {"type": "boolean", "example": True},
            "message": {"type": "string"},
        },
    })

    spec.components.schema("PaginationParams", {
        "type": "object",
        "properties": {
            "page": {"type": "integer", "minimum": 1, "default": 1},
            "per_page": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
        },
    })

    spec.components.schema("UserSummary", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "username": {"type": "string"},
            "email": {"type": "string", "format": "email"},
            "full_name": {"type": "string", "nullable": True},
            "is_active": {"type": "boolean"},
        },
    })

    spec.components.schema("User", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "username": {"type": "string"},
            "email": {"type": "string", "format": "email"},
            "first_name": {"type": "string", "nullable": True},
            "last_name": {"type": "string", "nullable": True},
            "full_name": {"type": "string", "nullable": True},
            "role": {"type": "string", "enum": ["Admin", "Analyst", "Viewer"]},
            "is_active": {"type": "boolean"},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("AuthResponse", {
        "type": "object",
        "properties": {
            "token": {"type": "string", "description": "JWT access token"},
            "refresh_token": {"type": "string", "description": "Refresh token"},
            "csrf_token": {"type": "string", "description": "CSRF token"},
            "user": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "username": {"type": "string"},
                    "email": {"type": "string", "format": "email"},
                    "role": {"type": "string", "enum": ["Admin", "Analyst", "Viewer"]},
                },
            },
        },
    })

    spec.components.schema("ApiToken", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "owner_id": {"type": "integer"},
            "scopes": {"type": "array", "items": {"type": "string"}},
            "expires_at": {"type": "string", "format": "date-time", "nullable": True},
            "last_used_at": {"type": "string", "format": "date-time", "nullable": True},
            "revoked_at": {"type": "string", "format": "date-time", "nullable": True},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("Product", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "description": {"type": "string", "nullable": True},
            "version_count": {"type": "integer"},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("ProductDetail", {
        "allOf": [
            {"$ref": "#/components/schemas/Product"},
            {
                "type": "object",
                "properties": {
                    "owners": {"type": "array", "items": {"$ref": "#/components/schemas/UserSummary"}},
                    "owner_ids": {"type": "array", "items": {"type": "integer"}},
                    "versions": {"type": "array", "items": {"$ref": "#/components/schemas/ProductVersion"}},
                    "created_by": {"$ref": "#/components/schemas/UserSummary"},
                    "controls": {"type": "array", "items": {"type": "object"}},
                    "component_count": {"type": "integer"},
                    "components": {"type": "array", "items": {"$ref": "#/components/schemas/SoftwareComponent"}},
                },
            },
        ],
    })

    spec.components.schema("ProductVersion", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "product_id": {"type": "integer"},
            "version": {"type": "string"},
            "release_date": {"type": "string", "format": "date", "nullable": True},
            "is_active": {"type": "boolean"},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("SoftwareComponent", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "product_version_id": {"type": "integer"},
            "name": {"type": "string"},
            "version": {"type": "string", "nullable": True},
            "ecosystem": {"type": "string", "nullable": True},
            "purl": {"type": "string", "nullable": True},
            "cpe": {"type": "string", "nullable": True},
        },
    })

    spec.components.schema("Vulnerability", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "cve_id": {"type": "string", "nullable": True, "example": "CVE-2024-1234"},
            "title": {"type": "string"},
            "description": {"type": "string", "nullable": True},
            "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Informational"], "nullable": True},
            "cvss_score": {"type": "number", "format": "float", "nullable": True, "minimum": 0, "maximum": 10},
            "status": {"type": "string", "enum": ["Open", "In Progress", "Mitigated", "Resolved", "Accepted", "False Positive"]},
            "attack_complexity": {"type": "string", "nullable": True},
            "assigned_to": {"type": "integer", "nullable": True},
            "sla_due_at": {"type": "string", "format": "date-time", "nullable": True},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("VulnerabilityComment", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "vulnerability_id": {"type": "integer"},
            "author_id": {"type": "integer"},
            "author": {
                "type": "object",
                "nullable": True,
                "properties": {
                    "id": {"type": "integer"},
                    "username": {"type": "string"},
                },
            },
            "body": {"type": "string"},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("VulnerabilityWatcher", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "vulnerability_id": {"type": "integer"},
            "user_id": {"type": "integer"},
            "username": {"type": "string"},
            "added_by": {"type": "integer", "nullable": True},
            "created_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("Control", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "framework": {"type": "string", "nullable": True},
            "description": {"type": "string", "nullable": True},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("AttackVector", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "description": {"type": "string", "nullable": True},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("TerminalImpact", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "description": {"type": "string", "nullable": True},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("NotificationRule", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "is_enabled": {"type": "boolean"},
            "delivery_adapter": {"type": "string"},
            "delivery_config": {"type": "object", "nullable": True},
            "severity_threshold": {"type": "string", "nullable": True},
            "notify_on_status_change": {"type": "boolean"},
            "notify_on_assignment_change": {"type": "boolean"},
            "product_scope": {"type": "array", "items": {"type": "integer"}, "nullable": True},
            "frequency_days": {"type": "integer", "nullable": True},
            "escalation_after_days": {"type": "integer", "nullable": True},
            "channels": {"type": "array", "items": {"type": "string"}, "nullable": True},
            "recipients": {"type": "array", "items": {"type": "string"}, "nullable": True},
            "created_by": {"type": "integer", "nullable": True},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("Notification", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "user_id": {"type": "integer"},
            "title": {"type": "string"},
            "body": {"type": "string", "nullable": True},
            "is_read": {"type": "boolean"},
            "link": {"type": "string", "nullable": True},
            "created_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("AuditLog", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "actor_id": {"type": "integer", "nullable": True},
            "action": {"type": "string"},
            "resource": {"type": "string"},
            "record_id": {"type": "integer", "nullable": True},
            "old_values": {"type": "object", "nullable": True},
            "new_values": {"type": "object", "nullable": True},
            "created_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("PluginInfo", {
        "type": "object",
        "properties": {
            "plugin_id": {"type": "string"},
            "display_name": {"type": "string"},
            "version": {"type": "string"},
            "capabilities": {"type": "array", "items": {"type": "string"}},
            "config_schema": {"type": "object", "nullable": True},
            "config": {"type": "object"},
            "enabled": {"type": "boolean"},
            "schedule_cron": {"type": "string", "nullable": True},
            "interval_minutes": {"type": "integer", "nullable": True},
            "last_run": {"$ref": "#/components/schemas/PluginRun"},
        },
    })

    spec.components.schema("PluginRun", {
        "type": "object",
        "nullable": True,
        "properties": {
            "id": {"type": "integer"},
            "plugin_id": {"type": "string"},
            "status": {"type": "string"},
            "started_at": {"type": "string", "format": "date-time", "nullable": True},
            "finished_at": {"type": "string", "format": "date-time", "nullable": True},
            "error": {"type": "string", "nullable": True},
            "stats": {"type": "object", "nullable": True},
        },
    })

    spec.components.schema("PluginConfig", {
        "type": "object",
        "properties": {
            "plugin_id": {"type": "string"},
            "enabled": {"type": "boolean"},
            "schedule_cron": {"type": "string", "nullable": True},
            "interval_minutes": {"type": "integer", "nullable": True},
            "config": {"type": "object"},
        },
    })

    spec.components.schema("PluginArtifact", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "plugin_run_id": {"type": "integer"},
            "artifact_type": {"type": "string"},
            "storage_path": {"type": "string"},
            "checksum": {"type": "string", "nullable": True},
            "size": {"type": "integer", "nullable": True},
            "content_type": {"type": "string", "nullable": True},
            "created_at": {"type": "string", "format": "date-time"},
            "links": {"type": "array", "items": {"type": "object"}},
        },
    })

    spec.components.schema("ReportTemplate", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "report_type": {"type": "string"},
            "fields": {"type": "array", "items": {"type": "string"}, "nullable": True},
            "filters": {"type": "object", "nullable": True},
            "format": {"type": "string"},
            "delivery_channel": {"type": "string", "nullable": True},
            "recipients": {"type": "array", "items": {"type": "string"}, "nullable": True},
            "delivery_preferences": {"type": "object", "nullable": True},
            "visibility": {"type": "string"},
            "owner": {"$ref": "#/components/schemas/UserSummary"},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("ReportSchedule", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "report_type": {"type": "string"},
            "frequency": {"type": "string"},
            "delivery_channel": {"type": "string"},
            "recipients": {"type": "array", "items": {"type": "string"}},
            "timezone": {"type": "string", "nullable": True},
            "filters": {"type": "object", "nullable": True},
            "is_active": {"type": "boolean"},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("ReportArtifact", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "report_type": {"type": "string"},
            "format": {"type": "string"},
            "storage_path": {"type": "string"},
            "download_url": {"type": "string"},
            "created_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("DashboardSummary", {
        "type": "object",
        "properties": {
            "total": {"type": "integer"},
            "by_severity": {"type": "object"},
            "by_status": {"type": "object"},
        },
    })

    spec.components.schema("DashboardLayoutPreset", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "widget_config_json": {"type": "object"},
            "visibility": {"type": "string", "enum": ["private", "public"]},
            "is_default": {"type": "boolean"},
            "owner_id": {"type": "integer"},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("SavedVulnerabilityFilter", {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "filter_json": {"type": "object"},
            "visibility": {"type": "string", "enum": ["private", "public"]},
            "is_default": {"type": "boolean"},
            "owner_id": {"type": "integer"},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
    })

    spec.components.schema("SlaPolicy", {
        "type": "object",
        "description": "SLA policy defining remediation deadlines per severity level",
        "additionalProperties": True,
    })


# ---------------------------------------------------------------------------
# Route auto-discovery
# ---------------------------------------------------------------------------

# Map blueprint names to OpenAPI tags
_BLUEPRINT_TAG_MAP = {
    "auth_api": "Auth",
    "users_api": "Users",
    "users_tokens_api": "API Tokens",
    "products_api": "Products",
    "vulns_api": "Vulnerabilities",
    "vuln_comments_api": "Vulnerability Comments",
    "vuln_versions_api": "Vulnerability Versions",
    "vuln_bulk_api": "Vulnerability Bulk",
    "vuln_filters_api": "Vulnerability Filters",
    "components_api": "Components",
    "controls_api": "Controls",
    "attack_vectors_api": "Attack Vectors",
    "terminal_impacts_api": "Terminal Impacts",
    "sla_policy_api": "SLA Policy",
    "audit_logs_api": "Audit Logs",
    "notifications_api": "Notifications",
    "notification_rules_api": "Notification Rules",
    "notification_delivery_api": "Notification Delivery",
    "live_notifications": "Live Notifications",
    "report_exports_api": "Reports",
    "report_templates_api": "Report Templates",
    "report_schedules_api": "Report Schedules",
    "dashboard_layout_presets_api": "Dashboard Layout Presets",
    "plugins_api": "Plugins",
}

# Endpoints to skip in the spec
_SKIP_ENDPOINTS = {"static", "swagger_ui.show"}


def _register_paths(spec, app):
    """Walk all Flask URL rules and register them with apispec."""
    with app.test_request_context():
        for rule in app.url_map.iter_rules():
            if rule.endpoint in _SKIP_ENDPOINTS:
                continue
            if rule.endpoint.startswith("swagger_ui"):
                continue
            # Only document /api/ routes
            if not rule.rule.startswith("/api/"):
                continue
            # Skip the openapi.json endpoint itself
            if rule.rule == OPENAPI_JSON_URL:
                continue

            view = app.view_functions.get(rule.endpoint)
            if view is None:
                continue

            # Determine tag from blueprint
            bp_name = rule.endpoint.rsplit(".", 1)[0] if "." in rule.endpoint else None
            tag = _BLUEPRINT_TAG_MAP.get(bp_name)
            # Non-blueprint /api/ endpoints (e.g. health) get the Health tag
            if not tag and not bp_name:
                tag = "Health"

            operations = {}
            methods = rule.methods - {"OPTIONS", "HEAD"}
            for method in methods:
                op = {}
                if tag:
                    op["tags"] = [tag]
                operations[method.lower()] = op

            try:
                spec.path(view=view, operations=operations)
            except Exception:
                # If a view can't be registered (e.g. duplicate), skip it
                pass


# ---------------------------------------------------------------------------
# App integration
# ---------------------------------------------------------------------------

def init_openapi(app):
    """Register OpenAPI JSON endpoint and Swagger UI with the Flask app."""
    spec = _build_spec()
    _register_paths(spec, app)

    # Store spec on app for potential reuse
    app.extensions["openapi_spec"] = spec

    @app.get(OPENAPI_JSON_URL)
    def openapi_json():
        return jsonify(spec.to_dict())

    # Swagger UI blueprint
    swagger_bp = get_swaggerui_blueprint(
        SWAGGER_URL,
        OPENAPI_JSON_URL,
        config={"app_name": API_TITLE, "deepLinking": True},
    )
    app.register_blueprint(swagger_bp, url_prefix=SWAGGER_URL)
