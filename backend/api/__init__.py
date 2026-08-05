from .auth_routes import bp as auth_bp
from .attack_vectors import bp as attack_vectors_bp
from .controls import bp as controls_bp
from .products import bp as products_bp
from .plugins import bp as plugins_bp
from .terminal_impacts import bp as terminal_impacts_bp
from .vuln_crud import bp as vulns_bp
from .vuln_comments import bp as vuln_comments_bp
from .vuln_versions import bp as vuln_versions_bp
from .vuln_bulk import bp as vuln_bulk_bp
from .vuln_risk import bp as vuln_risk_bp
from .users_crud import bp as users_bp
from .users_tokens import bp as users_tokens_bp
from .audit_logs import bp as audit_logs_bp
from .notification_rules import bp as notification_rules_bp
from .notification_delivery import bp as notification_delivery_bp
from .vulnerability_filters import bp as vulnerability_filters_bp
from .sla_policy import bp as sla_policy_bp
from .report_exports import bp as report_exports_bp
from .report_templates import bp as report_templates_bp
from .report_schedules import bp as report_schedules_bp
from .components import bp as components_bp
from .live_notifications import bp as live_notifications_bp
from .notifications import bp as notifications_bp
from .dashboard_layout_presets import bp as dashboard_layout_presets_bp
from .tasks import bp as tasks_bp
from .search import bp as search_bp
from .webhooks import bp as webhooks_bp
from .user_preferences import bp as user_preferences_bp
from .scanner_imports import bp as scanner_imports_bp
from .teams import bp as teams_bp
from .branding import bp as branding_bp


_BLUEPRINTS = [
    auth_bp,
    attack_vectors_bp,
    controls_bp,
    products_bp,
    plugins_bp,
    terminal_impacts_bp,
    vulns_bp,
    vuln_comments_bp,
    vuln_versions_bp,
    vuln_bulk_bp,
    vuln_risk_bp,
    users_bp,
    users_tokens_bp,
    audit_logs_bp,
    notification_rules_bp,
    notification_delivery_bp,
    vulnerability_filters_bp,
    sla_policy_bp,
    report_exports_bp,
    report_templates_bp,
    report_schedules_bp,
    components_bp,
    live_notifications_bp,
    notifications_bp,
    dashboard_layout_presets_bp,
    tasks_bp,
    search_bp,
    webhooks_bp,
    user_preferences_bp,
    scanner_imports_bp,
    teams_bp,
    branding_bp,
]


class _V1AliasMiddleware:
    """WSGI middleware that rewrites ``/api/v1/*`` → ``/api/*`` before routing.

    Runs outside the Flask app, which is required because Flask's
    ``before_request`` hooks fire after URL matching has already happened —
    too late to redirect a request to a different rule.
    """

    _PREFIX = "/api/v1/"

    def __init__(self, wsgi_app):
        self._wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path.startswith(self._PREFIX):
            environ["PATH_INFO"] = "/api/" + path[len(self._PREFIX):]
            environ["uvt.api_version"] = "v1"
        return self._wsgi_app(environ, start_response)


def _install_v1_alias(app):
    """Accept /api/v1/* as an alias for /api/* (F18).

    External callers can pin to the v1 namespace today; future breaking changes
    land at /api/v2 and leave /api/v1 stable. Implemented as WSGI middleware so
    the URL map stays single-source-of-truth and OpenAPI docs don't double-
    register every route.
    """
    app.wsgi_app = _V1AliasMiddleware(app.wsgi_app)


def register_api(app):
    for bp in _BLUEPRINTS:
        app.register_blueprint(bp)
    _install_v1_alias(app)
