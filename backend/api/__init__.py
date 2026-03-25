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


def register_api(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(attack_vectors_bp)
    app.register_blueprint(controls_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(plugins_bp)
    app.register_blueprint(terminal_impacts_bp)
    app.register_blueprint(vulns_bp)
    app.register_blueprint(vuln_comments_bp)
    app.register_blueprint(vuln_versions_bp)
    app.register_blueprint(vuln_bulk_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(users_tokens_bp)
    app.register_blueprint(audit_logs_bp)
    app.register_blueprint(notification_rules_bp)
    app.register_blueprint(notification_delivery_bp)
    app.register_blueprint(vulnerability_filters_bp)
    app.register_blueprint(sla_policy_bp)
    app.register_blueprint(report_exports_bp)
    app.register_blueprint(report_templates_bp)
    app.register_blueprint(report_schedules_bp)
    app.register_blueprint(components_bp)
    app.register_blueprint(live_notifications_bp)
    app.register_blueprint(notifications_bp)
    app.register_blueprint(dashboard_layout_presets_bp)
