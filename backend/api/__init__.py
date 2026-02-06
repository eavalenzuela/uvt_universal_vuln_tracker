from .auth_routes import bp as auth_bp
from .attack_vectors import bp as attack_vectors_bp
from .controls import bp as controls_bp
from .products import bp as products_bp
from .plugins import bp as plugins_bp
from .terminal_impacts import bp as terminal_impacts_bp
from .vulnerabilities import bp as vulns_bp
from .users import bp as users_bp
from .notification_rules import bp as notification_rules_bp
from .vulnerability_filters import bp as vulnerability_filters_bp
from .sla_policy import bp as sla_policy_bp
from .reports import bp as reports_bp
from .components import bp as components_bp


def register_api(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(attack_vectors_bp)
    app.register_blueprint(controls_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(plugins_bp)
    app.register_blueprint(terminal_impacts_bp)
    app.register_blueprint(vulns_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(notification_rules_bp)
    app.register_blueprint(vulnerability_filters_bp)
    app.register_blueprint(sla_policy_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(components_bp)
