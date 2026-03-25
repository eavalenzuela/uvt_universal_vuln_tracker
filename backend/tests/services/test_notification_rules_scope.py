from sqlalchemy import event

from backend.auth import create_user
from backend.database import db
from backend.models import NotificationRule, Product, ProductVersion, Vulnerability, VulnerabilityVersion
from backend.services.notification_rules import _passes_product_scope


def _seed_admin():
    admin = create_user("admin_scope", "admin_scope@example.com", "secret", role="Admin")
    db.session.flush()
    return admin


def _create_rule(admin_id: int, product_scope):
    rule = NotificationRule(
        name="scope rule",
        delivery_adapter="email",
        delivery_config={},
        severity_threshold="Low",
        notify_on_status_change=True,
        notify_on_assignment_change=True,
        product_scope=product_scope,
        frequency_days=1,
        escalation_after_days=1,
        channels=[],
        recipients=["owner@example.com"],
        created_by=admin_id,
        is_enabled=True,
    )
    db.session.add(rule)
    db.session.flush()
    return rule


def _create_vulnerability():
    vulnerability = Vulnerability(title="Scoped vuln", severity="High", status="Open")
    db.session.add(vulnerability)
    db.session.flush()
    return vulnerability


def _attach_vulnerability_to_product(vulnerability_id: int, product_id: int, version: str = "1.0.0"):
    product_version = ProductVersion(product_id=product_id, version=version)
    db.session.add(product_version)
    db.session.flush()
    db.session.add(VulnerabilityVersion(vulnerability_id=vulnerability_id, product_version_id=product_version.id))
    db.session.flush()


def test_passes_product_scope_returns_true_when_rule_is_unscoped(app):
    with app.app_context():
        admin = _seed_admin()
        rule = _create_rule(admin.id, product_scope=[])
        vulnerability = _create_vulnerability()

        assert _passes_product_scope(rule, vulnerability) is True


def test_passes_product_scope_honors_scoped_products(app):
    with app.app_context():
        admin = _seed_admin()

        in_scope_product = Product(name="In Scope Product", created_by=admin.id)
        out_scope_product = Product(name="Out Scope Product", created_by=admin.id)
        db.session.add_all([in_scope_product, out_scope_product])
        db.session.flush()

        vulnerability = _create_vulnerability()
        _attach_vulnerability_to_product(vulnerability.id, out_scope_product.id, version="1.0.0")

        scoped_rule = _create_rule(admin.id, product_scope=[in_scope_product.id])
        unscoped_rule = _create_rule(admin.id, product_scope=[out_scope_product.id])

        assert _passes_product_scope(scoped_rule, vulnerability) is False
        assert _passes_product_scope(unscoped_rule, vulnerability) is True


def test_passes_product_scope_uses_single_joined_query_for_many_versions(app):
    with app.app_context():
        admin = _seed_admin()
        vulnerability = _create_vulnerability()

        scoped_product = Product(name="Scoped Product", created_by=admin.id)
        db.session.add(scoped_product)
        db.session.flush()

        many_other_products = [Product(name=f"Other Product {idx}", created_by=admin.id) for idx in range(120)]
        db.session.add_all(many_other_products)
        db.session.flush()

        for idx, product in enumerate(many_other_products):
            _attach_vulnerability_to_product(vulnerability.id, product.id, version=f"1.{idx}.0")

        _attach_vulnerability_to_product(vulnerability.id, scoped_product.id, version="9.9.9")

        rule = _create_rule(admin.id, product_scope=[scoped_product.id])

        select_statements = []

        def _before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith("SELECT"):
                select_statements.append(statement)

        event.listen(db.engine, "before_cursor_execute", _before_cursor_execute)
        try:
            assert _passes_product_scope(rule, vulnerability) is True
        finally:
            event.remove(db.engine, "before_cursor_execute", _before_cursor_execute)

        assert len(select_statements) == 1
