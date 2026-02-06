from datetime import date
import json

from backend.auth import create_user, generate_token, hash_password
from backend.database import db
from backend.models import AuditLog, Product, ProductVersion, User, Vulnerability, VulnerabilityVersion


def auth_header(user):
    token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    return {"Authorization": f"Bearer {token}"}


def create_admin(app):
    with app.app_context():
        user = create_user("admin", "admin@example.com", "secret", role="Admin")
        db.session.refresh(user)
        db.session.expunge(user)
        return user


def create_user_direct(app, username, email, role="Analyst", is_active=True):
    with app.app_context():
        user = User(
            username=username,
            email=email,
            password_hash=hash_password("pass123"),
            role=role,
            is_active=is_active,
        )
        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)
        db.session.expunge(user)
        return user


def create_product_with_version(app, owner_id=None, version="1.0.0"):
    with app.app_context():
        product = Product(name="Widget", description="Test product", created_by=owner_id)
        db.session.add(product)
        db.session.commit()

        pv = ProductVersion(product_id=product.id, version=version, release_date=date(2024, 1, 1))
        db.session.add(pv)
        db.session.commit()
        db.session.refresh(product)
        db.session.refresh(pv)
        db.session.expunge(product)
        db.session.expunge(pv)
        return product, pv




def _latest_audit(app, *, action, table_name):
    with app.app_context():
        return (
            AuditLog.query.filter_by(action=action, table_name=table_name)
            .order_by(AuditLog.id.desc())
            .first()
        )
def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True}


def test_auth_register_login_and_me(client):
    register = client.post(
        "/api/auth/register",
        json={"username": "first", "email": "first@example.com", "password": "secret"},
    )
    assert register.status_code == 201
    payload = register.get_json()
    assert payload["user"]["role"] == "Admin"

    login = client.post(
        "/api/auth/login",
        json={"username": "first", "password": "secret"},
    )
    assert login.status_code == 200
    token = login.get_json()["token"]

    email_login = client.post(
        "/api/auth/login",
        json={"username": "first@example.com", "password": "secret"},
    )
    assert email_login.status_code == 200
    assert email_login.get_json()["user"]["username"] == "first"

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.get_json()["username"] == "first"


def test_auth_guard_rails(app, client):
    create_admin(app)

    missing = client.get("/api/products")
    assert missing.status_code == 401

    invalid = client.get("/api/products", headers={"Authorization": "Bearer bad-token"})
    assert invalid.status_code == 401


def test_user_management_endpoints(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    viewer = create_user_direct(app, "view", "view@example.com", role="Viewer")

    forbidden = client.get("/api/users", headers=auth_header(viewer))
    assert forbidden.status_code == 403

    create_resp = client.post(
        "/api/users",
        headers=headers,
        json={"username": "analyst", "email": "analyst@example.com", "password": "secret", "role": "Analyst"},
    )
    assert create_resp.status_code == 201
    analyst_id = create_resp.get_json()["id"]

    invite_resp = client.post(
        "/api/users/invite",
        headers=headers,
        json={"username": "viewer", "email": "viewer@example.com", "role": "Viewer"},
    )
    assert invite_resp.status_code == 201
    invited = invite_resp.get_json()
    assert invited["temp_password"]

    list_resp = client.get("/api/users?search=analyst&role=Analyst&status=active", headers=headers)
    assert list_resp.status_code == 200
    assert any(u["username"] == "analyst" for u in list_resp.get_json())

    invalid_filter = client.get("/api/users?role=Unknown", headers=headers)
    assert invalid_filter.status_code == 400

    detail_resp = client.get(f"/api/users/{analyst_id}", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.get_json()["username"] == "analyst"

    patch_resp = client.patch(
        f"/api/users/{analyst_id}",
        headers=headers,
        json={"email": "new@example.com", "first_name": "Ana", "role": "Viewer", "is_active": False},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.get_json()["email"] == "new@example.com"
    assert patch_resp.get_json()["role"] == "Viewer"
    assert patch_resp.get_json()["is_active"] is False

    reset_resp = client.post(f"/api/users/{analyst_id}/reset-password", headers=headers, json={"password": "newpass"})
    assert reset_resp.status_code == 200

    toggle_resp = client.post(f"/api/users/{analyst_id}/toggle-active", headers=headers)
    assert toggle_resp.status_code == 200
    assert toggle_resp.get_json()["is_active"] is True

    impersonate_resp = client.post(
        f"/api/users/{analyst_id}/impersonate",
        headers=headers,
        json={"reason": "Troubleshooting user issue"},
    )
    assert impersonate_resp.status_code == 200
    assert "token" in impersonate_resp.get_json()

    active_list = client.get("/api/users/active", headers=headers)
    assert active_list.status_code == 200
    assert any(u["username"] == "analyst" for u in active_list.get_json())

    export = client.get("/api/users/export", headers=headers)
    assert export.status_code == 200
    assert "username,email,role" in export.get_data(as_text=True)


def test_product_crud_with_versions(app, client):
    admin = create_admin(app)
    analyst = create_user_direct(app, "analyst", "analyst@example.com")
    headers = auth_header(admin)

    create_resp = client.post(
        "/api/products",
        headers=headers,
        json={"name": "Product A", "description": "Desc"},
    )
    assert create_resp.status_code == 201
    product_id = create_resp.get_json()["id"]

    list_resp = client.get("/api/products", headers=headers)
    assert list_resp.status_code == 200
    assert any(p["name"] == "Product A" for p in list_resp.get_json())

    detail_resp = client.get(f"/api/products/{product_id}", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.get_json()["version_count"] == 0

    invalid_owner = client.patch(
        f"/api/products/{product_id}",
        headers=headers,
        json={"owner_ids": [999]},
    )
    assert invalid_owner.status_code == 400

    patch_resp = client.patch(
        f"/api/products/{product_id}",
        headers=headers,
        json={"name": "Product A+", "description": "Updated", "owner_ids": [analyst.id]},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.get_json()["name"] == "Product A+"
    assert patch_resp.get_json()["owners"][0]["username"] == "analyst"

    bad_version = client.post(
        f"/api/products/{product_id}/versions",
        headers=headers,
        json={"version": " ", "release_date": "not-a-date"},
    )
    assert bad_version.status_code == 400

    version_resp = client.post(
        f"/api/products/{product_id}/versions",
        headers=headers,
        json={"version": "1.0", "release_date": "2024-01-01", "is_active": True},
    )
    assert version_resp.status_code == 201
    version_id = version_resp.get_json()["id"]

    versions = client.get(f"/api/products/{product_id}/versions", headers=headers)
    assert versions.status_code == 200
    assert any(v["version"] == "1.0" for v in versions.get_json())

    invalid_update = client.patch(
        f"/api/products/{product_id}/versions/{version_id}",
        headers=headers,
        json={"release_date": "2024-13-01"},
    )
    assert invalid_update.status_code == 400

    update_resp = client.patch(
        f"/api/products/{product_id}/versions/{version_id}",
        headers=headers,
        json={"version": "1.1", "is_active": False},
    )
    assert update_resp.status_code == 200
    assert update_resp.get_json()["version"] == "1.1"

    delete_version = client.delete(f"/api/products/{product_id}/versions/{version_id}", headers=headers)
    assert delete_version.status_code == 200

    delete_resp = client.delete(f"/api/products/{product_id}", headers=headers)
    assert delete_resp.status_code == 200


def test_vulnerability_endpoints(app, client):
    admin = create_admin(app)
    analyst = create_user_direct(app, "analyst", "analyst@example.com")
    headers = auth_header(admin)

    product, pv1 = create_product_with_version(app, owner_id=admin.id, version="1.0")
    _, pv2 = create_product_with_version(app, owner_id=admin.id, version="2.0")

    product_versions = client.get("/api/product_versions", headers=headers)
    assert product_versions.status_code == 200
    assert any(pv["product_id"] == product.id for pv in product_versions.get_json())

    product_versions_all = client.get("/api/product_versions?include_inactive=true", headers=headers)
    assert product_versions_all.status_code == 200

    create_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={
            "cve_id": "CVE-0001",
            "title": "Example vuln",
            "severity": "High",
            "cvss_score": "not-a-number",
            "published_date": "2024-01-02",
            "last_modified_date": "2024-01-03",
            "status": "Open",
            "assigned_to": analyst.id,
            "affected_versions": [pv1.id],
        },
    )
    assert create_resp.status_code == 201
    vuln_id = create_resp.get_json()["id"]

    list_resp = client.get("/api/vulnerabilities?severity=High&status=Open&search=Example", headers=headers)
    assert list_resp.status_code == 200
    assert list_resp.get_json()["total"] == 1

    detail_resp = client.get(f"/api/vulnerabilities/{vuln_id}", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.get_json()["cve_id"] == "CVE-0001"
    mapping_id = detail_resp.get_json()["affected_versions"][0]["id"]

    invalid_update = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"published_date": "2024-14-01"},
    )
    assert invalid_update.status_code == 400

    update_resp = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"title": "Updated vuln", "cvss_score": 9.9, "severity": "Critical", "status": "In Progress"},
    )
    assert update_resp.status_code == 200

    attach_resp = client.post(
        f"/api/vulnerabilities/{vuln_id}/versions",
        headers=headers,
        json={"product_version_ids": [pv2.id]},
    )
    assert attach_resp.status_code == 200
    assert attach_resp.get_json()["added"] == 1

    patch_mapping = client.patch(
        f"/api/vulnerabilities/{vuln_id}/versions/{mapping_id}",
        headers=headers,
        json={"affected": False, "fixed_in_version": "1.0.1", "notes": "Mitigated"},
    )
    assert patch_mapping.status_code == 200
    assert patch_mapping.get_json()["affected"] is False

    delete_mapping = client.delete(
        f"/api/vulnerabilities/{vuln_id}/versions/{mapping_id}",
        headers=headers,
    )
    assert delete_mapping.status_code == 200

    delete_resp = client.delete(f"/api/vulnerabilities/{vuln_id}", headers=headers)
    assert delete_resp.status_code == 200


def test_vulnerability_list_validation_errors(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    invalid_page = client.get("/api/vulnerabilities?page=abc", headers=headers)
    assert invalid_page.status_code == 400
    assert "page" in invalid_page.get_json()["error"]

    invalid_page_size = client.get("/api/vulnerabilities?page_size=0", headers=headers)
    assert invalid_page_size.status_code == 400
    assert "page_size" in invalid_page_size.get_json()["error"]

    invalid_sort = client.get("/api/vulnerabilities?sort=unknown_field", headers=headers)
    assert invalid_sort.status_code == 400
    assert "sort" in invalid_sort.get_json()["error"]

    invalid_order = client.get("/api/vulnerabilities?order=sideways", headers=headers)
    assert invalid_order.status_code == 400
    assert "order" in invalid_order.get_json()["error"]


def test_controls_endpoints(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    list_empty = client.get("/api/controls", headers=headers)
    assert list_empty.status_code == 200
    assert list_empty.get_json() == []

    invalid_create = client.post("/api/controls", headers=headers, json={"name": " "})
    assert invalid_create.status_code == 400

    create_resp = client.post(
        "/api/controls",
        headers=headers,
        json={"name": "AC-1", "framework": "NIST", "description": "Access control policy"},
    )
    assert create_resp.status_code == 201
    control_id = create_resp.get_json()["id"]

    list_resp = client.get("/api/controls", headers=headers)
    assert list_resp.status_code == 200
    assert any(c["id"] == control_id for c in list_resp.get_json())

    detail_resp = client.get(f"/api/controls/{control_id}", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.get_json()["name"] == "AC-1"

    invalid_patch = client.patch(f"/api/controls/{control_id}", headers=headers, json={"name": ""})
    assert invalid_patch.status_code == 400

    patch_resp = client.patch(
        f"/api/controls/{control_id}",
        headers=headers,
        json={"name": "AC-1 Updated", "framework": "NIST 800-53", "description": "Updated"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.get_json()["framework"] == "NIST 800-53"

    delete_resp = client.delete(f"/api/controls/{control_id}", headers=headers)
    assert delete_resp.status_code == 200


def test_attack_vectors_and_mappings(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)
    product, pv1 = create_product_with_version(app, owner_id=admin.id, version="1.0")

    vuln_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Vector vuln", "severity": "Low", "status": "Open"},
    )
    assert vuln_resp.status_code == 201
    vuln_id = vuln_resp.get_json()["id"]

    invalid_create = client.post("/api/attack_vectors", headers=headers, json={"name": " "})
    assert invalid_create.status_code == 400

    create_resp = client.post(
        "/api/attack_vectors",
        headers=headers,
        json={"name": "Network", "description": "Remote network access"},
    )
    assert create_resp.status_code == 201
    vector_id = create_resp.get_json()["id"]

    list_resp = client.get("/api/attack_vectors", headers=headers)
    assert list_resp.status_code == 200
    assert any(v["id"] == vector_id for v in list_resp.get_json())

    detail_resp = client.get(f"/api/attack_vectors/{vector_id}", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.get_json()["name"] == "Network"

    invalid_mapping = client.post(
        f"/api/vulnerabilities/{vuln_id}/attack_vectors",
        headers=headers,
        json={"mappings": [{}]},
    )
    assert invalid_mapping.status_code == 400

    mapping_resp = client.post(
        f"/api/vulnerabilities/{vuln_id}/attack_vectors",
        headers=headers,
        json={"mappings": [{"attack_vector_id": vector_id, "product_version_id": pv1.id}]},
    )
    assert mapping_resp.status_code == 200
    assert mapping_resp.get_json()["added"] == 1

    mappings = client.get(f"/api/vulnerabilities/{vuln_id}/attack_vectors", headers=headers)
    assert mappings.status_code == 200
    mapping_id = mappings.get_json()[0]["id"]

    second_resp = client.post(
        "/api/attack_vectors",
        headers=headers,
        json={"name": "Local", "description": "Local access"},
    )
    assert second_resp.status_code == 201
    second_id = second_resp.get_json()["id"]

    patch_resp = client.patch(
        f"/api/vulnerabilities/{vuln_id}/attack_vectors/{mapping_id}",
        headers=headers,
        json={"attack_vector_id": second_id, "product_version_id": None},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.get_json()["attack_vector_id"] == second_id
    assert patch_resp.get_json()["product_version_id"] is None

    delete_mapping = client.delete(
        f"/api/vulnerabilities/{vuln_id}/attack_vectors/{mapping_id}",
        headers=headers,
    )
    assert delete_mapping.status_code == 200

    delete_resp = client.delete(f"/api/attack_vectors/{vector_id}", headers=headers)
    assert delete_resp.status_code == 200


def test_terminal_impacts_and_mappings(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    vuln_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Impact vuln", "severity": "Medium", "status": "Open"},
    )
    assert vuln_resp.status_code == 201
    vuln_id = vuln_resp.get_json()["id"]

    invalid_create = client.post("/api/terminal_impacts", headers=headers, json={"name": ""})
    assert invalid_create.status_code == 400

    create_resp = client.post(
        "/api/terminal_impacts",
        headers=headers,
        json={"name": "Data Loss", "description": "Sensitive data loss"},
    )
    assert create_resp.status_code == 201
    impact_id = create_resp.get_json()["id"]

    list_resp = client.get("/api/terminal_impacts", headers=headers)
    assert list_resp.status_code == 200
    assert any(i["id"] == impact_id for i in list_resp.get_json())

    detail_resp = client.get(f"/api/terminal_impacts/{impact_id}", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.get_json()["name"] == "Data Loss"

    invalid_attach = client.post(
        f"/api/vulnerabilities/{vuln_id}/terminal_impacts",
        headers=headers,
        json={"terminal_impact_ids": [None]},
    )
    assert invalid_attach.status_code == 400

    attach_resp = client.post(
        f"/api/vulnerabilities/{vuln_id}/terminal_impacts",
        headers=headers,
        json={"terminal_impact_ids": [impact_id]},
    )
    assert attach_resp.status_code == 200
    assert attach_resp.get_json()["added"] == 1

    mappings = client.get(f"/api/vulnerabilities/{vuln_id}/terminal_impacts", headers=headers)
    assert mappings.status_code == 200
    mapping_id = mappings.get_json()[0]["id"]

    second_resp = client.post(
        "/api/terminal_impacts",
        headers=headers,
        json={"name": "Service Disruption", "description": "Availability loss"},
    )
    assert second_resp.status_code == 201
    second_id = second_resp.get_json()["id"]

    patch_resp = client.patch(
        f"/api/vulnerabilities/{vuln_id}/terminal_impacts/{mapping_id}",
        headers=headers,
        json={"terminal_impact_id": second_id},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.get_json()["terminal_impact_id"] == second_id

    delete_mapping = client.delete(
        f"/api/vulnerabilities/{vuln_id}/terminal_impacts/{mapping_id}",
        headers=headers,
    )
    assert delete_mapping.status_code == 200

    delete_resp = client.delete(f"/api/terminal_impacts/{impact_id}", headers=headers)
    assert delete_resp.status_code == 200


def test_plugin_endpoints(app, client, monkeypatch):
    admin = create_admin(app)
    headers = auth_header(admin)

    plugins_resp = client.get("/api/plugins", headers=headers)
    assert plugins_resp.status_code == 200
    plugins = plugins_resp.get_json()
    expected_schemas = {
        "slack": {"webhook_url"},
        "jira": {"base_url"},
        "vuln-feed-nvd": {"feed_url"},
        "vuln-feed-exploitdb": {"feed_url"},
        "controls-import-cis": {"file_path"},
        "controls-import-pci-dss": {"file_path"},
        "controls-import-stig": {"file_path"},
    }

    def _schema_field_names(schema):
        fields = schema.get("fields", schema)
        if isinstance(fields, dict):
            return set(fields.keys())
        return {entry.get("name") for entry in fields if isinstance(entry, dict) and entry.get("name")}

    for plugin_id, required_fields in expected_schemas.items():
        plugin = next((item for item in plugins if item["plugin_id"] == plugin_id), None)
        assert plugin is not None
        field_names = _schema_field_names(plugin.get("config_schema") or {})
        assert required_fields.issubset(field_names)

    configs_resp = client.get("/api/plugins/configs", headers=headers)
    assert configs_resp.status_code == 200
    assert configs_resp.get_json() == []

    get_resp = client.get("/api/plugins/slack", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.get_json()["plugin_id"] == "slack"

    missing_resp = client.get("/api/plugins/missing", headers=headers)
    assert missing_resp.status_code == 404


def test_plugin_run_enqueue_behavior(app, client, monkeypatch):
    admin = create_admin(app)
    headers = auth_header(admin)

    submitted = {}

    class FakeExecutor:
        def submit(self, fn, *args, **kwargs):
            submitted["fn"] = fn
            submitted["args"] = args
            submitted["kwargs"] = kwargs
            return object()

    monkeypatch.setattr("backend.plugins.runner.get_plugin_run_executor", lambda: FakeExecutor())

    run_resp = client.post(
        "/api/plugins/slack/run",
        headers=headers,
        json={"config": {"webhook_url": "https://example.com/webhook"}},
    )
    assert run_resp.status_code == 202
    run_payload = run_resp.get_json()
    assert run_payload["status"] == "running"
    assert run_payload["finished_at"] is None
    assert submitted["kwargs"]["run_id"] == run_payload["id"]
    assert submitted["kwargs"]["plugin_id"] == "slack"


def test_plugin_run_status_transition_success_and_status_endpoint(app, client, monkeypatch):
    from backend.services.slack_alerts import SlackWebhookClient

    admin = create_admin(app)
    headers = auth_header(admin)

    def fake_send_message(self, *, text, channel=None, username=None, icon_emoji=None, blocks=None):
        return None

    class ImmediateExecutor:
        def submit(self, fn, *args, **kwargs):
            fn(*args, **kwargs)
            return object()

    monkeypatch.setattr(SlackWebhookClient, "send_message", fake_send_message)
    monkeypatch.setattr("backend.plugins.runner.get_plugin_run_executor", lambda: ImmediateExecutor())

    run_resp = client.post(
        "/api/plugins/slack/run",
        headers=headers,
        json={"config": {"webhook_url": "https://example.com/webhook"}},
    )
    assert run_resp.status_code == 202
    run_id = run_resp.get_json()["id"]

    payload = None
    for _ in range(5):
        status_resp = client.get(f"/api/plugins/runs/{run_id}", headers=headers)
        assert status_resp.status_code == 200
        payload = status_resp.get_json()
        if payload["status"] != "running":
            break

    assert payload is not None
    assert payload["id"] == run_id
    assert payload["plugin_id"] == "slack"
    assert payload["status"] == "success"
    assert payload["stats"]["sent"] == 1
    assert payload["stats"]["failed"] == 0


def test_plugin_run_records_failure(app, client, monkeypatch):
    from backend.services.slack_alerts import SlackWebhookClient, SlackWebhookError

    admin = create_admin(app)
    headers = auth_header(admin)

    def fake_send_message(self, *, text, channel=None, username=None, icon_emoji=None, blocks=None):
        raise SlackWebhookError("boom")

    class ImmediateExecutor:
        def submit(self, fn, *args, **kwargs):
            fn(*args, **kwargs)
            return object()

    monkeypatch.setattr(SlackWebhookClient, "send_message", fake_send_message)
    monkeypatch.setattr("backend.plugins.runner.get_plugin_run_executor", lambda: ImmediateExecutor())

    run_resp = client.post(
        "/api/plugins/slack/run",
        headers=headers,
        json={"config": {"webhook_url": "https://example.com/webhook"}},
    )
    assert run_resp.status_code == 202
    run_id = run_resp.get_json()["id"]

    run_payload = None
    for _ in range(5):
        status_resp = client.get(f"/api/plugins/runs/{run_id}", headers=headers)
        assert status_resp.status_code == 200
        run_payload = status_resp.get_json()
        if run_payload["status"] != "running":
            break

    assert run_payload is not None
    assert run_payload["status"] == "failed"
    assert run_payload["error"]


def test_plugin_run_status_endpoint_not_found(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    status_resp = client.get("/api/plugins/runs/99999", headers=headers)
    assert status_resp.status_code == 404
    assert status_resp.get_json()["error"] == "Plugin run not found"


def test_vulnerability_create_emits_audit_log(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Audit vuln", "severity": "Low", "status": "Open"},
    )
    assert resp.status_code == 201
    vuln_id = resp.get_json()["id"]

    log = _latest_audit(app, action="CREATE", table_name="vulnerabilities")
    assert log is not None
    assert log.user_id == admin.id
    assert log.record_id == vuln_id
    assert log.new_values["title"] == "Audit vuln"


def test_product_update_emits_audit_log(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    create_resp = client.post("/api/products", headers=headers, json={"name": "Prod A", "description": "old"})
    assert create_resp.status_code == 201
    product_id = create_resp.get_json()["id"]

    update_resp = client.patch(
        f"/api/products/{product_id}",
        headers=headers,
        json={"description": "new"},
    )
    assert update_resp.status_code == 200

    log = _latest_audit(app, action="UPDATE", table_name="products")
    assert log is not None
    assert log.record_id == product_id
    assert log.old_values["description"] == "old"
    assert log.new_values["description"] == "new"


def test_plugin_config_update_emits_scrubbed_audit_log(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    resp = client.post(
        "/api/plugins/slack/config",
        headers=headers,
        json={"enabled": True, "config": {"webhook_url": "https://example.local/secret", "default_channel": "#sec"}},
    )
    assert resp.status_code == 200

    log = _latest_audit(app, action="UPDATE", table_name="plugin_configs")
    assert log is not None
    assert log.user_id == admin.id
    assert log.new_values["config"]["webhook_url"] == "***"
    assert log.new_values["config"]["default_channel"] == "#sec"


def test_control_delete_emits_audit_log(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    create_resp = client.post(
        "/api/controls",
        headers=headers,
        json={"name": "AU-1", "framework": "NIST"},
    )
    assert create_resp.status_code == 201
    control_id = create_resp.get_json()["id"]

    delete_resp = client.delete(f"/api/controls/{control_id}", headers=headers)
    assert delete_resp.status_code == 200

    log = _latest_audit(app, action="DELETE", table_name="controls")
    assert log is not None
    assert log.record_id == control_id
    assert log.old_values["name"] == "AU-1"
