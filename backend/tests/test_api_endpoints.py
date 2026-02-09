from datetime import date, datetime, timedelta
import json

from backend.auth import create_user, generate_token, hash_password
from backend.database import db
from backend.models import (
    AuditLog,
    ComponentDependency,
    Product,
    ProductVersion,
    SoftwareComponent,
    User,
    Vulnerability,
    VulnerabilityComponent,
    VulnerabilityVersion,
    VulnerabilityComment,
    VulnerabilityWatcher,
)


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


def test_cookie_authenticated_write_requires_csrf_header(app, client):
    create_admin(app)

    login = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    assert login.status_code == 200
    csrf_token = login.get_json()["csrf_token"]

    missing = client.post("/api/products", json={"name": "csrf-product"})
    assert missing.status_code == 403
    assert missing.get_json()["error"] == "CSRF validation failed"

    allowed = client.post(
        "/api/products",
        headers={"X-CSRF-Token": csrf_token},
        json={"name": "csrf-product"},
    )
    assert allowed.status_code == 201


def test_bearer_authenticated_write_does_not_require_csrf(app, client):
    admin = create_admin(app)

    response = client.post(
        "/api/products",
        headers=auth_header(admin),
        json={"name": "bearer-product"},
    )
    assert response.status_code == 201


def test_scope_enforcement_for_newly_scoped_endpoints(app, client):
    admin = create_admin(app)
    analyst = create_user_direct(app, "analyst_scope", "analyst_scope@example.com", role="Analyst")
    viewer = create_user_direct(app, "viewer_scope", "viewer_scope@example.com", role="Viewer")

    for endpoint in (
        "/api/plugins",
        "/api/controls",
        "/api/attack_vectors",
        "/api/terminal_impacts",
    ):
        admin_read = client.get(endpoint, headers=auth_header(admin))
        assert admin_read.status_code == 200

        analyst_read = client.get(endpoint, headers=auth_header(analyst))
        assert analyst_read.status_code == 200

        viewer_read = client.get(endpoint, headers=auth_header(viewer))
        assert viewer_read.status_code == 200

    analyst_plugin_write = client.post(
        "/api/plugins/slack/config",
        headers=auth_header(analyst),
        json={"enabled": True, "config": {"webhook_url": "https://example.local/test"}},
    )
    assert analyst_plugin_write.status_code == 200

    viewer_plugin_write = client.post(
        "/api/plugins/slack/config",
        headers=auth_header(viewer),
        json={"enabled": True, "config": {"webhook_url": "https://example.local/test"}},
    )
    assert viewer_plugin_write.status_code == 403

    analyst_control_write = client.post(
        "/api/controls",
        headers=auth_header(analyst),
        json={"name": "SC-1", "framework": "NIST"},
    )
    assert analyst_control_write.status_code == 201

    viewer_control_write = client.post(
        "/api/controls",
        headers=auth_header(viewer),
        json={"name": "SC-2", "framework": "NIST"},
    )
    assert viewer_control_write.status_code == 403

    analyst_vector_write = client.post(
        "/api/attack_vectors",
        headers=auth_header(analyst),
        json={"name": "Scope Vector", "description": "test"},
    )
    assert analyst_vector_write.status_code == 201

    viewer_vector_write = client.post(
        "/api/attack_vectors",
        headers=auth_header(viewer),
        json={"name": "Viewer Vector", "description": "test"},
    )
    assert viewer_vector_write.status_code == 403

    analyst_impact_write = client.post(
        "/api/terminal_impacts",
        headers=auth_header(analyst),
        json={"name": "Scope Impact", "description": "test"},
    )
    assert analyst_impact_write.status_code == 201

    viewer_impact_write = client.post(
        "/api/terminal_impacts",
        headers=auth_header(viewer),
        json={"name": "Viewer Impact", "description": "test"},
    )
    assert viewer_impact_write.status_code == 403


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

    reset_log = _latest_audit(app, action="RESET_PASSWORD", table_name="users")
    assert reset_log is not None
    assert reset_log.record_id == analyst_id
    assert reset_log.old_values == {"password_reset": True}
    assert reset_log.new_values is None
    assert "password_hash" not in json.dumps(reset_log.old_values)

    audit_resp = client.get("/api/audit-logs?action=RESET_PASSWORD&table=users", headers=headers)
    assert audit_resp.status_code == 200
    reset_entry = audit_resp.get_json()[0]
    assert reset_entry["old_values"] == {"password_reset": True}
    assert reset_entry["new_values"] is None
    assert "password_hash" not in json.dumps(reset_entry)

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
            "cve_id": "CVE-2024-0001",
            "title": "Example vuln",
            "severity": "High",
            "cvss_score": 7.2,
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
    assert detail_resp.get_json()["cve_id"] == "CVE-2024-0001"
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

    activity_resp = client.get(f"/api/vulnerabilities/{vuln_id}/activity", headers=headers)
    assert activity_resp.status_code == 200
    activity_payload = activity_resp.get_json()
    assert any(event["table_name"] == "vulnerabilities" for event in activity_payload)

    delete_resp = client.delete(f"/api/vulnerabilities/{vuln_id}", headers=headers)
    assert delete_resp.status_code == 200



def test_vulnerability_batch_update_mutation(app, client):
    admin = create_admin(app)
    analyst = create_user_direct(app, "batch-analyst", "batch-analyst@example.com")
    headers = auth_header(admin)

    vuln_ids = []
    for idx in range(2):
        resp = client.post(
            "/api/vulnerabilities",
            headers=headers,
            json={
                "title": f"Batch vuln {idx}",
                "severity": "Medium",
                "status": "Open",
            },
        )
        assert resp.status_code == 201
        vuln_ids.append(resp.get_json()["id"])

    update_resp = client.patch(
        "/api/vulnerabilities/batch",
        headers=headers,
        json={
            "vulnerability_ids": vuln_ids,
            "status": "Resolved",
            "severity": "High",
            "assigned_to": analyst.id,
            "sla_due_at": "2026-01-01T08:30:00",
        },
    )
    assert update_resp.status_code == 200
    payload = update_resp.get_json()
    assert payload["updated_count"] == 2
    assert payload["missing_count"] == 0
    assert payload["skipped_count"] == 0

    detail = client.get(f"/api/vulnerabilities/{vuln_ids[0]}", headers=headers)
    assert detail.status_code == 200
    detail_json = detail.get_json()
    assert detail_json["status"] == "Resolved"
    assert detail_json["severity"] == "High"
    assert detail_json["assigned_to"] == analyst.id
    assert detail_json["sla_due_at"].startswith("2026-01-01T08:30:00")

    log = _latest_audit(app, action="BATCH_UPDATE", table_name="vulnerabilities")
    assert log is not None
    assert log.record_id in vuln_ids
    assert "field_diff" in (log.new_values or {})


def test_vulnerability_batch_update_validation_and_missing(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    create_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Validation batch vuln", "severity": "Low", "status": "Open"},
    )
    assert create_resp.status_code == 201
    vuln_id = create_resp.get_json()["id"]

    invalid_resp = client.patch(
        "/api/vulnerabilities/batch",
        headers=headers,
        json={"vulnerability_ids": [vuln_id], "status": "Bad Status"},
    )
    assert invalid_resp.status_code == 400

    partial_resp = client.patch(
        "/api/vulnerabilities/batch",
        headers=headers,
        json={"vulnerability_ids": [vuln_id, 999999], "status": "Closed"},
    )
    assert partial_resp.status_code == 200
    partial_json = partial_resp.get_json()
    assert partial_json["updated_count"] == 1
    assert partial_json["missing_count"] == 1


def test_vulnerability_merge_candidates_and_merge_flow(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)
    _, pv = create_product_with_version(app, owner_id=admin.id, version="3.0")

    create_target = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={
            "cve_id": "CVE-2024-9000",
            "title": "SQL Injection in Widget Service",
            "severity": "High",
            "affected_versions": [pv.id],
        },
    )
    assert create_target.status_code == 201
    target_id = create_target.get_json()["id"]

    create_source = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={
            "title": "SQL injection in widget-service",
            "severity": "High",
            "affected_versions": [pv.id],
        },
    )
    assert create_source.status_code == 201
    source_id = create_source.get_json()["id"]

    with app.app_context():
        component = SoftwareComponent(
            product_version_id=pv.id,
            name="widget-core",
            version="1.0.0",
            ecosystem="pypi",
        )
        db.session.add(component)
        db.session.flush()
        db.session.add(VulnerabilityComponent(vulnerability_id=source_id, component_id=component.id, source="manual", match_type="direct"))
        db.session.add(VulnerabilityComment(vulnerability_id=source_id, author_id=admin.id, body="dedup me"))
        db.session.add(VulnerabilityWatcher(vulnerability_id=source_id, user_id=admin.id, added_by=admin.id))
        db.session.commit()

    candidates = client.get(f"/api/vulnerabilities/{target_id}/merge_candidates", headers=headers)
    assert candidates.status_code == 200
    items = candidates.get_json()["items"]
    assert any(item["candidate"]["id"] == source_id for item in items)

    merge_resp = client.post(
        f"/api/vulnerabilities/{target_id}/merge",
        headers=headers,
        json={"source_vulnerability_id": source_id, "reason": "duplicate ingest"},
    )
    assert merge_resp.status_code == 200

    target_detail = client.get(f"/api/vulnerabilities/{target_id}", headers=headers)
    assert target_detail.status_code == 200
    target_payload = target_detail.get_json()
    assert target_payload["is_merged"] is False
    assert any(component["name"] == "widget-core" for component in target_payload["affected_components"])

    source_detail = client.get(f"/api/vulnerabilities/{source_id}", headers=headers)
    assert source_detail.status_code == 200
    source_payload = source_detail.get_json()
    assert source_payload["is_merged"] is True
    assert source_payload["merged_into_id"] == target_id

    comments = client.get(f"/api/vulnerabilities/{target_id}/comments", headers=headers)
    assert comments.status_code == 200
    assert any(comment["body"] == "dedup me" for comment in comments.get_json())


def test_vulnerability_rejects_invalid_cve_id(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    create_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Bad CVE", "cve_id": "cve-123"},
    )
    assert create_resp.status_code == 400
    assert create_resp.get_json()["field"] == "cve_id"

    valid_create = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Good CVE", "cve_id": "CVE-2024-1111"},
    )
    assert valid_create.status_code == 201
    vuln_id = valid_create.get_json()["id"]

    update_resp = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"cve_id": "bad-id"},
    )
    assert update_resp.status_code == 400
    assert update_resp.get_json()["field"] == "cve_id"


def test_vulnerability_cvss_validation_rejects_non_numeric(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    create_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Bad CVSS Create", "cvss_score": "not-a-number"},
    )
    assert create_resp.status_code == 400
    assert create_resp.get_json()["field"] == "cvss_score"

    valid_create = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Valid CVSS Base", "cvss_score": 5.0},
    )
    assert valid_create.status_code == 201
    vuln_id = valid_create.get_json()["id"]

    update_resp = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"cvss_score": "not-a-number"},
    )
    assert update_resp.status_code == 400
    assert update_resp.get_json()["field"] == "cvss_score"


def test_vulnerability_cvss_validation_rejects_out_of_range(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    create_low = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Low CVSS", "cvss_score": -0.1},
    )
    assert create_low.status_code == 400
    assert create_low.get_json()["field"] == "cvss_score"

    create_high = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "High CVSS", "cvss_score": 10.1},
    )
    assert create_high.status_code == 400
    assert create_high.get_json()["field"] == "cvss_score"

    valid_create = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Range Base", "cvss_score": 5.0},
    )
    assert valid_create.status_code == 201
    vuln_id = valid_create.get_json()["id"]

    update_low = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"cvss_score": -1},
    )
    assert update_low.status_code == 400
    assert update_low.get_json()["field"] == "cvss_score"

    update_high = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"cvss_score": 11},
    )
    assert update_high.status_code == 400
    assert update_high.get_json()["field"] == "cvss_score"


def test_vulnerability_rejects_invalid_severity_status_enums(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    invalid_create_severity = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Bad Severity", "severity": "Severe"},
    )
    assert invalid_create_severity.status_code == 400
    assert invalid_create_severity.get_json()["field"] == "severity"

    invalid_create_status = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Bad Status", "status": "Doing"},
    )
    assert invalid_create_status.status_code == 400
    assert invalid_create_status.get_json()["field"] == "status"

    valid_create = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Enum Base", "severity": "High", "status": "Open"},
    )
    assert valid_create.status_code == 201
    vuln_id = valid_create.get_json()["id"]

    invalid_update_severity = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"severity": "Super High"},
    )
    assert invalid_update_severity.status_code == 400
    assert invalid_update_severity.get_json()["field"] == "severity"

    invalid_update_status = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"status": "Working"},
    )
    assert invalid_update_status.status_code == 400
    assert invalid_update_status.get_json()["field"] == "status"


def test_vulnerability_assigned_to_validation(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    invalid_create_assignee_type = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Bad Assignee Type", "assigned_to": "abc"},
    )
    assert invalid_create_assignee_type.status_code == 400
    assert invalid_create_assignee_type.get_json()["field"] == "assigned_to"

    invalid_create_assignee_missing = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Bad Assignee Missing", "assigned_to": 999999},
    )
    assert invalid_create_assignee_missing.status_code == 400
    assert invalid_create_assignee_missing.get_json()["field"] == "assigned_to"

    valid_create = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Assigned Base"},
    )
    assert valid_create.status_code == 201
    vuln_id = valid_create.get_json()["id"]

    invalid_update_assignee_type = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"assigned_to": 0},
    )
    assert invalid_update_assignee_type.status_code == 400
    assert invalid_update_assignee_type.get_json()["field"] == "assigned_to"

    invalid_update_assignee_missing = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"assigned_to": 999999},
    )
    assert invalid_update_assignee_missing.status_code == 400
    assert invalid_update_assignee_missing.get_json()["field"] == "assigned_to"

def test_vulnerability_cvss_validation_accepts_edge_values(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    create_zero = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Zero CVSS", "cvss_score": 0.0},
    )
    assert create_zero.status_code == 201
    zero_id = create_zero.get_json()["id"]

    zero_detail = client.get(f"/api/vulnerabilities/{zero_id}", headers=headers)
    assert zero_detail.status_code == 200
    assert zero_detail.get_json()["cvss_score"] == 0.0

    create_ten = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Ten CVSS", "cvss_score": 10.0},
    )
    assert create_ten.status_code == 201
    ten_id = create_ten.get_json()["id"]

    ten_detail = client.get(f"/api/vulnerabilities/{ten_id}", headers=headers)
    assert ten_detail.status_code == 200
    assert ten_detail.get_json()["cvss_score"] == 10.0

    update_zero = client.put(
        f"/api/vulnerabilities/{ten_id}",
        headers=headers,
        json={"cvss_score": 0.0},
    )
    assert update_zero.status_code == 200

    update_ten = client.put(
        f"/api/vulnerabilities/{zero_id}",
        headers=headers,
        json={"cvss_score": 10.0},
    )
    assert update_ten.status_code == 200

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




def test_uniform_validation_error_shape(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    invalid_login = client.post("/api/auth/login", json={"username": "admin"})
    assert invalid_login.status_code == 400
    login_payload = invalid_login.get_json()
    assert login_payload["error"] == "password is required"
    assert login_payload["field"] == "password"
    assert login_payload["details"] is None
    assert login_payload["status"] == 400

    invalid_page = client.get("/api/vulnerabilities?page=abc", headers=headers)
    assert invalid_page.status_code == 400
    page_payload = invalid_page.get_json()
    assert page_payload["field"] == "page"
    assert page_payload["status"] == 400

    invalid_schedule = client.post(
        "/api/reports/schedules",
        headers=headers,
        json={
            "name": "bad",
            "report_type": "invalid",
            "frequency": "daily",
            "delivery_channel": "email",
            "recipient": "a@example.com",
        },
    )
    assert invalid_schedule.status_code == 400
    schedule_payload = invalid_schedule.get_json()
    assert schedule_payload["field"] == "report_type"
    assert sorted(schedule_payload["details"]["allowed"]) == ["dashboard_summary", "vulnerabilities"]
    assert schedule_payload["status"] == 400

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




def test_plugin_import_sources_and_validation(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    app.config["PLUGIN_IMPORT_PATHS"] = ["backend.tests"]

    sources_resp = client.get("/api/plugins/import/sources", headers=headers)
    assert sources_resp.status_code == 200
    assert "backend.tests" in sources_resp.get_json()["paths"]

    validate_resp = client.post(
        "/api/plugins/import/validate",
        headers=headers,
        json={"module_path": "backend.tests.sample_import_plugin", "class_name": "SampleImportPlugin"},
    )
    assert validate_resp.status_code == 200
    payload = validate_resp.get_json()
    assert payload["plugin_id"] == "sample-import-plugin"
    assert "controls_import" in payload["capabilities"]
    assert payload["already_registered"] is False


def test_plugin_import_registers_plugin_and_config(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    app.config["PLUGIN_IMPORT_PATHS"] = ["backend.tests"]

    register_resp = client.post(
        "/api/plugins/import/register",
        headers=headers,
        json={
            "module_path": "backend.tests.sample_import_plugin",
            "class_name": "SampleImportPlugin",
            "enabled": True,
            "config": {"file_path": "/tmp/sample.json", "dry_run": True},
        },
    )
    assert register_resp.status_code == 201
    register_payload = register_resp.get_json()
    assert register_payload["plugin"]["plugin_id"] == "sample-import-plugin"
    assert register_payload["config"]["enabled"] is True

    plugins_resp = client.get("/api/plugins", headers=headers)
    assert plugins_resp.status_code == 200
    plugin_ids = {item["plugin_id"] for item in plugins_resp.get_json()}
    assert "sample-import-plugin" in plugin_ids


def test_plugin_import_rejects_disallowed_module_path(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    app.config["PLUGIN_IMPORT_PATHS"] = ["backend.tests.allowed"]

    validate_resp = client.post(
        "/api/plugins/import/validate",
        headers=headers,
        json={"module_path": "backend.tests.sample_import_plugin", "class_name": "SampleImportPlugin"},
    )
    assert validate_resp.status_code == 400
    assert "PLUGIN_IMPORT_PATHS" in validate_resp.get_json()["error"]

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
    for key in ["severity", "status", "cvss_score", "assigned_to", "sla_due_at"]:
        assert key in log.new_values


def test_vulnerability_update_emits_full_audit_snapshot(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    create_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Update audit vuln", "severity": "Low", "status": "Open"},
    )
    assert create_resp.status_code == 201
    vuln_id = create_resp.get_json()["id"]

    update_resp = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"severity": "High", "status": "In Progress"},
    )
    assert update_resp.status_code == 200

    log = _latest_audit(app, action="UPDATE", table_name="vulnerabilities")
    assert log is not None
    assert log.record_id == vuln_id
    for key in ["severity", "status", "cvss_score", "assigned_to", "sla_due_at"]:
        assert key in log.old_values
        assert key in log.new_values

    field_diff = log.new_values["field_diff"]
    assert field_diff["severity"] == {"before": "Low", "after": "High"}
    assert field_diff["status"] == {"before": "Open", "after": "In Progress"}
    assert "cvss_score" not in field_diff
    assert "assigned_to" not in field_diff


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


def test_notification_rule_crud_and_test_send(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    vuln_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Notif Seed", "severity": "High", "status": "Open"},
    )
    assert vuln_resp.status_code == 201

    create_resp = client.post(
        "/api/notification-rules",
        headers=headers,
        json={
            "name": "High severity changes",
            "delivery_adapter": "slack",
            "severity_threshold": "Medium",
            "is_enabled": True,
            "notify_on_status_change": True,
            "notify_on_assignment_change": True,
            "delivery_config": {"webhook_url": "https://example.invalid"},
            "product_scope": [],
        },
    )
    assert create_resp.status_code == 201
    rule_id = create_resp.get_json()["id"]

    list_resp = client.get("/api/notification-rules", headers=headers)
    assert list_resp.status_code == 200
    assert any(r["id"] == rule_id for r in list_resp.get_json())

    update_resp = client.put(
        f"/api/notification-rules/{rule_id}",
        headers=headers,
        json={"name": "Updated name", "severity_threshold": "High"},
    )
    assert update_resp.status_code == 200
    assert update_resp.get_json()["name"] == "Updated name"

    test_resp = client.post(f"/api/notification-rules/{rule_id}/test-send", headers=headers)
    assert test_resp.status_code == 200

    log_resp = client.get("/api/notification-delivery-logs", headers=headers)
    assert log_resp.status_code == 200
    assert any(log["rule_id"] == rule_id for log in log_resp.get_json())


def test_notification_trigger_on_vulnerability_status_change(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    rule_resp = client.post(
        "/api/notification-rules",
        headers=headers,
        json={
            "name": "status only",
            "delivery_adapter": "slack",
            "severity_threshold": "Low",
            "notify_on_status_change": True,
            "notify_on_assignment_change": False,
            "delivery_config": {"webhook_url": "https://example.invalid"},
        },
    )
    assert rule_resp.status_code == 201

    vuln_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Status change target", "severity": "High", "status": "Open"},
    )
    assert vuln_resp.status_code == 201
    vuln_id = vuln_resp.get_json()["id"]

    update_resp = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"status": "Resolved"},
    )
    assert update_resp.status_code == 200

    logs_resp = client.get("/api/notification-delivery-logs", headers=headers)
    assert logs_resp.status_code == 200
    logs = logs_resp.get_json()
    assert any(log["vulnerability_id"] == vuln_id and log["event_type"] == "status_change" for log in logs)


def test_notification_delivery_attempts_list_retry_and_replay(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    vuln_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Delivery retry target", "severity": "High", "status": "Open"},
    )
    assert vuln_resp.status_code == 201
    vuln_id = vuln_resp.get_json()["id"]

    rule_resp = client.post(
        "/api/notification-rules",
        headers=headers,
        json={
            "name": "retryable rule",
            "delivery_adapter": "webhook",
            "severity_threshold": "Low",
            "notify_on_status_change": True,
            "notify_on_assignment_change": True,
            "delivery_config": {"webhook_url": "http://127.0.0.1:9/nope"},
        },
    )
    assert rule_resp.status_code == 201

    trigger_resp = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"status": "In Progress"},
    )
    assert trigger_resp.status_code == 200

    attempts_resp = client.get("/api/notification-delivery-attempts?limit=20&failed_only=true", headers=headers)
    assert attempts_resp.status_code == 200
    attempts = attempts_resp.get_json()
    assert attempts
    attempt = attempts[0]
    assert attempt["status"] == "failed"
    assert attempt["channel"] == "webhook"
    assert isinstance(attempt["retry_count"], int)

    retry_resp = client.post(f"/api/notification-delivery-attempts/{attempt['id']}/retry", headers=headers)
    assert retry_resp.status_code == 200
    assert retry_resp.get_json()["ok"] is True

    replay_resp = client.post(f"/api/notification-delivery-attempts/{attempt['id']}/replay", headers=headers)
    assert replay_resp.status_code == 200
    assert replay_resp.get_json()["ok"] is True

    retry_audit = _latest_audit(app, action="RETRY_NOTIFICATION_DELIVERY", table_name="notification_delivery_logs")
    assert retry_audit is not None
    assert retry_audit.record_id == attempt["id"]

    replay_audit = _latest_audit(app, action="REPLAY_NOTIFICATION_DELIVERY", table_name="notification_delivery_logs")
    assert replay_audit is not None
    assert replay_audit.record_id == attempt["id"]


def test_saved_vulnerability_filters_crud_and_visibility(app, client):
    admin = create_admin(app)
    analyst = create_user_direct(app, "analyst_filters", "analyst_filters@example.com", role="Analyst")
    viewer = create_user_direct(app, "viewer_filters", "viewer_filters@example.com", role="Viewer")

    analyst_headers = auth_header(analyst)
    viewer_headers = auth_header(viewer)
    admin_headers = auth_header(admin)

    create_private = client.post(
        "/api/vulnerabilities/filters",
        headers=analyst_headers,
        json={
            "name": "My Open High",
            "filter_json": {"status": "Open", "severity": "High"},
            "visibility": "private",
            "is_default": True,
        },
    )
    assert create_private.status_code == 201
    private_id = create_private.get_json()["id"]

    create_shared = client.post(
        "/api/vulnerabilities/filters",
        headers=analyst_headers,
        json={
            "name": "Team Open",
            "filter_json": {"status": "Open"},
            "visibility": "shared",
        },
    )
    assert create_shared.status_code == 201
    shared_id = create_shared.get_json()["id"]

    viewer_create_shared = client.post(
        "/api/vulnerabilities/filters",
        headers=viewer_headers,
        json={
            "name": "Viewer Shared",
            "filter_json": {"status": "Open"},
            "visibility": "shared",
        },
    )
    assert viewer_create_shared.status_code == 403

    viewer_list = client.get("/api/vulnerabilities/filters", headers=viewer_headers)
    assert viewer_list.status_code == 200
    viewer_ids = {item["id"] for item in viewer_list.get_json()}
    assert shared_id in viewer_ids
    assert private_id not in viewer_ids

    default_resp = client.get("/api/vulnerabilities/filters/default", headers=analyst_headers)
    assert default_resp.status_code == 200
    assert default_resp.get_json()["default"]["id"] == private_id

    viewer_set_default = client.put(
        f"/api/vulnerabilities/filters/{shared_id}",
        headers=viewer_headers,
        json={"is_default": True},
    )
    assert viewer_set_default.status_code == 403

    admin_set_default = client.put(
        f"/api/vulnerabilities/filters/{shared_id}",
        headers=admin_headers,
        json={"is_default": True},
    )
    assert admin_set_default.status_code == 200

    default_resp_after = client.get("/api/vulnerabilities/filters/default", headers=analyst_headers)
    assert default_resp_after.status_code == 200
    assert default_resp_after.get_json()["default"]["id"] == shared_id

    delete_resp = client.delete(f"/api/vulnerabilities/filters/{private_id}", headers=analyst_headers)
    assert delete_resp.status_code == 204


def test_sla_policy_and_vulnerability_due_dates(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)
    product, pv = create_product_with_version(app, owner_id=admin.id)

    update_policy_resp = client.put(
        "/api/sla_policy",
        headers=headers,
        json={
            "global": {"Critical": 10, "High": 20, "Medium": 30, "Low": 40, "None": 50},
            "overrides": [{"product_id": product.id, "severity": "Critical", "days": 2}],
            "due_soon_days": 3,
        },
    )
    assert update_policy_resp.status_code == 200
    assert update_policy_resp.get_json()["global"]["Critical"] == 10

    create_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={
            "title": "Critical vuln",
            "severity": "Critical",
            "affected_versions": [pv.id],
        },
    )
    assert create_resp.status_code == 201
    vuln_id = create_resp.get_json()["id"]

    detail = client.get(f"/api/vulnerabilities/{vuln_id}", headers=headers)
    assert detail.status_code == 200
    payload = detail.get_json()
    due_at = datetime.fromisoformat(payload["sla_due_at"])
    created_at = datetime.fromisoformat(payload["created_at"])
    assert due_at - created_at < timedelta(days=3)
    assert payload["sla_state"] in {"on_track", "due_soon"}

    list_resp = client.get("/api/vulnerabilities", headers=headers)
    assert list_resp.status_code == 200
    item = next(row for row in list_resp.get_json()["items"] if row["id"] == vuln_id)
    assert item["sla_due_at"] is not None
    assert item["sla_state"] in {"on_track", "due_soon", "breached"}

    update_resp = client.put(
        f"/api/vulnerabilities/{vuln_id}",
        headers=headers,
        json={"severity": "Low"},
    )
    assert update_resp.status_code == 200

    detail2 = client.get(f"/api/vulnerabilities/{vuln_id}", headers=headers).get_json()
    due_at_low = datetime.fromisoformat(detail2["sla_due_at"])
    created_at_low = datetime.fromisoformat(detail2["created_at"])
    assert due_at_low - created_at_low > timedelta(days=30)


def test_validation_error_payload_shape_consistent(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    responses = [
        client.post('/api/attack_vectors', headers=headers, json={}),
        client.post('/api/notification-rules', headers=headers, json={"name": "rule", "delivery_adapter": "invalid"}),
        client.post('/api/vulnerabilities/filters', headers=headers, json={"name": "x", "filter_json": {}, "visibility": "bad"}),
        client.get('/api/users?role=Unknown', headers=headers),
    ]

    for resp in responses:
        assert resp.status_code == 400
        payload = resp.get_json()
        assert isinstance(payload, dict)
        assert set(["error", "details", "field"]).issubset(payload.keys())
        assert payload["error"]

def test_reports_export_endpoints_apply_filters_and_schema(app, client):
    admin = create_admin(app)
    analyst = create_user_direct(app, "report_analyst", "report_analyst@example.com", role="Analyst")
    headers = auth_header(admin)

    client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Critical item", "severity": "Critical", "status": "Open", "assigned_to": analyst.id},
    )
    client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Low item", "severity": "Low", "status": "Closed"},
    )

    export_resp = client.get(
        f"/api/reports/vulnerabilities/export?severity=Critical&status=Open&assigned_to={analyst.id}",
        headers=headers,
    )
    assert export_resp.status_code == 200
    export_payload = export_resp.get_json()
    export_download = client.get(export_payload["artifact"]["download_url"], headers=headers)
    assert export_download.status_code == 200
    body = export_download.get_data(as_text=True)
    assert "id,cve_id,title,severity,cvss_score,status" in body
    assert "Critical item" in body
    assert "Low item" not in body

    dashboard_resp = client.get("/api/reports/dashboard/export?severity=Critical", headers=headers)
    assert dashboard_resp.status_code == 200
    dashboard_payload = dashboard_resp.get_json()
    dashboard_download = client.get(dashboard_payload["artifact"]["download_url"], headers=headers)
    assert dashboard_download.status_code == 200
    dashboard_csv = dashboard_download.get_data(as_text=True)
    assert "metric,group,value" in dashboard_csv
    assert "severity,Critical,1" in dashboard_csv


def test_report_schedule_permissions_and_run(app, client, monkeypatch):
    admin = create_admin(app)
    analyst = create_user_direct(app, "sched_analyst", "sched_analyst@example.com", role="Analyst")
    viewer = create_user_direct(app, "sched_viewer", "sched_viewer@example.com", role="Viewer")

    headers_admin = auth_header(admin)
    headers_analyst = auth_header(analyst)
    headers_viewer = auth_header(viewer)

    monkeypatch.setattr(
        "backend.api.reports.send_email",
        lambda **_kwargs: {"channel": "email", "status": "sent", "ok": True},
    )

    create_forbidden = client.post(
        "/api/reports/schedules",
        headers=headers_viewer,
        json={
            "name": "Viewer schedule",
            "report_type": "vulnerabilities",
            "frequency": "daily",
            "delivery_channel": "email",
            "recipient": "viewer@example.com",
        },
    )
    assert create_forbidden.status_code == 403

    create_resp = client.post(
        "/api/reports/schedules",
        headers=headers_analyst,
        json={
            "name": "Daily open critical",
            "report_type": "vulnerabilities",
            "frequency": "daily",
            "delivery_channel": "email",
            "recipients": ["analyst@example.com", "secops@example.com"],
            "timezone": "America/New_York",
            "filter_preset": "critical-open",
            "delivery_preferences": {"subject_suffix": "[SOC]"},
            "filters": {"severity": "Critical", "status": "Open"},
        },
    )
    assert create_resp.status_code == 201
    created_payload = create_resp.get_json()
    schedule_id = created_payload["id"]
    assert created_payload["timezone"] == "America/New_York"
    assert created_payload["recipients"] == ["analyst@example.com", "secops@example.com"]
    assert created_payload["last_run_status"] == "never"

    analyst_list = client.get("/api/reports/schedules", headers=headers_analyst)
    assert analyst_list.status_code == 200
    assert len(analyst_list.get_json()) == 1

    admin_list = client.get("/api/reports/schedules", headers=headers_admin)
    assert admin_list.status_code == 200
    assert any(item["id"] == schedule_id for item in admin_list.get_json())


    update_resp = client.patch(
        f"/api/reports/schedules/{schedule_id}",
        headers=headers_analyst,
        json={"frequency": "weekly", "timezone": "UTC", "recipients": ["owner@example.com"]},
    )
    assert update_resp.status_code == 200
    assert update_resp.get_json()["frequency"] == "weekly"

    run_forbidden = client.post(f"/api/reports/schedules/{schedule_id}/run", headers=headers_viewer)
    assert run_forbidden.status_code == 403

    run_resp = client.post(f"/api/reports/schedules/{schedule_id}/run", headers=headers_analyst)
    assert run_resp.status_code == 200
    payload = run_resp.get_json()
    assert payload["status"] == "sent"
    assert payload["delivery"]["channel"] == "email"
    assert payload["schedule"]["last_run_status"] == "success"
    assert payload["schedule"]["retry_count"] == 0

    delete_forbidden = client.delete(f"/api/reports/schedules/{schedule_id}", headers=headers_viewer)
    assert delete_forbidden.status_code == 403

    invalid_frequency = client.post(
        "/api/reports/schedules",
        headers=headers_admin,
        json={
            "name": "Bad schedule",
            "report_type": "vulnerabilities",
            "frequency": "monthly",
            "delivery_channel": "email",
            "recipient": "admin@example.com",
        },
    )
    assert invalid_frequency.status_code == 400


def test_rate_limit_login_threshold_crossing_and_retry_metadata(app, client):
    app.config.update(
        RATE_LIMIT_AUTH_LOGIN_LIMIT=2,
        RATE_LIMIT_AUTH_LOGIN_WINDOW_SECONDS=60,
    )

    create_admin(app)

    first = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    assert first.status_code == 200
    assert first.headers.get("X-RateLimit-Limit") == "2"
    assert first.headers.get("X-RateLimit-Remaining") == "1"

    second = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    assert second.status_code == 200
    assert second.headers.get("X-RateLimit-Remaining") == "0"

    blocked = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    assert blocked.status_code == 429
    payload = blocked.get_json()
    assert payload["error"] == "Rate limit exceeded"
    assert int(payload["retry_after_seconds"]) >= 1
    assert int(blocked.headers.get("Retry-After")) == int(payload["retry_after_seconds"])
    assert blocked.headers.get("X-RateLimit-Limit") == "2"
    assert blocked.headers.get("X-RateLimit-Remaining") == "0"


def test_rate_limit_vulnerability_list_resets_after_window(app, client):
    admin = create_admin(app)

    now = [1000.0]

    def fake_now():
        return now[0]

    app.config.update(
        RATE_LIMIT_VULN_LIST_LIMIT=2,
        RATE_LIMIT_VULN_LIST_WINDOW_SECONDS=10,
        RATE_LIMIT_TIME_FUNCTION=fake_now,
    )

    headers = auth_header(admin)

    first = client.get("/api/vulnerabilities", headers=headers)
    assert first.status_code == 200
    assert first.headers.get("X-RateLimit-Remaining") == "1"

    second = client.get("/api/vulnerabilities", headers=headers)
    assert second.status_code == 200
    assert second.headers.get("X-RateLimit-Remaining") == "0"

    blocked = client.get("/api/vulnerabilities", headers=headers)
    assert blocked.status_code == 429
    assert blocked.headers.get("Retry-After") == "10"

    now[0] += 11

    allowed_after_reset = client.get("/api/vulnerabilities", headers=headers)
    assert allowed_after_reset.status_code == 200
    assert allowed_after_reset.headers.get("X-RateLimit-Remaining") == "1"


def test_rate_limit_export_endpoint(app, client):
    admin = create_admin(app)
    app.config.update(
        RATE_LIMIT_VULN_EXPORT_LIMIT=1,
        RATE_LIMIT_VULN_EXPORT_WINDOW_SECONDS=60,
    )

    first = client.get("/api/reports/vulnerabilities/export", headers=auth_header(admin))
    assert first.status_code == 200
    assert first.headers.get("X-RateLimit-Remaining") == "0"

    blocked = client.get("/api/reports/vulnerabilities/export", headers=auth_header(admin))
    assert blocked.status_code == 429
    assert blocked.get_json()["error"] == "Rate limit exceeded"


def test_sbom_ingest_and_component_listing(app, client):
    admin = create_admin(app)
    _, pv = create_product_with_version(app, owner_id=admin.id)

    payload = {
        "format": "cyclonedx",
        "sbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "bom-ref": "pkg:npm/lodash@4.17.21",
                    "type": "library",
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21",
                    "properties": [{"name": "uvt:cve", "value": "CVE-2024-9999"}],
                },
            ],
            "dependencies": [
                {"ref": "pkg:npm/lodash@4.17.21", "dependsOn": []},
            ],
        },
    }

    ingest = client.post(f"/api/product_versions/{pv.id}/sbom", headers=auth_header(admin), json=payload)
    assert ingest.status_code == 200
    assert ingest.get_json()["stats"]["components_ingested"] == 1

    listing = client.get(f"/api/product_versions/{pv.id}/components", headers=auth_header(admin))
    assert listing.status_code == 200
    rows = listing.get_json()
    assert len(rows) == 1
    assert rows[0]["name"] == "lodash"
    assert rows[0]["ecosystem"] == "npm"


def test_dependency_graph_endpoint_returns_nodes_edges_and_vulnerabilities(app, client):
    admin = create_admin(app)
    _, pv = create_product_with_version(app, owner_id=admin.id)

    with app.app_context():
        parent = SoftwareComponent(
            product_version_id=pv.id,
            name="app-core",
            version="1.0.0",
            ecosystem="npm",
            bom_ref="pkg:npm/app-core@1.0.0",
        )
        child = SoftwareComponent(
            product_version_id=pv.id,
            name="lodash",
            version="4.17.21",
            ecosystem="npm",
            bom_ref="pkg:npm/lodash@4.17.21",
        )
        db.session.add_all([parent, child])
        db.session.flush()

        dep = ComponentDependency(
            product_version_id=pv.id,
            parent_component_id=parent.id,
            child_component_id=child.id,
            dependency_path=f"{parent.bom_ref}>{child.bom_ref}",
            depth=1,
            is_direct=True,
        )
        vuln = Vulnerability(title="Lodash issue", severity="High", status="Open")
        db.session.add_all([dep, vuln])
        db.session.flush()
        db.session.add(VulnerabilityComponent(
            vulnerability_id=vuln.id,
            component_id=child.id,
            source="sbom",
            match_type="purl",
            transitive_depth=1,
        ))
        db.session.commit()

    resp = client.get(f"/api/product_versions/{pv.id}/dependency_graph", headers=auth_header(admin))
    assert resp.status_code == 200
    payload = resp.get_json()

    assert payload["product_version_id"] == pv.id
    assert len(payload["nodes"]) == 2
    assert len(payload["edges"]) == 1
    vulnerable_node = next(node for node in payload["nodes"] if node["name"] == "lodash")
    assert vulnerable_node["vulnerability_count"] == 1
    assert vulnerable_node["max_severity"] == "High"
    assert vulnerable_node["vulnerabilities"][0]["title"] == "Lodash issue"
    root_node = next(node for node in payload["nodes"] if node["name"] == "app-core")
    assert root_node["id"] in payload["root_node_ids"]


def test_vulnerability_component_filters_and_export(app, client):
    admin = create_admin(app)
    _, pv = create_product_with_version(app, owner_id=admin.id)

    vuln = client.post(
        "/api/vulnerabilities",
        headers=auth_header(admin),
        json={"title": "lodash vuln", "cve_id": "CVE-2024-9999", "severity": "High"},
    )
    assert vuln.status_code == 201

    payload = {
        "format": "cyclonedx",
        "sbom": {
            "components": [
                {
                    "bom-ref": "pkg:npm/lodash@4.17.21",
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21",
                    "properties": [{"name": "uvt:cve", "value": "CVE-2024-9999"}],
                },
            ],
            "dependencies": [],
        },
    }
    ingest = client.post(f"/api/product_versions/{pv.id}/sbom", headers=auth_header(admin), json=payload)
    assert ingest.status_code == 200

    filtered = client.get(
        "/api/vulnerabilities?component_ecosystem=npm&component_name=lodash",
        headers=auth_header(admin),
    )
    assert filtered.status_code == 200
    assert filtered.get_json()["total"] >= 1

    exported = client.get(
        "/api/reports/vulnerabilities/export?component_ecosystem=npm&component_name=lodash",
        headers=auth_header(admin),
    )
    assert exported.status_code == 200
    export_payload = exported.get_json()
    downloaded = client.get(export_payload["artifact"]["download_url"], headers=auth_header(admin))
    assert downloaded.status_code == 200
    csv = downloaded.get_data(as_text=True)
    assert "component_ecosystems" in csv


def test_vulnerability_comment_mentions_create_notifications(app, client):
    admin = create_admin(app)
    analyst = create_user_direct(app, "analyst_mentions", "analyst_mentions@example.com", role="Analyst")
    mentioned = create_user_direct(app, "mention_target", "mention_target@example.com", role="Analyst")

    headers = auth_header(admin)
    vuln_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Mention test vuln", "severity": "High", "status": "Open"},
    )
    assert vuln_resp.status_code == 201
    vuln_id = vuln_resp.get_json()["id"]

    comment_resp = client.post(
        f"/api/vulnerabilities/{vuln_id}/comments",
        headers=auth_header(analyst),
        json={"body": "Please review this @mention_target and @missing_user"},
    )
    assert comment_resp.status_code == 201

    with app.app_context():
        from backend.models import Notification
        notifications = Notification.query.filter_by(vulnerability_id=vuln_id).all()
        assert len(notifications) == 1
        assert notifications[0].user_id == mentioned.id
        assert "mentioned" in notifications[0].message.lower()




def test_notifications_list_and_update_flow(app, client):
    admin = create_admin(app)
    other = create_user_direct(app, "notif_other", "notif_other@example.com", role="Analyst")

    with app.app_context():
        from backend.models import Notification

        first = Notification(user_id=admin.id, message="First", is_read=False)
        second = Notification(user_id=admin.id, message="Second", is_read=True)
        hidden = Notification(user_id=other.id, message="Other user", is_read=False)
        db.session.add_all([first, second, hidden])
        db.session.commit()

    listed = client.get("/api/notifications?page=1&page_size=1", headers=auth_header(admin))
    assert listed.status_code == 200
    payload = listed.get_json()
    assert payload["ok"] is True
    assert payload["data"]["pagination"]["total"] == 2
    assert len(payload["data"]["items"]) == 1
    assert payload["data"]["unread_count"] == 1

    target_id = payload["data"]["items"][0]["id"]
    updated = client.patch(
        f"/api/notifications/{target_id}",
        headers=auth_header(admin),
        json={"is_read": False},
    )
    assert updated.status_code == 200
    updated_payload = updated.get_json()
    assert updated_payload["data"]["notification"]["is_read"] is False

    not_found = client.patch(
        "/api/notifications/999999",
        headers=auth_header(admin),
        json={"is_read": True},
    )
    assert not_found.status_code == 404


def test_notifications_mark_all_and_archive_modes(app, client):
    admin = create_admin(app)

    with app.app_context():
        from backend.models import Notification

        row1 = Notification(user_id=admin.id, message="Unread 1", is_read=False)
        row2 = Notification(user_id=admin.id, message="Unread 2", is_read=False)
        db.session.add_all([row1, row2])
        db.session.commit()
        first_id = row1.id
        second_id = row2.id

    mark_all = client.post("/api/notifications/read-all", headers=auth_header(admin))
    assert mark_all.status_code == 200
    mark_payload = mark_all.get_json()
    assert mark_payload["data"]["updated"] == 2
    assert mark_payload["data"]["unread_count"] == 0

    archived = client.delete(f"/api/notifications/{first_id}?mode=archive", headers=auth_header(admin))
    assert archived.status_code == 200
    archived_payload = archived.get_json()
    assert archived_payload["data"]["mode"] == "archive"

    bad_mode = client.delete(f"/api/notifications/{second_id}?mode=nope", headers=auth_header(admin))
    assert bad_mode.status_code == 400

def test_vulnerability_comment_permissions_author_or_admin(app, client):
    admin = create_admin(app)
    author = create_user_direct(app, "comment_author", "comment_author@example.com", role="Analyst")
    other = create_user_direct(app, "comment_other", "comment_other@example.com", role="Analyst")

    vuln_resp = client.post(
        "/api/vulnerabilities",
        headers=auth_header(admin),
        json={"title": "Comment permission vuln"},
    )
    assert vuln_resp.status_code == 201
    vuln_id = vuln_resp.get_json()["id"]

    comment_resp = client.post(
        f"/api/vulnerabilities/{vuln_id}/comments",
        headers=auth_header(author),
        json={"body": "Author comment"},
    )
    assert comment_resp.status_code == 201
    comment_id = comment_resp.get_json()["id"]

    denied_update = client.put(
        f"/api/vulnerabilities/{vuln_id}/comments/{comment_id}",
        headers=auth_header(other),
        json={"body": "Unauthorized edit"},
    )
    assert denied_update.status_code == 403

    denied_delete = client.delete(
        f"/api/vulnerabilities/{vuln_id}/comments/{comment_id}",
        headers=auth_header(other),
    )
    assert denied_delete.status_code == 403

    admin_update = client.put(
        f"/api/vulnerabilities/{vuln_id}/comments/{comment_id}",
        headers=auth_header(admin),
        json={"body": "Admin moderation edit"},
    )
    assert admin_update.status_code == 200

    admin_delete = client.delete(
        f"/api/vulnerabilities/{vuln_id}/comments/{comment_id}",
        headers=auth_header(admin),
    )
    assert admin_delete.status_code == 200


def test_vulnerability_enrich_success(app, client, monkeypatch):
    admin = create_admin(app)
    headers = auth_header(admin)

    create_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Needs enrichment", "cve_id": "CVE-2024-1234", "severity": "Low", "status": "Open"},
    )
    assert create_resp.status_code == 201
    vuln_id = create_resp.get_json()["id"]

    class DummyEnrichment:
        title = "NVD Title"
        description = "NVD description"
        severity = "Critical"
        cvss_score = 9.8
        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        cvss_version = "3.1"
        cwe_id = "CWE-79"
        references_json = [{"url": "https://example.com/ref", "title": "ref"}]
        published_date = date(2024, 1, 1)
        last_modified_date = date(2024, 1, 20)

    monkeypatch.setattr("backend.api.vulnerabilities.fetch_cve_enrichment", lambda _cve_id: DummyEnrichment())

    resp = client.post(f"/api/vulnerabilities/{vuln_id}/enrich?force=true", headers=headers)
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["ok"] is True
    assert payload["enrichment"]["status"] == "enriched"
    assert "severity" in payload["enrichment"]["applied_fields"]
    assert payload["vulnerability"]["severity"] == "Critical"
    assert payload["vulnerability"]["cvss_score"] == 9.8
    assert payload["vulnerability"]["cwe_id"] == "CWE-79"
    assert payload["vulnerability"]["references_json"][0]["url"] == "https://example.com/ref"

    log = _latest_audit(app, action="ENRICH", table_name="vulnerabilities")
    assert log is not None
    assert log.record_id == vuln_id


def test_vulnerability_enrich_missing_cve_id(app, client):
    admin = create_admin(app)
    headers = auth_header(admin)

    create_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "No cve", "severity": "Low", "status": "Open"},
    )
    assert create_resp.status_code == 201
    vuln_id = create_resp.get_json()["id"]

    resp = client.post(f"/api/vulnerabilities/{vuln_id}/enrich", headers=headers)
    assert resp.status_code == 400
    payload = resp.get_json()
    assert payload["ok"] is False
    assert payload["enrichment"]["status"] == "error"


def test_vulnerability_enrich_upstream_not_found_and_timeout(app, client, monkeypatch):
    from backend.services.cve_enrichment import CveNotFoundError, CveUpstreamTimeoutError

    admin = create_admin(app)
    headers = auth_header(admin)

    create_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Upstream failures", "cve_id": "CVE-2024-9999", "severity": "Low", "status": "Open"},
    )
    assert create_resp.status_code == 201
    vuln_id = create_resp.get_json()["id"]

    def raise_not_found(_cve_id):
        raise CveNotFoundError("not found")

    monkeypatch.setattr("backend.api.vulnerabilities.fetch_cve_enrichment", raise_not_found)
    not_found_resp = client.post(f"/api/vulnerabilities/{vuln_id}/enrich", headers=headers)
    assert not_found_resp.status_code == 404
    assert not_found_resp.get_json()["enrichment"]["status"] == "not_found"

    def raise_timeout(_cve_id):
        raise CveUpstreamTimeoutError("timed out")

    monkeypatch.setattr("backend.api.vulnerabilities.fetch_cve_enrichment", raise_timeout)
    timeout_resp = client.post(f"/api/vulnerabilities/{vuln_id}/enrich", headers=headers)
    assert timeout_resp.status_code == 504
    assert timeout_resp.get_json()["enrichment"]["status"] == "timeout"


def test_vulnerability_enrich_merge_vs_force(app, client, monkeypatch):
    admin = create_admin(app)
    headers = auth_header(admin)

    create_resp = client.post(
        "/api/vulnerabilities",
        headers=headers,
        json={"title": "Keep my title", "cve_id": "CVE-2024-5555", "severity": "Low", "status": "Open"},
    )
    assert create_resp.status_code == 201
    vuln_id = create_resp.get_json()["id"]

    class DummyEnrichment:
        title = "External title"
        description = "External description"
        severity = "High"
        cvss_score = 8.1
        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        cvss_version = "3.1"
        cwe_id = "CWE-89"
        references_json = [{"url": "https://example.com/advisory", "title": "adv"}]
        published_date = date(2023, 3, 1)
        last_modified_date = date(2023, 3, 2)

    monkeypatch.setattr("backend.api.vulnerabilities.fetch_cve_enrichment", lambda _cve_id: DummyEnrichment())

    merge_resp = client.post(f"/api/vulnerabilities/{vuln_id}/enrich", headers=headers)
    assert merge_resp.status_code == 200
    merge_payload = merge_resp.get_json()
    assert merge_payload["vulnerability"]["severity"] == "Low"
    assert merge_payload["vulnerability"]["cwe_id"] == "CWE-89"
    assert "severity" not in merge_payload["enrichment"]["applied_fields"]

    force_resp = client.post(f"/api/vulnerabilities/{vuln_id}/enrich?force=true", headers=headers)
    assert force_resp.status_code == 200
    force_payload = force_resp.get_json()
    assert force_payload["vulnerability"]["severity"] == "High"
    assert "severity" in force_payload["enrichment"]["applied_fields"]


def test_compare_product_version_components_diff(app, client):
    admin = create_admin(app)

    with app.app_context():
        product = Product(name="Widget Diff", description="Diff target", created_by=admin.id)
        db.session.add(product)
        db.session.flush()

        from_pv = ProductVersion(product_id=product.id, version="1.0.0", release_date=date(2024, 1, 1))
        to_pv = ProductVersion(product_id=product.id, version="2.0.0", release_date=date(2024, 6, 1))
        db.session.add_all([from_pv, to_pv])
        db.session.flush()

        from_root = SoftwareComponent(
            product_version_id=from_pv.id,
            name="app-core",
            version="1.0.0",
            ecosystem="npm",
            purl="pkg:npm/app-core@1.0.0",
            component_type="application",
        )
        from_lodash = SoftwareComponent(
            product_version_id=from_pv.id,
            name="lodash",
            version="4.17.20",
            ecosystem="npm",
            purl="pkg:npm/lodash@4.17.20",
        )
        from_axios = SoftwareComponent(
            product_version_id=from_pv.id,
            name="axios",
            version="0.24.0",
            ecosystem="npm",
            purl="pkg:npm/axios@0.24.0",
        )
        db.session.add_all([from_root, from_lodash, from_axios])
        db.session.flush()

        db.session.add_all([
            ComponentDependency(
                product_version_id=from_pv.id,
                parent_component_id=from_root.id,
                child_component_id=from_lodash.id,
                dependency_path="app-core > lodash",
                depth=1,
                is_direct=True,
            ),
            ComponentDependency(
                product_version_id=from_pv.id,
                parent_component_id=from_root.id,
                child_component_id=from_axios.id,
                dependency_path="app-core > axios",
                depth=1,
                is_direct=True,
            ),
        ])

        to_root = SoftwareComponent(
            product_version_id=to_pv.id,
            name="app-core",
            version="2.0.0",
            ecosystem="npm",
            purl="pkg:npm/app-core@2.0.0",
            component_type="application",
        )
        to_lodash = SoftwareComponent(
            product_version_id=to_pv.id,
            name="lodash",
            version="4.17.21",
            ecosystem="npm",
            purl="pkg:npm/lodash@4.17.21",
        )
        to_axios = SoftwareComponent(
            product_version_id=to_pv.id,
            name="axios",
            version="0.22.0",
            ecosystem="npm",
            purl="pkg:npm/axios@0.22.0",
        )
        to_dayjs = SoftwareComponent(
            product_version_id=to_pv.id,
            name="dayjs",
            version="1.11.13",
            ecosystem="npm",
            purl="pkg:npm/dayjs@1.11.13",
        )
        db.session.add_all([to_root, to_lodash, to_axios, to_dayjs])
        db.session.flush()

        db.session.add_all([
            ComponentDependency(
                product_version_id=to_pv.id,
                parent_component_id=to_root.id,
                child_component_id=to_lodash.id,
                dependency_path="app-core > lodash",
                depth=1,
                is_direct=True,
            ),
            ComponentDependency(
                product_version_id=to_pv.id,
                parent_component_id=to_root.id,
                child_component_id=to_axios.id,
                dependency_path="app-core > transitive > axios",
                depth=2,
                is_direct=False,
            ),
            ComponentDependency(
                product_version_id=to_pv.id,
                parent_component_id=to_root.id,
                child_component_id=to_dayjs.id,
                dependency_path="app-core > dayjs",
                depth=1,
                is_direct=True,
            ),
        ])

        db.session.commit()
        from_id = from_pv.id
        to_id = to_pv.id

    resp = client.get(
        f"/api/product_versions/compare/components?from_product_version_id={from_id}&to_product_version_id={to_id}",
        headers=auth_header(admin),
    )

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["from_product_version"]["id"] == from_id
    assert payload["to_product_version"]["id"] == to_id

    assert payload["summary"]["added_components"] == 1
    assert payload["summary"]["removed_components"] == 0
    assert payload["summary"]["changed_components"] >= 3
    assert payload["summary"]["version_upgrades"] == 2
    assert payload["summary"]["version_downgrades"] == 1

    added_names = {row["name"] for row in payload["components"]["added"]}
    assert added_names == {"dayjs"}

    upgrades = {(row["name"], row["from_version"], row["to_version"]) for row in payload["version_deltas"]["upgrades"]}
    assert ("app-core", "1.0.0", "2.0.0") in upgrades
    assert ("lodash", "4.17.20", "4.17.21") in upgrades

    downgrades = {(row["name"], row["from_version"], row["to_version"]) for row in payload["version_deltas"]["downgrades"]}
    assert ("axios", "0.24.0", "0.22.0") in downgrades

    assert payload["summary"]["dependency_edges_added"] == 1
    assert payload["summary"]["dependency_edges_removed"] == 0
    assert payload["summary"]["dependency_edges_changed"] == 1


def test_report_schedule_retry_backoff_metadata_on_failure(app, client, monkeypatch):
    analyst = create_user_direct(app, "sched_retry", "sched_retry@example.com", role="Analyst")
    headers = auth_header(analyst)

    created = client.post(
        "/api/reports/schedules",
        headers=headers,
        json={
            "name": "Retry schedule",
            "report_type": "vulnerabilities",
            "frequency": "daily",
            "delivery_channel": "slack",
            "recipients": ["https://hooks.slack.invalid/abc"],
        },
    )
    assert created.status_code == 201
    schedule_id = created.get_json()["id"]

    class FakeSlackError(Exception):
        pass

    def _raise(*_args, **_kwargs):
        from backend.services.slack_alerts import SlackWebhookError

        raise SlackWebhookError("forced slack failure")

    monkeypatch.setattr("backend.api.reports.SlackWebhookClient.send_message", _raise)

    run_resp = client.post(f"/api/reports/schedules/{schedule_id}/run", headers=headers)
    assert run_resp.status_code == 200
    payload = run_resp.get_json()
    assert payload["status"] == "failed"
    assert payload["schedule"]["last_run_status"] == "retrying"
    assert payload["schedule"]["retry_count"] == 1
    assert payload["schedule"]["next_retry_at"] is not None
    assert "forced slack failure" in (payload["schedule"]["last_failure_reason"] or "")
