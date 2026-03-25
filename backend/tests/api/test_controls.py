from backend.auth import generate_token, hash_password
from backend.database import db
from backend.models import AuditLog, Control, User


def _make_user(app, role="Admin"):
    with app.app_context():
        u = User(username=f"u_{role.lower()}", email=f"{role.lower()}@example.com", password_hash=hash_password("pw"), role=role)
        db.session.add(u)
        db.session.commit()
        db.session.refresh(u)
        db.session.expunge(u)
        return u


def _headers(user):
    token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    return {"Authorization": f"Bearer {token}"}


def test_control_crud(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    # Create
    resp = client.post("/api/controls", headers=headers, json={
        "name": "AC-1", "framework": "NIST 800-53", "description": "Access control policy"
    })
    assert resp.status_code == 201
    control = resp.get_json()
    assert control["name"] == "AC-1"
    assert control["framework"] == "NIST 800-53"
    control_id = control["id"]

    # List
    resp = client.get("/api/controls", headers=headers)
    assert resp.status_code == 200
    assert any(c["id"] == control_id for c in resp.get_json())

    # Get
    resp = client.get(f"/api/controls/{control_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "AC-1"

    # Update
    resp = client.patch(f"/api/controls/{control_id}", headers=headers, json={"name": "AC-2", "framework": "NIST"})
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "AC-2"
    assert resp.get_json()["framework"] == "NIST"

    # Delete
    resp = client.delete(f"/api/controls/{control_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True

    resp = client.get(f"/api/controls/{control_id}", headers=headers)
    assert resp.status_code == 404


def test_control_validation(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    resp = client.post("/api/controls", headers=headers, json={"name": ""})
    assert resp.status_code == 400

    resp = client.post("/api/controls", headers=headers, json={"name": "Valid"})
    cid = resp.get_json()["id"]
    resp = client.patch(f"/api/controls/{cid}", headers=headers, json={"name": ""})
    assert resp.status_code == 400


def test_control_empty_framework_stored_as_null(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    resp = client.post("/api/controls", headers=headers, json={"name": "Test", "framework": ""})
    assert resp.status_code == 201
    assert resp.get_json()["framework"] is None


def test_control_audit_logging(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    resp = client.post("/api/controls", headers=headers, json={"name": "Audited"})
    control_id = resp.get_json()["id"]

    with app.app_context():
        log = AuditLog.query.filter_by(action="CREATE", table_name="controls", record_id=control_id).first()
        assert log is not None

    client.patch(f"/api/controls/{control_id}", headers=headers, json={"name": "Updated"})
    with app.app_context():
        log = AuditLog.query.filter_by(action="UPDATE", table_name="controls", record_id=control_id).first()
        assert log is not None

    client.delete(f"/api/controls/{control_id}", headers=headers)
    with app.app_context():
        log = AuditLog.query.filter_by(action="DELETE", table_name="controls", record_id=control_id).first()
        assert log is not None


def test_control_role_enforcement(app, client):
    viewer = _make_user(app, "Viewer")
    headers = _headers(viewer)

    resp = client.post("/api/controls", headers=headers, json={"name": "Blocked"})
    assert resp.status_code == 403

    resp = client.delete("/api/controls/1", headers=headers)
    assert resp.status_code == 403

    resp = client.get("/api/controls", headers=headers)
    assert resp.status_code == 200
