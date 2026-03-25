from backend.auth import generate_token, hash_password
from backend.database import db
from backend.models import AuditLog, User


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


def test_get_default_sla_policy(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    resp = client.get("/api/sla_policy", headers=headers)
    assert resp.status_code == 200
    policy = resp.get_json()
    assert "global" in policy
    assert "Critical" in policy["global"]


def test_update_sla_policy(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    resp = client.put("/api/sla_policy", headers=headers, json={
        "global": {"Critical": 3, "High": 14, "Medium": 30, "Low": 90}
    })
    assert resp.status_code == 200
    policy = resp.get_json()
    assert policy["global"]["Critical"] == 3
    assert policy["global"]["High"] == 14

    # Verify persisted
    resp = client.get("/api/sla_policy", headers=headers)
    assert resp.get_json()["global"]["Critical"] == 3


def test_update_sla_policy_normalizes_input(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    # Invalid severity keys should be ignored, valid ones kept
    resp = client.put("/api/sla_policy", headers=headers, json={
        "global": {"Critical": 5, "Bogus": 999}
    })
    assert resp.status_code == 200
    policy = resp.get_json()
    assert policy["global"]["Critical"] == 5
    assert "Bogus" not in policy["global"]


def test_update_sla_policy_creates_audit_log(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    client.put("/api/sla_policy", headers=headers, json={"global": {"Critical": 7}})

    with app.app_context():
        log = AuditLog.query.filter_by(action="UPDATE", table_name="sla_policies").first()
        assert log is not None


def test_sla_policy_role_enforcement(app, client):
    viewer = _make_user(app, "Viewer")
    headers = _headers(viewer)

    resp = client.put("/api/sla_policy", headers=headers, json={"global": {"Critical": 1}})
    assert resp.status_code == 403

    resp = client.get("/api/sla_policy", headers=headers)
    assert resp.status_code == 200
