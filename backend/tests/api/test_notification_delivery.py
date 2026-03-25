from backend.auth import generate_token, hash_password
from backend.database import db
from backend.models import NotificationDeliveryLog, NotificationRule, User, Vulnerability


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


_seed_counter = {"n": 0}


def _seed_delivery_log(app, admin, *, success=False):
    """Create a rule, vulnerability, and delivery log entry."""
    _seed_counter["n"] += 1
    with app.app_context():
        vuln = Vulnerability(cve_id=f"CVE-2026-7{_seed_counter['n']:03d}", title="Test", severity="High", status="Open", created_by=admin.id)
        db.session.add(vuln)
        db.session.flush()

        rule = NotificationRule(
            name="test-rule",
            delivery_adapter="webhook",
            delivery_config={"url": "http://example.com/hook"},
            created_by=admin.id,
        )
        db.session.add(rule)
        db.session.flush()

        log = NotificationDeliveryLog(
            rule_id=rule.id,
            vulnerability_id=vuln.id,
            event_type="status_change",
            delivery_adapter="webhook",
            success=success,
            error_message=None if success else "connection refused",
        )
        db.session.add(log)
        db.session.commit()
        db.session.refresh(log)
        return log.id, rule.id, vuln.id


def test_list_delivery_attempts(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)
    _seed_delivery_log(app, admin, success=True)
    _seed_delivery_log(app, admin, success=False)

    resp = client.get("/api/notification-delivery-attempts", headers=headers)
    assert resp.status_code == 200
    items = resp.get_json()
    assert len(items) >= 2


def test_list_delivery_attempts_failed_only(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)
    _seed_delivery_log(app, admin, success=True)
    _seed_delivery_log(app, admin, success=False)

    resp = client.get("/api/notification-delivery-attempts?failed_only=true", headers=headers)
    assert resp.status_code == 200
    items = resp.get_json()
    assert all(item["status"] == "failed" for item in items)


def test_list_delivery_attempts_limit(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    resp = client.get("/api/notification-delivery-attempts?limit=1", headers=headers)
    assert resp.status_code == 200
    assert len(resp.get_json()) <= 1


def test_retry_requires_failed_attempt(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)
    log_id, _, _ = _seed_delivery_log(app, admin, success=True)

    resp = client.post(f"/api/notification-delivery-attempts/{log_id}/retry", headers=headers)
    assert resp.status_code == 409


def test_replay_allows_successful_attempt(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)
    log_id, _, _ = _seed_delivery_log(app, admin, success=True)

    resp = client.post(f"/api/notification-delivery-attempts/{log_id}/replay", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True


def test_delivery_role_enforcement(app, client):
    viewer = _make_user(app, "Viewer")
    headers = _headers(viewer)

    resp = client.get("/api/notification-delivery-attempts", headers=headers)
    assert resp.status_code == 403
