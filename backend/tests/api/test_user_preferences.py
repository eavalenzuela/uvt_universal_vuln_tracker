from backend.database import db
from backend.models import SavedVulnerabilityFilter, UserPreferences


def test_get_returns_defaults_for_new_user(client, user_factory, auth_header, app):
    user = user_factory(role="Analyst")
    resp = client.get("/api/me/preferences", headers=auth_header(user))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["timezone"] == "UTC"
    assert body["theme"] == "auto"
    assert body["notify_on_mention"] is True
    assert body["email_digest_frequency"] == "off"

    with app.app_context():
        assert UserPreferences.query.filter_by(user_id=user.id).count() == 1


def test_put_updates_scalar_fields(client, user_factory, auth_header):
    user = user_factory(role="Analyst")
    resp = client.put(
        "/api/me/preferences",
        json={
            "timezone": "America/New_York",
            "theme": "dark",
            "notify_on_mention": False,
            "email_digest_frequency": "weekly",
        },
        headers=auth_header(user),
    )
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body["timezone"] == "America/New_York"
    assert body["theme"] == "dark"
    assert body["notify_on_mention"] is False
    assert body["email_digest_frequency"] == "weekly"


def test_put_rejects_invalid_theme(client, user_factory, auth_header):
    user = user_factory(role="Analyst")
    resp = client.put(
        "/api/me/preferences",
        json={"theme": "neon"},
        headers=auth_header(user),
    )
    assert resp.status_code == 400
    assert "theme" in resp.get_json()["field"]


def test_put_rejects_unknown_filter(client, user_factory, auth_header):
    user = user_factory(role="Analyst")
    resp = client.put(
        "/api/me/preferences",
        json={"default_vuln_filter_id": 99999},
        headers=auth_header(user),
    )
    assert resp.status_code == 404


def test_put_rejects_other_users_filter(app, client, user_factory, auth_header):
    owner = user_factory(role="Analyst")
    intruder = user_factory(role="Analyst")

    with app.app_context():
        filt = SavedVulnerabilityFilter(
            name="owner's filter",
            filter_json={"status": "Open"},
            visibility="private",
            owner_id=owner.id,
        )
        db.session.add(filt)
        db.session.commit()
        filt_id = filt.id

    resp = client.put(
        "/api/me/preferences",
        json={"default_vuln_filter_id": filt_id},
        headers=auth_header(intruder),
    )
    assert resp.status_code == 404  # treated as "not found" to avoid existence oracle


def test_put_persists_and_get_returns(client, user_factory, auth_header):
    user = user_factory(role="Analyst")
    client.put(
        "/api/me/preferences",
        json={"theme": "light", "notify_on_sla_breach": False},
        headers=auth_header(user),
    )
    resp = client.get("/api/me/preferences", headers=auth_header(user))
    body = resp.get_json()
    assert body["theme"] == "light"
    assert body["notify_on_sla_breach"] is False


def test_requires_auth(client):
    assert client.get("/api/me/preferences").status_code == 401
    assert client.put("/api/me/preferences", json={}).status_code == 401
