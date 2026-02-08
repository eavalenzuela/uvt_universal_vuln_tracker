from backend.database import db
from backend.models import RefreshToken


def test_login_returns_refresh_token_and_persists_hash(client, admin_user):
    res = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    assert res.status_code == 200
    payload = res.get_json()
    assert payload["token"]
    assert payload["refresh_token"]

    with client.application.app_context():
        saved = RefreshToken.query.one()
        assert saved.user_id == admin_user.id
        assert saved.revoked is False
        assert saved.token_hash != payload["refresh_token"]


def test_refresh_rotates_refresh_token(client, admin_user):
    login = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    first = login.get_json()

    refresh = client.post("/api/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert refresh.status_code == 200
    payload = refresh.get_json()
    assert payload["token"]
    assert payload["refresh_token"]
    assert payload["refresh_token"] != first["refresh_token"]

    with client.application.app_context():
        tokens = RefreshToken.query.order_by(RefreshToken.id.asc()).all()
        assert len(tokens) == 2
        assert tokens[0].revoked is True
        assert tokens[1].revoked is False


def test_logout_revokes_refresh_token_and_blocks_future_refresh(client, admin_user):
    login = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    refresh_token = login.get_json()["refresh_token"]

    logout = client.post("/api/auth/logout", json={"refresh_token": refresh_token})
    assert logout.status_code == 200

    refresh = client.post("/api/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh.status_code == 401




def test_logout_all_revokes_access_token_and_refresh_tokens(client, admin_user):
    login = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    payload = login.get_json()

    before = client.get("/api/auth/me", headers={"Authorization": f"Bearer {payload['token']}"})
    assert before.status_code == 200

    logout_all = client.post("/api/auth/logout_all", headers={"Authorization": f"Bearer {payload['token']}"})
    assert logout_all.status_code == 200

    after = client.get("/api/auth/me", headers={"Authorization": f"Bearer {payload['token']}"})
    assert after.status_code == 401

    refresh = client.post("/api/auth/refresh", json={"refresh_token": payload["refresh_token"]})
    assert refresh.status_code == 401


def test_logout_all_revokes_all_refresh_tokens(client, admin_user, auth_header):
    first = client.post("/api/auth/login", json={"username": "admin", "password": "secret"}).get_json()
    second = client.post("/api/auth/login", json={"username": "admin", "password": "secret"}).get_json()

    logout_all = client.post("/api/auth/logout_all", headers=auth_header(admin_user))
    assert logout_all.status_code == 200

    r1 = client.post("/api/auth/refresh", json={"refresh_token": first["refresh_token"]})
    r2 = client.post("/api/auth/refresh", json={"refresh_token": second["refresh_token"]})
    assert r1.status_code == 401
    assert r2.status_code == 401

    with client.application.app_context():
        active_count = RefreshToken.query.filter_by(revoked=False).count()
        assert active_count == 0
        db.session.rollback()
