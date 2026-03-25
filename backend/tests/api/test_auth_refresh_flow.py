from backend.database import db
from backend.models import RefreshToken


def test_login_returns_refresh_token_and_persists_hash(client, admin_user):
    res = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    assert res.status_code == 200
    payload = res.get_json()
    assert payload["token"]
    assert payload["refresh_token"]
    assert payload["csrf_token"]
    set_cookie = res.headers.get("Set-Cookie", "")
    assert "uvt_auth_token=" in set_cookie
    assert "HttpOnly" in set_cookie

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
    assert payload["csrf_token"]
    set_cookie = refresh.headers.get("Set-Cookie", "")
    assert "uvt_auth_token=" in set_cookie
    assert "HttpOnly" in set_cookie
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


def test_logout_clears_auth_cookie_with_or_without_refresh_token(client, admin_user):
    login = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    refresh_token = login.get_json()["refresh_token"]

    with_token = client.post("/api/auth/logout", json={"refresh_token": refresh_token})
    assert with_token.status_code == 200
    with_token_cookie = "\n".join(with_token.headers.getlist("Set-Cookie"))
    assert "uvt_auth_token=" in with_token_cookie
    assert "uvt_csrf_token=" in with_token_cookie
    assert "Max-Age=0" in with_token_cookie

    without_token = client.post("/api/auth/logout", json={})
    assert without_token.status_code == 200
    without_token_cookie = "\n".join(without_token.headers.getlist("Set-Cookie"))
    assert "uvt_auth_token=" in without_token_cookie
    assert "uvt_csrf_token=" in without_token_cookie
    assert "Max-Age=0" in without_token_cookie




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


def test_logout_all_clears_auth_cookie(client, admin_user):
    login = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    payload = login.get_json()

    logout_all = client.post("/api/auth/logout_all", headers={"Authorization": f"Bearer {payload['token']}"})
    assert logout_all.status_code == 200
    set_cookie_headers = "\n".join(logout_all.headers.getlist("Set-Cookie"))
    assert "uvt_auth_token=" in set_cookie_headers
    assert "uvt_csrf_token=" in set_cookie_headers
    assert "Max-Age=0" in set_cookie_headers


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


def test_csrf_endpoint_issues_token_cookie(client):
    response = client.get("/api/auth/csrf")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["csrf_token"]
    set_cookie = response.headers.get("Set-Cookie", "")
    assert "uvt_csrf_token=" in set_cookie
