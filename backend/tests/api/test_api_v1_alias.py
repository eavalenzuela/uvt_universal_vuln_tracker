"""F18: /api/v1/* should serve the same responses as /api/* (alias, not copy)."""


def test_health_v1_alias(client):
    resp_plain = client.get("/api/health")
    resp_v1 = client.get("/api/v1/health")
    assert resp_plain.status_code == resp_v1.status_code
    assert resp_plain.get_json() == resp_v1.get_json()


def test_auth_login_via_v1(client, admin_user):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": admin_user.username, "password": "secret-pass-12"},
    )
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_protected_v1_requires_auth(client):
    resp = client.get("/api/v1/vulnerabilities")
    # Same 401 shape as the unversioned prefix.
    assert resp.status_code == 401


def test_protected_v1_succeeds_with_auth(client, admin_user, auth_header):
    resp = client.get("/api/v1/vulnerabilities", headers=auth_header(admin_user))
    assert resp.status_code == 200


def test_deep_prefix_blueprint_works_under_v1(client, admin_user, auth_header):
    # Blueprints with deeper prefixes (e.g. /api/vulnerabilities/filters) must
    # still resolve under /api/v1 — guards the before_request path rewrite.
    resp = client.get("/api/v1/vulnerabilities/filters", headers=auth_header(admin_user))
    assert resp.status_code == 200
