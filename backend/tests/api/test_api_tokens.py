from backend.database import db
from backend.models import ApiToken


def _create_api_token(client, auth_headers, path="/api/users/me/api-tokens", scopes=None):
    response = client.post(
        path,
        headers=auth_headers,
        json={"name": "ci-token", "scopes": scopes or ["products:read"]},
    )
    assert response.status_code == 201
    return response.get_json()


def test_self_service_api_token_lifecycle(client, admin_user, auth_header):
    headers = auth_header(admin_user)
    create_payload = _create_api_token(client, headers)
    assert isinstance(create_payload.get("token"), str)
    assert create_payload["token"].startswith("uvt_")
    token_id = create_payload["api_token"]["id"]

    list_response = client.get("/api/users/me/api-tokens", headers=headers)
    assert list_response.status_code == 200
    listed = list_response.get_json()
    assert listed and listed[0]["id"] == token_id
    assert "token" not in listed[0]

    revoke_response = client.post(f"/api/users/me/api-tokens/{token_id}/revoke", headers=headers)
    assert revoke_response.status_code == 200
    assert revoke_response.get_json()["revoked_at"] is not None


def test_admin_can_manage_another_users_api_tokens(client, admin_user, user_factory, auth_header):
    analyst = user_factory(role="Analyst")
    headers = auth_header(admin_user)

    created = _create_api_token(
        client,
        headers,
        path=f"/api/users/{analyst.id}/api-tokens",
        scopes=["products:read", "products:write"],
    )
    token_id = created["api_token"]["id"]

    listed = client.get(f"/api/users/{analyst.id}/api-tokens", headers=headers)
    assert listed.status_code == 200
    assert any(item["id"] == token_id for item in listed.get_json())

    revoked = client.post(f"/api/users/{analyst.id}/api-tokens/{token_id}/revoke", headers=headers)
    assert revoked.status_code == 200
    assert revoked.get_json()["revoked_at"] is not None


def test_bearer_api_token_auth_with_scope_enforcement(client, admin_user, auth_header):
    jwt_headers = auth_header(admin_user)
    created = _create_api_token(client, jwt_headers, scopes=["products:read"])
    bearer = {"Authorization": f"Bearer {created['token']}"}

    me_response = client.get("/api/auth/me", headers=bearer)
    assert me_response.status_code == 200
    assert me_response.get_json()["id"] == admin_user.id

    denied = client.post("/api/products", headers=bearer, json={"name": "Scoped Product"})
    assert denied.status_code == 403

    with client.application.app_context():
        token_row = db.session.get(ApiToken, created["api_token"]["id"])
        assert token_row.last_used_at is not None


def test_api_token_cannot_request_scope_outside_owner_role(client, admin_user, user_factory, auth_header):
    analyst = user_factory(role="Analyst")
    headers = auth_header(admin_user)

    response = client.post(
        f"/api/users/{analyst.id}/api-tokens",
        headers=headers,
        json={"name": "bad-scope", "scopes": ["users:write"]},
    )
    assert response.status_code == 400


def test_revoked_api_token_is_rejected(client, admin_user, auth_header):
    headers = auth_header(admin_user)
    created = _create_api_token(client, headers, scopes=["products:read"])

    with client.application.app_context():
        token_row = db.session.get(ApiToken, created["api_token"]["id"])
        token_row.revoked_at = db.func.now()
        db.session.add(token_row)
        db.session.commit()

    denied = client.get("/api/auth/me", headers={"Authorization": f"Bearer {created['token']}"})
    assert denied.status_code == 401


def test_self_service_revoke_for_other_users_token_forbidden(client, admin_user, user_factory, auth_header):
    analyst = user_factory(role="Analyst")

    with client.application.app_context():
        token = ApiToken(name="foreign", secret_hash="x" * 64, owner_id=analyst.id, scopes=["products:read"])
        db.session.add(token)
        db.session.commit()
        db.session.refresh(token)
        token_id = token.id

    resp = client.post(f"/api/users/me/api-tokens/{token_id}/revoke", headers=auth_header(admin_user))
    assert resp.status_code == 403
