import pytest

from backend.models import User
from backend.services.oidc import complete_oidc_login, upsert_user_from_claims, validate_id_token
from backend.services.oidc_mapping import map_claims_to_role


def test_map_claims_to_role_uses_mapping_and_default(app):
    with app.app_context():
        app.config["OIDC_ROLE_MAPPING"] = '{"uvt-admins": "Admin", "uvt-analysts": "Analyst"}'
        app.config["OIDC_DEFAULT_ROLE"] = "Viewer"

        assert map_claims_to_role({"groups": ["uvt-analysts"]}, app.config) == "Analyst"
        assert map_claims_to_role({"groups": ["unknown"]}, app.config) == "Viewer"


def test_upsert_user_from_claims_provisions_and_updates(app):
    with app.app_context():
        app.config["OIDC_ROLE_MAPPING"] = '{"uvt-admins": "Admin"}'
        app.config["OIDC_DEFAULT_ROLE"] = "Viewer"

        created = upsert_user_from_claims(
            {"email": "sso@example.com", "preferred_username": "sso-user", "groups": ["uvt-admins"]},
            app.config,
        )
        assert created.id is not None
        assert created.role == "Admin"

        updated = upsert_user_from_claims(
            {"email": "sso@example.com", "preferred_username": "renamed", "groups": []},
            app.config,
        )
        assert updated.id == created.id
        assert updated.username == "renamed"
        assert updated.role == "Viewer"
        assert User.query.count() == 1


def test_validate_id_token_uses_expected_audience_and_issuer(app, monkeypatch):
    with app.app_context():
        app.config["OIDC_CLIENT_ID"] = "uvt-client"
        app.config["OIDC_ISSUER"] = "https://issuer.example"

        class DummySigningKey:
            key = "public-key"

        class DummyJwksClient:
            def __init__(self, uri):
                assert uri == "https://issuer.example/jwks"

            def get_signing_key_from_jwt(self, token):
                assert token == "id-token"
                return DummySigningKey()

        captured = {}

        def fake_decode(token, key, algorithms, audience, issuer):
            captured.update(
                token=token,
                key=key,
                algorithms=algorithms,
                audience=audience,
                issuer=issuer,
            )
            return {"sub": "abc"}

        monkeypatch.setattr("backend.services.oidc.PyJWKClient", DummyJwksClient)
        monkeypatch.setattr("backend.services.oidc.jwt.decode", fake_decode)

        claims = validate_id_token(app.config, "id-token", {"jwks_uri": "https://issuer.example/jwks"})
        assert claims == {"sub": "abc"}
        assert captured["audience"] == "uvt-client"
        assert captured["issuer"] == "https://issuer.example"


def test_complete_oidc_login_rejects_invalid_state(app):
    with app.app_context():
        app.config["JWT_SECRET"] = "secret"
        with pytest.raises(Exception):
            complete_oidc_login(app.config, "code", "invalid-state")
