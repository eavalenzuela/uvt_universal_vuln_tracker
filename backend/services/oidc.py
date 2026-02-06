import datetime
import json
import secrets
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import jwt
from jwt import PyJWKClient

from ..auth import create_user, generate_token, get_user_by_identity
from ..database import db
from ..models import User
from .oidc_mapping import map_claims_to_role


def _json_request(url: str, method="GET", data=None, headers=None):
    req = Request(url=url, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    payload = None
    if data is not None:
        payload = json.dumps(data).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    with urlopen(req, data=payload, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def oidc_enabled(config) -> bool:
    return bool(config.get("OIDC_ENABLED"))


def discover_oidc_config(config):
    issuer = (config.get("OIDC_ISSUER") or "").rstrip("/")
    if not issuer:
        raise ValueError("OIDC issuer not configured")
    return _json_request(f"{issuer}/.well-known/openid-configuration")


def build_login_redirect(config, next_path="/"):
    oidc = discover_oidc_config(config)
    state_payload = {
        "next": next_path or "/",
        "nonce": secrets.token_urlsafe(16),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10),
    }
    state = jwt.encode(state_payload, config["JWT_SECRET"], algorithm="HS256")

    query = urlencode({
        "client_id": config["OIDC_CLIENT_ID"],
        "response_type": "code",
        "scope": config.get("OIDC_SCOPES", "openid profile email"),
        "redirect_uri": config["OIDC_REDIRECT_URL"],
        "state": state,
    })
    return f"{oidc['authorization_endpoint']}?{query}"


def _exchange_code_for_tokens(config, code: str):
    oidc = discover_oidc_config(config)
    token_resp = _json_request(
        oidc["token_endpoint"],
        method="POST",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config["OIDC_REDIRECT_URL"],
            "client_id": config["OIDC_CLIENT_ID"],
            "client_secret": config["OIDC_CLIENT_SECRET"],
        },
    )
    return token_resp, oidc


def validate_id_token(config, id_token: str, oidc_metadata: dict):
    jwks_client = PyJWKClient(oidc_metadata["jwks_uri"])
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    return jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256", "ES256"],
        audience=config["OIDC_CLIENT_ID"],
        issuer=config["OIDC_ISSUER"],
    )


def upsert_user_from_claims(claims: dict, config) -> User:
    email = claims.get("email")
    username = claims.get("preferred_username") or claims.get("name") or email
    if not email or not username:
        raise ValueError("OIDC claims missing email/username")

    role = map_claims_to_role(claims, config)

    user = get_user_by_identity(email) or get_user_by_identity(username)
    if not user:
        user = create_user(
            username=username,
            email=email,
            password=secrets.token_urlsafe(24),
            role=role,
        )
    else:
        user.username = username
        user.email = email
        user.role = role
        user.is_active = True
        db.session.add(user)
        db.session.commit()

    return user


def complete_oidc_login(config, code: str, state: str):
    jwt.decode(state, config["JWT_SECRET"], algorithms=["HS256"])
    token_response, oidc_metadata = _exchange_code_for_tokens(config, code)
    id_token = token_response.get("id_token")
    if not id_token:
        raise ValueError("Missing id_token from provider")

    claims = validate_id_token(config, id_token, oidc_metadata)
    user = upsert_user_from_claims(claims, config)

    app_token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    return {
        "token": app_token,
        "user": {"id": user.id, "username": user.username, "email": user.email, "role": user.role},
    }
