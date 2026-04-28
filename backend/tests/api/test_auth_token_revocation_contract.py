from datetime import datetime, timedelta, timezone

from backend.auth import generate_token, revoke_tokens
from backend.database import db
from backend.models import User


def test_revoked_token_version_is_rejected(client, admin_user):
    stale_token = generate_token(
        admin_user.id,
        admin_user.username,
        admin_user.role,
        admin_user.token_version,
        admin_user.last_revoked_at,
    )

    with client.application.app_context():
        user = db.session.get(User, admin_user.id)
        revoke_tokens(user)
        db.session.commit()

    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {stale_token}"})
    assert me_resp.status_code == 401
    assert me_resp.get_json()["error"] == "Token revoked"


def test_token_issued_before_last_revocation_timestamp_is_rejected(client, admin_user):
    with client.application.app_context():
        user = db.session.get(User, admin_user.id)
        old_token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)

        user.last_revoked_at = datetime.now(timezone.utc) + timedelta(minutes=1)
        db.session.add(user)
        db.session.commit()

    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {old_token}"})
    assert me_resp.status_code == 401
    assert me_resp.get_json()["error"] == "Token revoked"


def test_malformed_token_is_rejected(client, admin_user):
    with client.application.app_context():
        user = db.session.get(User, admin_user.id)
        user.last_revoked_at = datetime.now(timezone.utc)
        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)

    token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    tampered = token.split(".")
    assert len(tampered) == 3

    # Keep signature invalid to hit InvalidToken path safely.
    broken_token = f"{tampered[0]}.{tampered[1]}invalid.{tampered[2]}"
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {broken_token}"})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid token"
