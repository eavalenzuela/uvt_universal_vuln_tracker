"""Tests for email verification on registration (F3)."""

import pytest

from backend.database import db
from backend.models import EmailVerificationToken, User
from backend.services.email_verification import (
    create_verification_token,
    validate_verification_token,
)


@pytest.fixture()
def verify_required(app):
    """Turn on REQUIRE_EMAIL_VERIFICATION for the test app."""
    app.config["REQUIRE_EMAIL_VERIFICATION"] = True
    return app


def _register(client, username="newuser", email="newuser@example.com"):
    return client.post("/api/auth/register", json={
        "username": username,
        "email": email,
        "password": "register-pass-123",
    })


def test_register_without_flag_auto_logs_in_and_is_verified(client, admin_user):
    """Default behavior (flag off) is unchanged: register returns a token."""
    resp = _register(client)
    assert resp.status_code == 201
    data = resp.get_json()
    assert "token" in data
    assert "email_verification_required" not in data

    user = User.query.filter_by(username="newuser").first()
    assert user.email_verified is True


def test_register_with_flag_creates_unverified_user_without_token(client, admin_user, verify_required):
    resp = _register(client)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["email_verification_required"] is True
    assert "token" not in data

    user = User.query.filter_by(username="newuser").first()
    assert user.email_verified is False

    # A verification token was created
    tokens = EmailVerificationToken.query.filter_by(user_id=user.id).all()
    assert len(tokens) == 1


def test_first_user_skips_verification_even_when_required(client, verify_required):
    """The bootstrap Admin must never be locked out of a fresh install."""
    resp = _register(client, username="firstadmin", email="first@example.com")
    assert resp.status_code == 201
    data = resp.get_json()
    assert "token" in data

    user = User.query.filter_by(username="firstadmin").first()
    assert user.role == "Admin"
    assert user.email_verified is True


def test_login_blocked_until_verified(client, admin_user, verify_required):
    _register(client)

    resp = client.post("/api/auth/login", json={
        "username": "newuser",
        "password": "register-pass-123",
    })
    assert resp.status_code == 403
    assert "not verified" in resp.get_json()["error"].lower()


def test_verify_email_success_then_login(client, admin_user, verify_required, app):
    _register(client)
    with app.app_context():
        user = User.query.filter_by(username="newuser").first()
        raw_token = create_verification_token(user)
        db.session.commit()

    resp = client.post("/api/auth/verify-email", json={"token": raw_token})
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True

    user = User.query.filter_by(username="newuser").first()
    assert user.email_verified is True

    login_resp = client.post("/api/auth/login", json={
        "username": "newuser",
        "password": "register-pass-123",
    })
    assert login_resp.status_code == 200


def test_verify_email_token_single_use(client, admin_user, verify_required, app):
    with app.app_context():
        user = User(username="pending", email="pending@example.com",
                    password_hash="x", email_verified=False)
        db.session.add(user)
        db.session.commit()
        raw_token = create_verification_token(user)
        db.session.commit()

    assert client.post("/api/auth/verify-email", json={"token": raw_token}).status_code == 200
    # Second use fails
    assert client.post("/api/auth/verify-email", json={"token": raw_token}).status_code == 400


def test_verify_email_invalid_token(client, app):
    resp = client.post("/api/auth/verify-email", json={"token": "bogus-token"})
    assert resp.status_code == 400


def test_verify_email_requires_token(client, app):
    resp = client.post("/api/auth/verify-email", json={})
    assert resp.status_code == 400


def test_resend_verification_returns_200_for_unverified(client, admin_user, verify_required, app):
    _register(client)

    resp = client.post("/api/auth/resend-verification", json={"email": "newuser@example.com"})
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True

    with app.app_context():
        user = User.query.filter_by(username="newuser").first()
        # The previous token was invalidated and a fresh one issued
        active = EmailVerificationToken.query.filter_by(user_id=user.id, used_at=None).all()
        assert len(active) == 1


def test_resend_verification_returns_200_for_unknown_email(client, app):
    resp = client.post("/api/auth/resend-verification", json={"email": "nobody@example.com"})
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True


def test_resend_verification_requires_email(client, app):
    resp = client.post("/api/auth/resend-verification", json={})
    assert resp.status_code == 400


def test_resend_verification_invalidates_previous_token(client, admin_user, verify_required, app):
    _register(client)
    with app.app_context():
        user = User.query.filter_by(username="newuser").first()
        first_token = create_verification_token(user)
        db.session.commit()

    client.post("/api/auth/resend-verification", json={"email": "newuser@example.com"})

    with app.app_context():
        assert validate_verification_token(first_token) is None
