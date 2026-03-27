"""Tests for self-service password reset (S2 + F2)."""

from unittest.mock import patch

from backend.database import db
from backend.models import PasswordResetToken, User
from backend.services.password_reset import create_reset_token, validate_reset_token


def test_forgot_password_returns_200_for_known_email(client, admin_user):
    resp = client.post("/api/auth/forgot-password", json={"email": admin_user.email})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True

    # Token should have been created
    tokens = PasswordResetToken.query.filter_by(user_id=admin_user.id).all()
    assert len(tokens) == 1


def test_forgot_password_returns_200_for_unknown_email(client, app):
    resp = client.post("/api/auth/forgot-password", json={"email": "nobody@example.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True


def test_forgot_password_requires_email(client, app):
    resp = client.post("/api/auth/forgot-password", json={})
    assert resp.status_code == 400


def test_reset_password_success(client, admin_user, app):
    with app.app_context():
        raw_token = create_reset_token(admin_user)
        db.session.commit()

    resp = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "password": "new-secure-pass-123",
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True

    # Can log in with new password
    login_resp = client.post("/api/auth/login", json={
        "username": admin_user.username,
        "password": "new-secure-pass-123",
    })
    assert login_resp.status_code == 200

    # Old password no longer works
    old_login_resp = client.post("/api/auth/login", json={
        "username": admin_user.username,
        "password": "secret-pass-12",
    })
    assert old_login_resp.status_code == 401


def test_reset_password_token_single_use(client, admin_user, app):
    with app.app_context():
        raw_token = create_reset_token(admin_user)
        db.session.commit()

    # First use succeeds
    resp = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "password": "new-secure-pass-123",
    })
    assert resp.status_code == 200

    # Second use fails
    resp2 = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "password": "another-pass-12345",
    })
    assert resp2.status_code == 400


def test_reset_password_invalid_token(client, app):
    resp = client.post("/api/auth/reset-password", json={
        "token": "bogus-token",
        "password": "new-secure-pass-123",
    })
    assert resp.status_code == 400


def test_reset_password_weak_password(client, admin_user, app):
    with app.app_context():
        raw_token = create_reset_token(admin_user)
        db.session.commit()

    resp = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "password": "short",
    })
    assert resp.status_code == 400
    assert "12 characters" in resp.get_json()["error"]


def test_forgot_password_invalidates_previous_tokens(client, admin_user, app):
    with app.app_context():
        first_token = create_reset_token(admin_user)
        db.session.commit()

    # Request a second token
    client.post("/api/auth/forgot-password", json={"email": admin_user.email})

    # First token should be invalidated
    with app.app_context():
        record = validate_reset_token(first_token)
        assert record is None


def test_reset_email_sent_on_invite(client, admin_user, auth_header):
    headers = auth_header(admin_user)
    resp = client.post("/api/users/invite", headers=headers, json={
        "username": "newuser",
        "email": "newuser@example.com",
        "role": "Analyst",
    })
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["reset_email_sent"] is True
    assert "temp_password" not in data
