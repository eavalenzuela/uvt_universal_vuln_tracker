"""Self-service password reset: token creation, validation, and email delivery."""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app

from ..database import db
from ..models import PasswordResetToken, User

logger = logging.getLogger(__name__)

RESET_TOKEN_EXPIRY_MINUTES = 60


def _token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_reset_token(user: User) -> str:
    """Create a password-reset token for *user* and return the raw (unhashed) token."""
    # Invalidate any outstanding tokens for this user
    PasswordResetToken.query.filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at.is_(None),
    ).update({"used_at": datetime.now(timezone.utc)}, synchronize_session=False)

    raw_token = secrets.token_urlsafe(48)
    record = PasswordResetToken(
        token_hash=_token_hash(raw_token),
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_EXPIRY_MINUTES),
    )
    db.session.add(record)
    return raw_token


def validate_reset_token(raw_token: str) -> PasswordResetToken | None:
    """Return the token record if valid, or None."""
    record = PasswordResetToken.query.filter_by(token_hash=_token_hash(raw_token)).first()
    if not record:
        return None
    if record.used_at is not None:
        return None
    if record.expires_at <= datetime.now(timezone.utc):
        return None
    return record


def consume_reset_token(record: PasswordResetToken) -> None:
    """Mark the token as used."""
    record.used_at = datetime.now(timezone.utc)
    db.session.add(record)


def send_reset_email(user: User, raw_token: str) -> None:
    """Best-effort email delivery of the reset link.

    Logs but does not raise on failure so the endpoint always returns 200
    (prevents email enumeration).
    """
    from .email_delivery import send_email, EmailDeliveryError

    frontend_base = current_app.config.get(
        "FRONTEND_URL", "http://127.0.0.1:5173"
    ).rstrip("/")
    reset_link = f"{frontend_base}/#/reset-password/{raw_token}"

    subject = "UVT — Password Reset"
    body = (
        f"Hello {user.username},\n\n"
        f"A password reset was requested for your UVT account.\n\n"
        f"Click the link below to set a new password (valid for {RESET_TOKEN_EXPIRY_MINUTES} minutes):\n\n"
        f"  {reset_link}\n\n"
        f"If you did not request this, you can safely ignore this email.\n"
    )

    try:
        send_email(recipient=user.email, subject=subject, body_text=body)
        logger.info("Password-reset email sent to user %s", user.id)
    except EmailDeliveryError:
        logger.warning("Failed to send password-reset email to user %s", user.id, exc_info=True)
