"""Email verification on registration (F3): token creation, validation, and email delivery."""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app

from ..database import db
from ..models import EmailVerificationToken, User

logger = logging.getLogger(__name__)

VERIFICATION_TOKEN_EXPIRY_MINUTES = 60 * 24  # 24 hours


def _token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_verification_token(user: User) -> str:
    """Create an email-verification token for *user* and return the raw (unhashed) token."""
    # Invalidate any outstanding tokens for this user
    EmailVerificationToken.query.filter(
        EmailVerificationToken.user_id == user.id,
        EmailVerificationToken.used_at.is_(None),
    ).update({"used_at": datetime.now(timezone.utc)}, synchronize_session=False)

    raw_token = secrets.token_urlsafe(48)
    record = EmailVerificationToken(
        token_hash=_token_hash(raw_token),
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=VERIFICATION_TOKEN_EXPIRY_MINUTES),
    )
    db.session.add(record)
    return raw_token


def validate_verification_token(raw_token: str) -> EmailVerificationToken | None:
    """Return the token record if valid, or None."""
    record = EmailVerificationToken.query.filter_by(token_hash=_token_hash(raw_token)).first()
    if not record:
        return None
    if record.used_at is not None:
        return None
    if record.expires_at <= datetime.now(timezone.utc):
        return None
    return record


def consume_verification_token(record: EmailVerificationToken) -> None:
    """Mark the token as used."""
    record.used_at = datetime.now(timezone.utc)
    db.session.add(record)


def send_verification_email(user: User, raw_token: str) -> None:
    """Best-effort email delivery of the verification link.

    Logs but does not raise on failure so callers (register / resend) can keep a
    non-enumerating response contract.
    """
    from .email_delivery import send_email, EmailDeliveryError

    frontend_base = current_app.config.get(
        "FRONTEND_URL", "http://127.0.0.1:5173"
    ).rstrip("/")
    verify_link = f"{frontend_base}/#/verify-email/{raw_token}"

    subject = "UVT — Verify Your Email"
    body = (
        f"Hello {user.username},\n\n"
        f"Welcome to UVT. Please confirm your email address to activate your account.\n\n"
        f"Click the link below to verify (valid for {VERIFICATION_TOKEN_EXPIRY_MINUTES // 60} hours):\n\n"
        f"  {verify_link}\n\n"
        f"If you did not create this account, you can safely ignore this email.\n"
    )

    try:
        send_email(recipient=user.email, subject=subject, body_text=body)
        logger.info("Verification email sent to user %s", user.id)
    except EmailDeliveryError:
        logger.warning("Failed to send verification email to user %s", user.id, exc_info=True)
