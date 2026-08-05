"""TOTP multi-factor authentication.

The Admin → Users page has always described itself as a place to manage "MFA
posture"; until now that was the only mention of MFA anywhere in the codebase.
This module makes the claim true.

Design notes:

* **TOTP (RFC 6238)** via ``pyotp`` — works with any authenticator app, needs
  no third-party service, and adds no outbound dependency.
* **Enrolment is two-phase.** ``begin_enrollment`` stores a secret but leaves
  ``mfa_enabled`` false; only ``confirm_enrollment``, which requires a valid
  code, flips the flag. A user therefore cannot lock themselves out by
  enrolling with a misconfigured app.
* **Recovery codes are stored hashed**, exactly like API tokens, and each is
  single-use.
* **The login challenge is a signed, short-lived token**, not server state, so
  it works across workers without a shared session store. It is bound to the
  user's ``token_version``, so revoking sessions also invalidates any
  outstanding challenge.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

import pyotp
from flask import current_app
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from ..database import db
from ..models import User

MFA_CHALLENGE_SALT = "uvt-mfa-challenge"
MFA_CHALLENGE_MAX_AGE_SECONDS = 300
RECOVERY_CODE_COUNT = 10
TOTP_VALID_WINDOW = 1  # accept the adjacent step, for clock skew


class MfaError(Exception):
    """Raised when an MFA operation cannot be completed."""


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=MFA_CHALLENGE_SALT)


def _hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").lower().encode("utf-8")).hexdigest()


def _generate_recovery_codes() -> tuple[list[str], list[str]]:
    """Return (plaintext codes shown once, hashes to persist)."""
    plaintext = [
        f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}"
        for _ in range(RECOVERY_CODE_COUNT)
    ]
    return plaintext, [_hash_recovery_code(code) for code in plaintext]


def begin_enrollment(user: User, *, issuer: str = "UVT") -> dict:
    """Generate a secret and provisioning URI. Does not enable MFA yet."""
    if user.mfa_enabled:
        raise MfaError("Multi-factor authentication is already enabled for this account")

    secret = pyotp.random_base32()
    user.mfa_secret = secret
    db.session.add(user)
    db.session.commit()

    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email or user.username, issuer_name=issuer)
    return {"secret": secret, "otpauth_uri": uri}


def confirm_enrollment(user: User, code: str) -> list[str]:
    """Verify the first code, enable MFA, and return one-time recovery codes."""
    if user.mfa_enabled:
        raise MfaError("Multi-factor authentication is already enabled for this account")
    if not user.mfa_secret:
        raise MfaError("Start enrolment before confirming it")
    if not verify_totp(user, code):
        raise MfaError("That code is not valid. Check your authenticator app's clock and try again.")

    plaintext, hashes = _generate_recovery_codes()
    user.mfa_enabled = True
    user.mfa_recovery_codes = hashes
    user.mfa_enrolled_at = datetime.now(timezone.utc)
    db.session.add(user)
    db.session.commit()
    return plaintext


def disable_mfa(user: User) -> None:
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_recovery_codes = []
    user.mfa_enrolled_at = None
    db.session.add(user)
    db.session.commit()


def verify_totp(user: User, code: str) -> bool:
    if not user.mfa_secret or not isinstance(code, str):
        return False
    cleaned = code.strip().replace(" ", "")
    if not cleaned.isdigit():
        return False
    return pyotp.TOTP(user.mfa_secret).verify(cleaned, valid_window=TOTP_VALID_WINDOW)


def consume_recovery_code(user: User, code: str) -> bool:
    """Spend a recovery code. Single-use: a match is removed from the list."""
    if not isinstance(code, str):
        return False
    stored = list(user.mfa_recovery_codes or [])
    candidate = _hash_recovery_code(code.strip())
    if candidate not in stored:
        return False
    stored.remove(candidate)
    user.mfa_recovery_codes = stored
    db.session.add(user)
    db.session.commit()
    return True


def issue_mfa_challenge(user: User) -> str:
    """Mint the short-lived token that stands between password and session."""
    return _serializer().dumps({
        "user_id": user.id,
        "token_version": int(user.token_version or 1),
    })


def resolve_mfa_challenge(token: str) -> User:
    """Validate a challenge token and return its user."""
    try:
        payload = _serializer().loads(token, max_age=MFA_CHALLENGE_MAX_AGE_SECONDS)
    except SignatureExpired as exc:
        raise MfaError("This sign-in attempt expired. Start again.") from exc
    except BadSignature as exc:
        raise MfaError("Invalid sign-in token") from exc

    user = db.session.get(User, payload.get("user_id"))
    if not user or not user.is_active or not user.mfa_enabled:
        raise MfaError("Invalid sign-in token")
    # Revoking a user's sessions must also kill any challenge already in flight.
    if int(payload.get("token_version", 0)) != int(user.token_version or 1):
        raise MfaError("This sign-in attempt is no longer valid. Start again.")
    return user
