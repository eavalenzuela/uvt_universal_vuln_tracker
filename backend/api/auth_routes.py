import secrets

from flask import Blueprint, jsonify, request, current_app, redirect

from ..database import db
from ..models import User
from ..auth import (
    authenticate_user,
    create_refresh_token,
    create_user,
    generate_token,
    hash_password,
    login_required,
    revoke_tokens,
    revoke_all_refresh_tokens,
    revoke_refresh_token,
    rotate_refresh_token,
    validate_password,
    PasswordTooWeakError,
)
from ..rate_limiter import rate_limit
from ..services.audit import record_audit
from ..services.oidc import build_login_redirect, complete_oidc_login, oidc_enabled, validate_next_path
from ..services.password_reset import (
    create_reset_token,
    validate_reset_token,
    consume_reset_token,
    send_reset_email,
)
from ..services.email_verification import (
    create_verification_token,
    validate_verification_token,
    consume_verification_token,
    send_verification_email,
)
from .validation import ValidationError, error_response, required_string

bp = Blueprint("auth_api", __name__, url_prefix="/api/auth")


def _auth_response(user, access_token, refresh_token=None):
    payload = {
        "token": access_token,
        "user": {"id": user.id, "username": user.username, "email": user.email, "role": user.role},
    }
    if refresh_token:
        payload["refresh_token"] = refresh_token
    return payload


def _generate_csrf_token():
    return secrets.token_urlsafe(32)


def _set_csrf_cookie(response, csrf_token):
    response.set_cookie(
        "uvt_csrf_token",
        csrf_token,
        httponly=False,
        secure=current_app.config.get("AUTH_COOKIE_SECURE", True),
        samesite=current_app.config.get("AUTH_COOKIE_SAMESITE", "Lax"),
        domain=current_app.config.get("AUTH_COOKIE_DOMAIN"),
        max_age=12 * 60 * 60,
        path="/",
    )
    return response


def _clear_auth_cookie(response):
    response.set_cookie(
        "uvt_csrf_token",
        "",
        httponly=False,
        secure=current_app.config.get("AUTH_COOKIE_SECURE", True),
        samesite=current_app.config.get("AUTH_COOKIE_SAMESITE", "Lax"),
        domain=current_app.config.get("AUTH_COOKIE_DOMAIN"),
        max_age=0,
        path="/",
    )
    response.set_cookie(
        "uvt_auth_token",
        "",
        httponly=True,
        secure=current_app.config.get("AUTH_COOKIE_SECURE", True),
        samesite=current_app.config.get("AUTH_COOKIE_SAMESITE", "Lax"),
        domain=current_app.config.get("AUTH_COOKIE_DOMAIN"),
        max_age=0,
        path="/",
    )
    return response


def _set_auth_cookie(response, token):
    response.set_cookie(
        "uvt_auth_token",
        token,
        httponly=True,
        secure=current_app.config.get("AUTH_COOKIE_SECURE", True),
        samesite=current_app.config.get("AUTH_COOKIE_SAMESITE", "Lax"),
        domain=current_app.config.get("AUTH_COOKIE_DOMAIN"),
        max_age=12 * 60 * 60,
        path="/",
    )
    return response


def _issue_csrf_token(payload=None):
    csrf_token = _generate_csrf_token()
    if payload is not None:
        payload["csrf_token"] = csrf_token
    return csrf_token


@bp.post("/login")
@rate_limit("RATE_LIMIT_AUTH_LOGIN_LIMIT", "RATE_LIMIT_AUTH_LOGIN_WINDOW_SECONDS", identifier="auth_login")
def login():
    """Authenticate a user with username and password.
    ---
    post:
      summary: Log in with username and password
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [username, password]
              properties:
                username:
                  type: string
                password:
                  type: string
      responses:
        200:
          description: Authentication successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthResponse'
        401:
          description: Invalid credentials
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        422:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    data = request.get_json(silent=True) or {}
    try:
        username = required_string(data, "username")
        password = required_string(data, "password")
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    user = authenticate_user(username, password)
    if not user:
        return error_response("Invalid credentials", status_code=401)

    if current_app.config.get("REQUIRE_EMAIL_VERIFICATION", False) and not user.email_verified:
        return error_response(
            "Email not verified. Check your inbox for the verification link.",
            status_code=403,
        )

    token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    refresh_token, _ = create_refresh_token(user)
    db.session.commit()
    payload = _auth_response(user, token, refresh_token)
    csrf_token = _issue_csrf_token(payload)
    response = jsonify(payload)
    response = _set_auth_cookie(response, token)
    return _set_csrf_cookie(response, csrf_token)


@bp.post("/refresh")
def refresh():
    """Rotate a refresh token and issue new access and refresh tokens.
    ---
    post:
      summary: Refresh access token using a refresh token
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [refresh_token]
              properties:
                refresh_token:
                  type: string
      responses:
        200:
          description: Token refreshed successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthResponse'
        400:
          description: Missing refresh token
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        401:
          description: Invalid refresh token
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        return error_response("Missing refresh token", field="refresh_token", status_code=400)

    result, reason = rotate_refresh_token(refresh_token.strip())
    if reason:
        return error_response("Invalid refresh token", status_code=401)

    db.session.commit()
    payload = _auth_response(result["user"], result["access_token"], result["refresh_token"])
    csrf_token = _issue_csrf_token(payload)
    response = jsonify(payload)
    response = _set_auth_cookie(response, result["access_token"])
    return _set_csrf_cookie(response, csrf_token)


@bp.post("/logout")
def logout():
    """Log out the current session and optionally revoke a refresh token.
    ---
    post:
      summary: Log out and optionally revoke a refresh token
      requestBody:
        required: false
        content:
          application/json:
            schema:
              type: object
              properties:
                refresh_token:
                  type: string
      responses:
        200:
          description: Logged out successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Ok'
    """
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token")
    if isinstance(refresh_token, str) and refresh_token.strip():
        revoke_refresh_token(refresh_token.strip())
        db.session.commit()
    return _clear_auth_cookie(jsonify({"ok": True}))


@bp.post("/logout_all")
@login_required
def logout_all():
    """Revoke all access and refresh tokens for the current user.
    ---
    post:
      summary: Log out all sessions for the current user
      security:
        - BearerAuth: []
      responses:
        200:
          description: All sessions revoked
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Ok'
        401:
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    revoke_tokens(request.user)
    revoke_all_refresh_tokens(request.user)
    db.session.commit()
    return _clear_auth_cookie(jsonify({"ok": True}))


@bp.get("/providers")
def providers():
    """Return available authentication providers and their status.
    ---
    get:
      summary: List available authentication providers
      responses:
        200:
          description: Authentication providers info
          content:
            application/json:
              schema:
                type: object
                properties:
                  oidc:
                    type: object
                    properties:
                      enabled:
                        type: boolean
                      login_url:
                        type: string
    """
    return jsonify({
        "oidc": {
            "enabled": oidc_enabled(current_app.config),
            "login_url": "/api/auth/oidc/login",
        }
    })


@bp.get("/oidc/login")
def oidc_login():
    """Initiate OIDC login by redirecting to the identity provider.
    ---
    get:
      summary: Redirect to OIDC identity provider for login
      parameters:
        - in: query
          name: next
          schema:
            type: string
          required: false
          description: Path to redirect to after successful login
      responses:
        302:
          description: Redirect to OIDC provider
        404:
          description: OIDC is disabled
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    if not oidc_enabled(current_app.config):
        return error_response("OIDC disabled", status_code=404)

    next_path = request.args.get("next", "/")
    return redirect(build_login_redirect(current_app.config, next_path), code=302)


@bp.get("/oidc/callback")
def oidc_callback():
    """Handle the OIDC provider callback after authentication.
    ---
    get:
      summary: OIDC callback endpoint
      parameters:
        - in: query
          name: code
          schema:
            type: string
          required: true
          description: Authorization code from OIDC provider
        - in: query
          name: state
          schema:
            type: string
          required: true
          description: State parameter for CSRF protection
      responses:
        302:
          description: Redirect to frontend with auth cookie set
        400:
          description: Missing callback parameters
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        401:
          description: OIDC authentication failed
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        404:
          description: OIDC is disabled
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    if not oidc_enabled(current_app.config):
        return error_response("OIDC disabled", status_code=404)

    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state:
        return error_response("Missing OIDC callback parameters", status_code=400)

    try:
        result = complete_oidc_login(current_app.config, code, state)
    except Exception:
        current_app.logger.exception("OIDC callback failed")
        return error_response("OIDC authentication failed", status_code=401)

    frontend_redirect = current_app.config.get("FRONTEND_LOGIN_SUCCESS_URL", "http://127.0.0.1:5173/login")
    next_path = validate_next_path((result.get("state") or {}).get("next"), None)
    if next_path:
        frontend_redirect = f"{frontend_redirect.rstrip('/')}{next_path}"
    response = redirect(frontend_redirect, code=302)
    return _set_auth_cookie(response, result["token"])


@bp.post("/register")
@rate_limit("RATE_LIMIT_AUTH_LOGIN_LIMIT", "RATE_LIMIT_AUTH_LOGIN_WINDOW_SECONDS", identifier="auth_register")
def register():
    """Register a new user account. Simple bootstrap rule: if there are no
    users yet, the first registered user becomes Admin; otherwise the default
    role is Analyst.
    ---
    post:
      summary: Register a new user account
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [username, email, password]
              properties:
                username:
                  type: string
                email:
                  type: string
                  format: email
                password:
                  type: string
      responses:
        201:
          description: User registered successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthResponse'
        400:
          description: Invalid input or user creation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        403:
          description: Registration is disabled
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        422:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    if not current_app.config.get("ALLOW_PUBLIC_REGISTRATION", False):
        return error_response("Registration disabled", status_code=403)

    data = request.get_json(silent=True) or {}
    try:
        username = required_string(data, "username")
        email = required_string(data, "email")
        password = required_string(data, "password")
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    is_first_user = User.query.count() == 0
    role = "Admin" if is_first_user else "Analyst"

    try:
        user = create_user(username=username, email=email, password=password, role=role)
    except ValueError as e:
        return error_response(str(e), status_code=400)

    # The very first user (bootstrap Admin) is always trusted and skips
    # verification so an operator can never lock themselves out of a fresh
    # install that has no working mail server yet.
    if current_app.config.get("REQUIRE_EMAIL_VERIFICATION", False) and not is_first_user:
        user.email_verified = False
        db.session.add(user)
        raw_token = create_verification_token(user)
        db.session.commit()
        send_verification_email(user, raw_token)
        return jsonify({
            "ok": True,
            "email_verification_required": True,
            "message": "Account created. Check your email to verify your address before logging in.",
        }), 201

    token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    refresh_token, _ = create_refresh_token(user)
    db.session.commit()
    return jsonify(_auth_response(user, token, refresh_token)), 201


@bp.post("/forgot-password")
@rate_limit("RATE_LIMIT_SENSITIVE_LIMIT", "RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", identifier="forgot_password")
def forgot_password():
    """Request a password reset email. Always returns 200 to prevent email enumeration.
    ---
    post:
      summary: Request a password reset link via email
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email]
              properties:
                email:
                  type: string
                  format: email
      responses:
        200:
          description: Reset email sent if account exists
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/OkMessage'
        400:
          description: Email is required
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return error_response("Email is required", field="email", status_code=400)

    # Always return 200 to prevent email enumeration
    user = User.query.filter(db.func.lower(User.email) == email).first()
    if user and user.is_active:
        raw_token = create_reset_token(user)
        db.session.commit()
        send_reset_email(user, raw_token)

    return jsonify({"ok": True, "message": "If an account with that email exists, a reset link has been sent."})


@bp.post("/reset-password")
@rate_limit("RATE_LIMIT_SENSITIVE_LIMIT", "RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", identifier="reset_password")
def reset_password():
    """Reset a user password using a valid reset token.
    ---
    post:
      summary: Reset password with a reset token
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [token, password]
              properties:
                token:
                  type: string
                password:
                  type: string
      responses:
        200:
          description: Password reset successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/OkMessage'
        400:
          description: Invalid input, weak password, or invalid/expired token
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    password = data.get("password") or ""

    if not token:
        return error_response("Reset token is required", field="token", status_code=400)
    if not password:
        return error_response("Password is required", field="password", status_code=400)

    record = validate_reset_token(token)
    if not record:
        return error_response("Invalid or expired reset token", status_code=400)

    user = db.session.get(User, record.user_id)
    if not user or not user.is_active:
        return error_response("Invalid or expired reset token", status_code=400)

    try:
        validate_password(password, username=user.username, email=user.email)
    except PasswordTooWeakError as exc:
        return error_response(str(exc), field="password", status_code=400)

    user.password_hash = hash_password(password)
    revoke_tokens(user)
    consume_reset_token(record)
    record_audit("RESET_PASSWORD", "users", user.id, old_values={"self_service": True})
    db.session.commit()

    return jsonify({"ok": True, "message": "Password has been reset. You can now log in."})


@bp.post("/verify-email")
@rate_limit("RATE_LIMIT_SENSITIVE_LIMIT", "RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", identifier="verify_email")
def verify_email():
    """Confirm a user's email address using a verification token.
    ---
    post:
      summary: Verify an email address with a verification token
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [token]
              properties:
                token:
                  type: string
      responses:
        200:
          description: Email verified successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/OkMessage'
        400:
          description: Invalid or expired verification token
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return error_response("Verification token is required", field="token", status_code=400)

    record = validate_verification_token(token)
    if not record:
        return error_response("Invalid or expired verification token", status_code=400)

    user = db.session.get(User, record.user_id)
    if not user or not user.is_active:
        return error_response("Invalid or expired verification token", status_code=400)

    user.email_verified = True
    consume_verification_token(record)
    record_audit("VERIFY_EMAIL", "users", user.id, old_values={"self_service": True})
    db.session.commit()

    return jsonify({"ok": True, "message": "Email verified. You can now log in."})


@bp.post("/resend-verification")
@rate_limit("RATE_LIMIT_SENSITIVE_LIMIT", "RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", identifier="resend_verification")
def resend_verification():
    """Request a fresh email-verification link. Always returns 200 to prevent email enumeration.
    ---
    post:
      summary: Resend the email-verification link
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email]
              properties:
                email:
                  type: string
                  format: email
      responses:
        200:
          description: Verification email sent if an unverified account exists
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/OkMessage'
        400:
          description: Email is required
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return error_response("Email is required", field="email", status_code=400)

    # Always return 200 to prevent email enumeration
    user = User.query.filter(db.func.lower(User.email) == email).first()
    if user and user.is_active and not user.email_verified:
        raw_token = create_verification_token(user)
        db.session.commit()
        send_verification_email(user, raw_token)

    return jsonify({"ok": True, "message": "If an unverified account with that email exists, a verification link has been sent."})


@bp.get("/csrf")
def csrf_token():
    """Return or generate a CSRF token for cookie-based auth.
    ---
    get:
      summary: Get a CSRF token
      responses:
        200:
          description: CSRF token returned
          content:
            application/json:
              schema:
                type: object
                properties:
                  csrf_token:
                    type: string
    """
    existing = request.cookies.get("uvt_csrf_token")
    csrf_token = existing or _issue_csrf_token()
    response = jsonify({"csrf_token": csrf_token})
    if not existing:
        response = _set_csrf_cookie(response, csrf_token)
    return response


@bp.get("/me")
@login_required
def me():
    """Return the current authenticated user's profile information.
    ---
    get:
      summary: Get current user profile
      security:
        - BearerAuth: []
      responses:
        200:
          description: Current user info
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: integer
                  username:
                    type: string
                  email:
                    type: string
                  role:
                    type: string
        401:
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    u = request.user
    from ..models import Team, UserTeam
    from ..services.team_scope import resolve_current_team_id

    memberships = UserTeam.query.filter_by(user_id=u.id).all()
    team_ids = [m.team_id for m in memberships]
    teams = Team.query.filter(Team.id.in_(team_ids)).all() if team_ids else []
    teams_payload = [
        {"id": t.id, "slug": t.slug, "name": t.name, "is_default": t.is_default}
        for t in teams
    ]
    return jsonify({
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "teams": teams_payload,
        "current_team_id": resolve_current_team_id(u),
    })
