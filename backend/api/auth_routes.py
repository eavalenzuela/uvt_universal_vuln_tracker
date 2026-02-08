from flask import Blueprint, jsonify, request, current_app, redirect

from ..models import User
from ..auth import authenticate_user, create_user, generate_token, login_required
from ..rate_limiter import rate_limit
from ..services.oidc import build_login_redirect, complete_oidc_login, oidc_enabled
from .validation import ValidationError, error_response, required_string

bp = Blueprint("auth_api", __name__, url_prefix="/api/auth")


@bp.post("/login")
@rate_limit("RATE_LIMIT_AUTH_LOGIN_LIMIT", "RATE_LIMIT_AUTH_LOGIN_WINDOW_SECONDS", identifier="auth_login")
def login():
    data = request.get_json(silent=True) or {}
    try:
        username = required_string(data, "username")
        password = required_string(data, "password")
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    user = authenticate_user(username, password)
    if not user:
        return error_response("Invalid credentials", status_code=401)

    token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    return jsonify({
        "token": token,
        "user": {"id": user.id, "username": user.username, "email": user.email, "role": user.role}
    })


@bp.get("/providers")
def providers():
    return jsonify({
        "oidc": {
            "enabled": oidc_enabled(current_app.config),
            "login_url": "/api/auth/oidc/login",
        }
    })


@bp.get("/oidc/login")
def oidc_login():
    if not oidc_enabled(current_app.config):
        return error_response("OIDC disabled", status_code=404)

    next_path = request.args.get("next", "/")
    return redirect(build_login_redirect(current_app.config, next_path), code=302)


@bp.get("/oidc/callback")
def oidc_callback():
    if not oidc_enabled(current_app.config):
        return error_response("OIDC disabled", status_code=404)

    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state:
        return error_response("Missing OIDC callback parameters", status_code=400)

    try:
        result = complete_oidc_login(current_app.config, code, state)
    except Exception:
        return error_response("OIDC authentication failed", status_code=401)

    frontend_redirect = current_app.config.get("FRONTEND_LOGIN_SUCCESS_URL", "http://127.0.0.1:5173/login")
    response = redirect(frontend_redirect, code=302)
    response.set_cookie(
        "uvt_auth_token",
        result["token"],
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=12 * 60 * 60,
        path="/",
    )
    return response


@bp.post("/register")
def register():

    if not current_app.config.get("ALLOW_PUBLIC_REGISTRATION", False):
        return error_response("Registration disabled", status_code=403)

    """
    Simple bootstrap rule:
    - If there are no users yet, the first registered user becomes Admin.
    - Otherwise default role is Analyst.
    """
    data = request.get_json(silent=True) or {}
    try:
        username = required_string(data, "username")
        email = required_string(data, "email")
        password = required_string(data, "password")
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    role = "Admin" if User.query.count() == 0 else "Analyst"

    try:
        user = create_user(username=username, email=email, password=password, role=role)
    except ValueError as e:
        return error_response(str(e), status_code=400)

    token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    return jsonify({
        "token": token,
        "user": {"id": user.id, "username": user.username, "email": user.email, "role": user.role}
    }), 201


@bp.get("/me")
@login_required
def me():
    u = request.user
    return jsonify({"id": u.id, "username": u.username, "email": u.email, "role": u.role})
