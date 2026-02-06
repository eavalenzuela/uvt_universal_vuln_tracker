from flask import Blueprint, jsonify, request, current_app

from ..database import db
from ..models import User
from ..auth import authenticate_user, create_user, generate_token, login_required
from ..rate_limiter import rate_limit

bp = Blueprint("auth_api", __name__, url_prefix="/api/auth")

@bp.post("/login")
@rate_limit("RATE_LIMIT_AUTH_LOGIN_LIMIT", "RATE_LIMIT_AUTH_LOGIN_WINDOW_SECONDS", identifier="auth_login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user = authenticate_user(username, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    return jsonify({
        "token": token,
        "user": {"id": user.id, "username": user.username, "email": user.email, "role": user.role}
    })

@bp.post("/register")
def register():
    
    if not current_app.config.get("ALLOW_PUBLIC_REGISTRATION", False):
        return jsonify({"error": "Registration disabled"}), 403

    """
    Simple bootstrap rule:
    - If there are no users yet, the first registered user becomes Admin.
    - Otherwise default role is Analyst.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "username, email, password are required"}), 400

    role = "Admin" if User.query.count() == 0 else "Analyst"

    try:
        user = create_user(username=username, email=email, password=password, role=role)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

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