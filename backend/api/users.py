from flask import Blueprint, jsonify, request

from ..database import db
from ..models import User
from ..auth import role_required, hash_password

bp = Blueprint("users_api", __name__, url_prefix="/api")

_ALLOWED_ROLES = {"Admin", "Analyst", "Viewer"}

def _user_json(u: User):
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat(),
        "updated_at": u.updated_at.isoformat(),
    }

@bp.get("/users")
@role_required("Admin")
def list_users():
    users = User.query.order_by(User.username.asc()).all()
    return jsonify([_user_json(u) for u in users])

@bp.post("/users")
@role_required("Admin")
def create_user_admin():
    """
    Create a user (Admin-only).
    Body:
      { "username": "...", "email": "...", "password": "...", "role": "Analyst|Viewer|Admin", ... }
    """
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    role = (data.get("role") or "Analyst").strip()

    if not username or not email or not password:
        return jsonify({"error": "username, email, password are required"}), 400
    if role not in _ALLOWED_ROLES:
        return jsonify({"error": f"Invalid role. Allowed: {', '.join(sorted(_ALLOWED_ROLES))}"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400

    u = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role=role,
        is_active=bool(data.get("is_active", True)),
        first_name=data.get("first_name"),
        last_name=data.get("last_name"),
    )
    db.session.add(u)
    db.session.commit()
    return jsonify(_user_json(u)), 201

@bp.get("/users/<int:user_id>")
@role_required("Admin")
def get_user(user_id: int):
    u = User.query.get_or_404(user_id)
    return jsonify(_user_json(u))

@bp.patch("/users/<int:user_id>")
@role_required("Admin")
def update_user(user_id: int):
    """
    Patch fields:
      email, first_name, last_name, role, is_active
    """
    u = User.query.get_or_404(user_id)
    data = request.get_json(silent=True) or {}

    if "email" in data:
        email = (data.get("email") or "").strip()
        if not email:
            return jsonify({"error": "email cannot be empty"}), 400
        existing = User.query.filter(User.email == email, User.id != u.id).first()
        if existing:
            return jsonify({"error": "Email already exists"}), 400
        u.email = email

    if "username" in data:
        # keep simple: disallow username change for now
        return jsonify({"error": "username cannot be changed"}), 400

    if "first_name" in data:
        u.first_name = data.get("first_name")
    if "last_name" in data:
        u.last_name = data.get("last_name")

    if "role" in data:
        role = (data.get("role") or "").strip()
        if role not in _ALLOWED_ROLES:
            return jsonify({"error": f"Invalid role. Allowed: {', '.join(sorted(_ALLOWED_ROLES))}"}), 400
        u.role = role

    if "is_active" in data:
        u.is_active = bool(data.get("is_active"))

    db.session.commit()
    return jsonify(_user_json(u))

@bp.post("/users/<int:user_id>/reset-password")
@role_required("Admin")
def reset_password(user_id: int):
    """
    Body:
      { "password": "newpass" }
    """
    u = User.query.get_or_404(user_id)
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    if not password:
        return jsonify({"error": "password is required"}), 400

    u.password_hash = hash_password(password)
    db.session.commit()
    return jsonify({"ok": True})
