import csv
import io
import secrets

from flask import Blueprint, jsonify, request, Response
from sqlalchemy import or_

from ..database import db
from ..models import User
from ..auth import role_required, hash_password, generate_token

bp = Blueprint("users_api", __name__, url_prefix="/api")

_ALLOWED_ROLES = {"Admin", "Analyst", "Viewer"}

def _user_json(u: User):
    full_name = " ".join(filter(None, [u.first_name, u.last_name])).strip()
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "full_name": full_name or None,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat(),
        "updated_at": u.updated_at.isoformat(),
    }


def _user_summary(u: User):
    full_name = " ".join(filter(None, [u.first_name, u.last_name])).strip()
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "full_name": full_name or None,
        "is_active": u.is_active,
    }

@bp.get("/users")
@role_required("Admin")
def list_users():
    query = User.query

    search = (request.args.get("search") or "").strip()
    role = (request.args.get("role") or "").strip()
    status = (request.args.get("status") or "").strip().lower()

    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                User.username.ilike(like),
                User.email.ilike(like),
                User.first_name.ilike(like),
                User.last_name.ilike(like),
            )
        )

    if role:
        if role not in _ALLOWED_ROLES:
            return jsonify({"error": "Invalid role filter"}), 400
        query = query.filter(User.role == role)

    if status:
        if status not in {"active", "disabled"}:
            return jsonify({"error": "Invalid status filter"}), 400
        query = query.filter(User.is_active.is_(status == "active"))

    users = query.order_by(User.username.asc()).all()
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


@bp.post("/users/invite")
@role_required("Admin")
def invite_user():
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    role = (data.get("role") or "Analyst").strip()
    password = (data.get("password") or "").strip() or secrets.token_urlsafe(10)

    if not username or not email:
        return jsonify({"error": "username and email are required"}), 400
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

    payload = _user_json(u)
    payload["temp_password"] = password
    return jsonify(payload), 201


@bp.get("/users/active")
@role_required("Admin", "Analyst")
def list_active_users():
    users = User.query.filter(User.is_active.is_(True)).order_by(User.username.asc()).all()
    return jsonify([_user_summary(u) for u in users])

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


@bp.post("/users/<int:user_id>/impersonate")
@role_required("Admin")
def impersonate(user_id: int):
    target = User.query.get_or_404(user_id)
    if not target.is_active:
        return jsonify({"error": "Cannot impersonate inactive user"}), 400

    token = generate_token(target.id, target.username, target.role)
    return jsonify({"token": token, "user": _user_json(target)})


@bp.post("/users/<int:user_id>/toggle-active")
@role_required("Admin")
def toggle_active(user_id: int):
    u = User.query.get_or_404(user_id)
    u.is_active = not u.is_active
    db.session.commit()
    return jsonify(_user_json(u))


@bp.get("/users/export")
@role_required("Admin")
def export_users():
    # reuse list filters for consistency
    filtered = list_users()
    # If list_users returned a tuple (response, status), handle errors
    if isinstance(filtered, tuple):
        resp, status = filtered
        if status != 200:
            return filtered
        data = resp.get_json()
    else:
        data = filtered.get_json()

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["username", "email", "role", "is_active", "created_at", "updated_at", "first_name", "last_name"])
    writer.writeheader()
    for u in data:
        writer.writerow({
            "username": u.get("username"),
            "email": u.get("email"),
            "role": u.get("role"),
            "is_active": "true" if u.get("is_active") else "false",
            "created_at": u.get("created_at"),
            "updated_at": u.get("updated_at"),
            "first_name": u.get("first_name") or "",
            "last_name": u.get("last_name") or "",
        })

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=users.csv"},
    )
