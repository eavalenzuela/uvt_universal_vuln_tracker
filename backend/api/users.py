import csv
import io
import secrets

from flask import Blueprint, jsonify, request, Response
from sqlalchemy import or_

from datetime import datetime

from ..database import db
from ..models import User, AuditLog
from ..auth import role_required, hash_password, generate_token, revoke_tokens

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


def _audit(user_id, action, table, record_id, old_values=None, new_values=None):
    db.session.add(
        AuditLog(
            user_id=user_id,
            action=action,
            table_name=table,
            record_id=record_id,
            old_values=old_values,
            new_values=new_values,
            created_at=datetime.utcnow(),
        )
    )

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

    changed = False
    old_values = {}

    if "email" in data:
        email = (data.get("email") or "").strip()
        if not email:
            return jsonify({"error": "email cannot be empty"}), 400
        existing = User.query.filter(User.email == email, User.id != u.id).first()
        if existing:
            return jsonify({"error": "Email already exists"}), 400
        old_values["email"] = u.email
        u.email = email
        changed = True

    if "username" in data:
        # keep simple: disallow username change for now
        return jsonify({"error": "username cannot be changed"}), 400

    if "first_name" in data:
        old_values["first_name"] = u.first_name
        u.first_name = data.get("first_name")
        changed = True
    if "last_name" in data:
        old_values["last_name"] = u.last_name
        u.last_name = data.get("last_name")
        changed = True

    role_changed = False
    if "role" in data:
        role = (data.get("role") or "").strip()
        if role not in _ALLOWED_ROLES:
            return jsonify({"error": f"Invalid role. Allowed: {', '.join(sorted(_ALLOWED_ROLES))}"}), 400
        old_values["role"] = u.role
        u.role = role
        role_changed = True
        changed = True

    is_active_changed = False
    if "is_active" in data:
        is_active_changed = bool(data.get("is_active")) != bool(u.is_active)
        old_values["is_active"] = u.is_active
        u.is_active = bool(data.get("is_active"))
        changed = True

    if role_changed or is_active_changed:
        revoke_tokens(u)

    if changed:
        _audit(request.user.id, "UPDATE", "users", u.id, old_values=old_values or None, new_values=_user_json(u))

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

    old_password_hash = u.password_hash
    u.password_hash = hash_password(password)
    revoke_tokens(u)
    _audit(request.user.id, "RESET_PASSWORD", "users", u.id, old_values={"password_hash": old_password_hash}, new_values=None)
    db.session.commit()
    return jsonify({"ok": True})


@bp.post("/users/<int:user_id>/impersonate")
@role_required("Admin")
def impersonate(user_id: int):
    target = User.query.get_or_404(user_id)
    if not target.is_active:
        return jsonify({"error": "Cannot impersonate inactive user"}), 400

    payload = request.get_json(silent=True) or {}
    reason = (payload.get("reason") or "").strip()
    if not reason:
        return jsonify({"error": "reason is required to impersonate"}), 400

    token = generate_token(target.id, target.username, target.role, target.token_version, target.last_revoked_at)
    _audit(
        request.user.id,
        "IMPERSONATE",
        "users",
        target.id,
        old_values={"actor": request.user.username},
        new_values={"impersonated": target.username, "reason": reason},
    )
    db.session.commit()
    return jsonify({"token": token, "user": _user_json(target)})


@bp.post("/users/<int:user_id>/toggle-active")
@role_required("Admin")
def toggle_active(user_id: int):
    u = User.query.get_or_404(user_id)
    u.is_active = not u.is_active
    revoke_tokens(u)
    _audit(
        request.user.id,
        "TOGGLE_ACTIVE",
        "users",
        u.id,
        old_values={"is_active": not u.is_active},
        new_values={"is_active": u.is_active},
    )
    db.session.commit()
    return jsonify(_user_json(u))


@bp.get("/audit-logs")
@role_required("Admin")
def list_audit_logs():
    limit = request.args.get("limit")
    try:
        limit = int(limit) if limit is not None else 100
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid limit"}), 400
    limit = max(1, min(limit, 500))

    action = (request.args.get("action") or "").strip()
    table = (request.args.get("table") or "").strip()

    query = AuditLog.query
    if action:
        query = query.filter(AuditLog.action == action)
    if table:
        query = query.filter(AuditLog.table_name == table)

    logs = query.order_by(AuditLog.created_at.desc()).limit(limit).all()

    def _user_payload(log: AuditLog):
        if not log.user:
            return None
        return {"id": log.user.id, "username": log.user.username, "email": log.user.email}

    return jsonify([
        {
            "id": log.id,
            "action": log.action,
            "table_name": log.table_name,
            "record_id": log.record_id,
            "old_values": log.old_values,
            "new_values": log.new_values,
            "created_at": log.created_at.isoformat() if log.created_at else None,
            "user": _user_payload(log),
        }
        for log in logs
    ])


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
