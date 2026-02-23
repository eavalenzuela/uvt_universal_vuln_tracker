import csv
import io
import secrets
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request, Response
from sqlalchemy import or_

from ..database import db
from ..models import ApiToken, User, AuditLog
from ..auth import create_api_token, role_required, hash_password, generate_token, revoke_tokens
from ..permissions import ALL_ROLES, ROLE_SCOPES
from .validation import ValidationError, enum_value, error_response, parse_int, required_string
from ..serializers.users_serializers import serialize_api_token, serialize_user, serialize_user_summary

bp = Blueprint("users_api", __name__, url_prefix="/api")

_ALLOWED_ROLES = ALL_ROLES

def _user_json(u: User):
    return serialize_user(u)


def _user_summary(u: User):
    return serialize_user_summary(u)


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


def _api_token_json(token: ApiToken):
    return serialize_api_token(token)


def _parse_token_create_payload(data, owner: User):
    try:
        name = required_string(data, "name")
    except ValidationError as exc:
        return None, error_response(exc.error, field=exc.field, details=exc.details)

    requested_scopes = data.get("scopes")
    if not isinstance(requested_scopes, list) or not requested_scopes:
        return None, error_response("scopes must be a non-empty array", field="scopes")

    allowed_scopes = ROLE_SCOPES.get(owner.role, set())
    scopes = []
    for item in requested_scopes:
        if not isinstance(item, str) or not item.strip():
            return None, error_response("scope must be a non-empty string", field="scopes")
        scope = item.strip()
        if scope not in allowed_scopes:
            return None, error_response(
                "scope not permitted for owner role",
                field="scopes",
                details={"scope": scope, "allowed": sorted(allowed_scopes)},
            )
        scopes.append(scope)

    expires_in_days = data.get("expires_in_days")
    expires_at = None
    if expires_in_days is not None:
        try:
            days = parse_int(expires_in_days, field="expires_in_days", minimum=1, maximum=3650, required=True)
        except ValidationError as exc:
            return None, error_response(exc.error, field=exc.field, details=exc.details)
        expires_at = datetime.utcnow() + timedelta(days=days)

    return {
        "name": name,
        "scopes": sorted(set(scopes)),
        "expires_at": expires_at,
    }, None

@bp.get("/users")
@role_required("Admin")
def list_users():
    query = User.query

    try:
        page = parse_int(request.args.get("page"), field="page", minimum=1) or 1
        page_size = parse_int(request.args.get("page_size"), field="page_size", minimum=1, maximum=500) or 25
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

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
            return error_response("role must be one of allowed roles", field="role", details={"allowed": sorted(_ALLOWED_ROLES)})
        query = query.filter(User.role == role)

    if status:
        if status not in {"active", "disabled"}:
            return error_response("status must be one of ['active', 'disabled']", field="status", details={"allowed": ["active", "disabled"]})
        query = query.filter(User.is_active.is_(status == "active"))

    total = query.count()
    users = query.order_by(User.username.asc()).offset((page - 1) * page_size).limit(page_size).all()
    return jsonify({
        "items": [_user_json(u) for u in users],
        "total": total,
        "page": page,
        "page_size": page_size,
    })


@bp.get("/users/me/api-tokens")
@role_required("Admin", "Analyst", "Viewer")
def list_my_api_tokens():
    tokens = (
        ApiToken.query.filter_by(owner_id=request.user.id)
        .order_by(ApiToken.created_at.desc())
        .all()
    )
    return jsonify([_api_token_json(token) for token in tokens])


@bp.post("/users/me/api-tokens")
@role_required("Admin", "Analyst", "Viewer")
def create_my_api_token():
    payload = request.get_json(silent=True) or {}
    parsed, err = _parse_token_create_payload(payload, request.user)
    if err:
        return err

    plaintext, token = create_api_token(request.user, parsed["name"], parsed["scopes"], parsed["expires_at"])
    db.session.commit()
    return jsonify({"token": plaintext, "api_token": _api_token_json(token)}), 201


@bp.post("/users/me/api-tokens/<int:token_id>/revoke")
@role_required("Admin", "Analyst", "Viewer")
def revoke_my_api_token(token_id: int):
    token = ApiToken.query.get_or_404(token_id)
    if token.owner_id != request.user.id:
        return error_response("Forbidden", status_code=403)
    if token.revoked_at is None:
        token.revoked_at = datetime.utcnow()
        db.session.add(token)
        db.session.commit()
    return jsonify(_api_token_json(token))


@bp.get("/users/<int:user_id>/api-tokens")
@role_required("Admin")
def list_user_api_tokens(user_id: int):
    User.query.get_or_404(user_id)
    tokens = ApiToken.query.filter_by(owner_id=user_id).order_by(ApiToken.created_at.desc()).all()
    return jsonify([_api_token_json(token) for token in tokens])


@bp.post("/users/<int:user_id>/api-tokens")
@role_required("Admin")
def create_user_api_token(user_id: int):
    owner = User.query.get_or_404(user_id)
    payload = request.get_json(silent=True) or {}
    parsed, err = _parse_token_create_payload(payload, owner)
    if err:
        return err
    plaintext, token = create_api_token(owner, parsed["name"], parsed["scopes"], parsed["expires_at"])
    db.session.commit()
    return jsonify({"token": plaintext, "api_token": _api_token_json(token)}), 201


@bp.post("/users/<int:user_id>/api-tokens/<int:token_id>/revoke")
@role_required("Admin")
def revoke_user_api_token(user_id: int, token_id: int):
    token = ApiToken.query.get_or_404(token_id)
    if token.owner_id != user_id:
        return error_response("Token does not belong to user", status_code=404)
    if token.revoked_at is None:
        token.revoked_at = datetime.utcnow()
        db.session.add(token)
        db.session.commit()
    return jsonify(_api_token_json(token))

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
        return error_response("Required field missing", field="username", details="username, email, password are required")
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
        return error_response("Required field missing", field="username", details="username and email are required")
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
@role_required("Admin")
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
            return error_response("email cannot be empty", field="email")
        existing = User.query.filter(User.email == email, User.id != u.id).first()
        if existing:
            return jsonify({"error": "Email already exists"}), 400
        old_values["email"] = u.email
        u.email = email
        changed = True

    if "username" in data:
        # keep simple: disallow username change for now
        return error_response("username cannot be changed", field="username")

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
        return error_response("password is required", field="password")

    u.password_hash = hash_password(password)
    revoke_tokens(u)
    _audit(
        request.user.id,
        "RESET_PASSWORD",
        "users",
        u.id,
        old_values={"password_reset": True},
        new_values=None,
    )
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
        return error_response("reason is required to impersonate", field="reason")

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
    try:
        page = parse_int(request.args.get("page"), field="page", minimum=1) or 1
        page_size = parse_int(request.args.get("page_size"), field="page_size", minimum=1, maximum=500) or 100
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    action = (request.args.get("action") or "").strip()
    table = (request.args.get("table") or "").strip()

    query = AuditLog.query
    if action:
        query = query.filter(AuditLog.action == action)
    if table:
        query = query.filter(AuditLog.table_name == table)

    total = query.count()
    logs = query.order_by(AuditLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()

    def _user_payload(log: AuditLog):
        if not log.user:
            return None
        return {"id": log.user.id, "username": log.user.username, "email": log.user.email}

    return jsonify({
        "items": [
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
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    })


@bp.get("/users/export")
@role_required("Admin")
def export_users():
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
            return error_response("role must be one of allowed roles", field="role", details={"allowed": sorted(_ALLOWED_ROLES)})
        query = query.filter(User.role == role)

    if status:
        if status not in {"active", "disabled"}:
            return error_response("status must be one of ['active', 'disabled']", field="status", details={"allowed": ["active", "disabled"]})
        query = query.filter(User.is_active.is_(status == "active"))

    data = [_user_json(u) for u in query.order_by(User.username.asc()).all()]

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
