import csv
import io
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request, Response
from sqlalchemy import or_

from ..database import db
from ..models import ApiToken, User
from ..auth import role_required, hash_password, generate_token, revoke_tokens, validate_password, PasswordTooWeakError
from ..permissions import ALL_ROLES, ROLE_SCOPES
from ..rate_limiter import rate_limit
from .validation import ValidationError, enum_value, error_response, parse_int, required_string
from ..serializers.users_serializers import serialize_api_token, serialize_user, serialize_user_summary
from ..services.audit import record_audit

bp = Blueprint("users_api", __name__, url_prefix="/api")

_ALLOWED_ROLES = ALL_ROLES


def _user_json(u: User):
    return serialize_user(u)


def _user_summary(u: User):
    return serialize_user_summary(u)


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
        expires_at = datetime.now(timezone.utc) + timedelta(days=days)

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


@bp.post("/users")
@role_required("Admin")
@rate_limit("RATE_LIMIT_SENSITIVE_LIMIT", "RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", identifier="create_user")
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
    try:
        validate_password(password)
    except PasswordTooWeakError as exc:
        return error_response(str(exc), field="password")
    if role not in _ALLOWED_ROLES:
        return error_response(f"Invalid role. Allowed: {', '.join(sorted(_ALLOWED_ROLES))}", field="role")

    if User.query.filter_by(username=username).first():
        return error_response("Username already exists", field="username")
    if User.query.filter_by(email=email).first():
        return error_response("Email already exists", field="email")

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
@rate_limit("RATE_LIMIT_SENSITIVE_LIMIT", "RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", identifier="invite_user")
def invite_user():
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    role = (data.get("role") or "Analyst").strip()
    user_supplied_password = (data.get("password") or "").strip()
    password = user_supplied_password or secrets.token_urlsafe(16)

    if not username or not email:
        return error_response("Required field missing", field="username", details="username and email are required")
    if user_supplied_password:
        try:
            validate_password(user_supplied_password)
        except PasswordTooWeakError as exc:
            return error_response(str(exc), field="password")
    if role not in _ALLOWED_ROLES:
        return error_response(f"Invalid role. Allowed: {', '.join(sorted(_ALLOWED_ROLES))}", field="role")

    if User.query.filter_by(username=username).first():
        return error_response("Username already exists", field="username")
    if User.query.filter_by(email=email).first():
        return error_response("Email already exists", field="email")

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
    query = User.query.filter(User.is_active.is_(True)).order_by(User.username.asc())
    try:
        from .validation import paginate_query
        users, meta = paginate_query(query)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify({"items": [_user_summary(u) for u in users], **meta})

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
            return error_response("Email already exists", field="email")
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
            return error_response(f"Invalid role. Allowed: {', '.join(sorted(_ALLOWED_ROLES))}", field="role")
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
        record_audit("UPDATE", "users", u.id, old_values=old_values or None, new_values=_user_json(u))

    db.session.commit()
    return jsonify(_user_json(u))

@bp.post("/users/<int:user_id>/reset-password")
@role_required("Admin")
@rate_limit("RATE_LIMIT_SENSITIVE_LIMIT", "RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", identifier="password_reset")
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
    try:
        validate_password(password)
    except PasswordTooWeakError as exc:
        return error_response(str(exc), field="password")

    u.password_hash = hash_password(password)
    revoke_tokens(u)
    record_audit("RESET_PASSWORD", "users", u.id, old_values={"password_reset": True})
    db.session.commit()
    return jsonify({"ok": True})


@bp.post("/users/<int:user_id>/impersonate")
@role_required("Admin")
@rate_limit("RATE_LIMIT_SENSITIVE_LIMIT", "RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", identifier="impersonate")
def impersonate(user_id: int):
    target = User.query.get_or_404(user_id)
    if not target.is_active:
        return error_response("Cannot impersonate inactive user")

    payload = request.get_json(silent=True) or {}
    reason = (payload.get("reason") or "").strip()
    if not reason:
        return error_response("reason is required to impersonate", field="reason")

    token = generate_token(target.id, target.username, target.role, target.token_version, target.last_revoked_at)
    record_audit("IMPERSONATE", "users", target.id,
                 old_values={"actor": request.user.username},
                 new_values={"impersonated": target.username, "reason": reason})
    db.session.commit()
    return jsonify({"token": token, "user": _user_json(target)})


@bp.post("/users/<int:user_id>/toggle-active")
@role_required("Admin")
def toggle_active(user_id: int):
    u = User.query.get_or_404(user_id)
    u.is_active = not u.is_active
    revoke_tokens(u)
    record_audit("TOGGLE_ACTIVE", "users", u.id,
                 old_values={"is_active": not u.is_active},
                 new_values={"is_active": u.is_active})
    db.session.commit()
    return jsonify(_user_json(u))


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
