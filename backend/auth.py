import datetime
import hashlib
import secrets
from functools import wraps

import jwt
from flask import current_app, request, jsonify
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash

from .database import db
from .models import ApiToken, RefreshToken, User
from .permissions import role_has_scope, scope_for_request


def revoke_tokens(user: User):
    user.token_version = int(user.token_version or 0) + 1
    user.last_revoked_at = datetime.datetime.utcnow()
    db.session.add(user)


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return check_password_hash(hashed_password, password)


def generate_token(user_id: int, username: str, role: str, token_version: int = 1, last_revoked_at=None) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "token_version": int(token_version or 1),
        "last_revoked_at": int(last_revoked_at.timestamp()) if last_revoked_at else None,
        "iat": now,
        "exp": now + datetime.timedelta(hours=12),
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm="HS256")


def verify_token(token: str):
    return jwt.decode(token, current_app.config["JWT_SECRET"], algorithms=["HS256"])


def _refresh_token_lifetime_days() -> int:
    return int(current_app.config.get("REFRESH_TOKEN_LIFETIME_DAYS", 30))


def _refresh_token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _api_token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _generate_api_token_secret() -> str:
    return f"uvt_{secrets.token_urlsafe(48)}"


def create_api_token(owner: User, name: str, scopes: list[str], expires_at=None):
    plaintext = _generate_api_token_secret()
    token_record = ApiToken(
        name=name,
        secret_hash=_api_token_hash(plaintext),
        owner_id=owner.id,
        scopes=sorted(set(scopes)),
        expires_at=expires_at,
    )
    db.session.add(token_record)
    return plaintext, token_record


def authenticate_api_token(raw_token: str):
    token_record = ApiToken.query.filter_by(secret_hash=_api_token_hash(raw_token)).first()
    if not token_record or token_record.revoked_at is not None:
        return None, (jsonify({"error": "Invalid token"}), 401)

    if token_record.expires_at and token_record.expires_at <= datetime.datetime.utcnow():
        return None, (jsonify({"error": "Token expired"}), 401)

    user = User.query.get(token_record.owner_id)
    if not user or not user.is_active:
        return None, (jsonify({"error": "User inactive or not found"}), 401)

    token_record.last_used_at = datetime.datetime.utcnow()
    db.session.add(token_record)
    request.user = user
    request.jwt_claims = None
    request.api_token = token_record
    return user, None


def create_refresh_token(user: User):
    raw_token = secrets.token_urlsafe(48)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=_refresh_token_lifetime_days())
    token_record = RefreshToken(
        token_hash=_refresh_token_hash(raw_token),
        user_id=user.id,
        expires_at=expires_at,
        revoked=False,
    )
    db.session.add(token_record)
    return raw_token, token_record


def find_refresh_token(raw_token: str):
    if not raw_token:
        return None
    return RefreshToken.query.filter_by(token_hash=_refresh_token_hash(raw_token)).first()


def revoke_refresh_token(raw_token: str):
    token_record = find_refresh_token(raw_token)
    if not token_record or token_record.revoked:
        return False
    token_record.revoked = True
    token_record.revoked_at = datetime.datetime.utcnow()
    db.session.add(token_record)
    return True


def revoke_all_refresh_tokens(user: User):
    now = datetime.datetime.utcnow()
    RefreshToken.query.filter(
        RefreshToken.user_id == user.id,
        RefreshToken.revoked.is_(False),
    ).update(
        {
            RefreshToken.revoked: True,
            RefreshToken.revoked_at: now,
        },
        synchronize_session=False,
    )


def rotate_refresh_token(raw_token: str):
    token_record = find_refresh_token(raw_token)
    if not token_record:
        return None, "invalid"
    if token_record.revoked:
        return None, "revoked"
    if token_record.expires_at <= datetime.datetime.utcnow():
        return None, "expired"

    user = User.query.get(token_record.user_id)
    if not user or not user.is_active:
        return None, "inactive"

    token_record.revoked = True
    token_record.revoked_at = datetime.datetime.utcnow()
    db.session.add(token_record)

    raw_new_refresh, _ = create_refresh_token(user)
    access_token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    return {
        "access_token": access_token,
        "refresh_token": raw_new_refresh,
        "user": user,
    }, None


def _get_bearer_token():
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()

    cookie_token = request.cookies.get("uvt_auth_token")
    if cookie_token:
        return cookie_token

    return None


def authenticate_request():
    token = _get_bearer_token()
    if not token:
        return None, None, (jsonify({"error": "Missing Bearer token"}), 401)
    try:
        claims = verify_token(token)
    except jwt.ExpiredSignatureError:
        user, error = authenticate_api_token(token)
        if error:
            return None, None, (jsonify({"error": "Token expired"}), 401)
        return user, None, None
    except jwt.InvalidTokenError:
        user, error = authenticate_api_token(token)
        if error:
            return None, None, (jsonify({"error": "Invalid token"}), 401)
        return user, None, None

    user = User.query.get(int(claims["sub"]))
    if not user or not user.is_active:
        return None, None, (jsonify({"error": "User inactive or not found"}), 401)

    token_version = int(claims.get("token_version", 0))
    if token_version != int(user.token_version or 0):
        return None, None, (jsonify({"error": "Token revoked"}), 401)

    issued_at = claims.get("iat")
    last_revoked_at = user.last_revoked_at
    if issued_at and last_revoked_at:
        try:
            issued_dt = (
                datetime.datetime.utcfromtimestamp(issued_at)
                if isinstance(issued_at, (int, float))
                else issued_at
            )
            if issued_dt <= last_revoked_at:
                return None, None, (jsonify({"error": "Token revoked"}), 401)
        except Exception:
            return None, None, (jsonify({"error": "Invalid token"}), 401)

    request.user = user
    request.jwt_claims = claims
    request.api_token = None
    return user, claims, None


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if getattr(request, "user", None) is None:
            _, _, error = authenticate_request()
            if error:
                return error
        return f(*args, **kwargs)

    return wrapper


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if getattr(request, "user", None) is None or request.user.role != "Admin":
            return jsonify({"error": "Admin required"}), 403
        return f(*args, **kwargs)

    return wrapper


def role_required(*allowed_roles: str):
    """
    Usage:
      @role_required("Admin", "Analyst")
    """
    allowed = set(allowed_roles)

    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            user = getattr(request, "user", None)
            if user is None:
                return jsonify({"error": "Unauthorized"}), 401
            if user.role not in allowed:
                return jsonify({"error": f"Requires role(s): {', '.join(sorted(allowed))}"}), 403
            return f(*args, **kwargs)

        return wrapper

    return decorator


def enforce_scopes(app):
    @app.before_request
    def _enforce_scopes():
        if request.method == "OPTIONS":
            return None
        scope = scope_for_request(request.path, request.method)
        if not scope:
            return None
        if getattr(request, "user", None) is None:
            _, _, error = authenticate_request()
            if error:
                return error
        user = getattr(request, "user", None)
        if user is None:
            return jsonify({"error": "Unauthorized"}), 401
        if not role_has_scope(user.role, scope):
            return jsonify({"error": "Forbidden"}), 403
        api_token = getattr(request, "api_token", None)
        if api_token is not None and scope not in set(api_token.scopes or []):
            return jsonify({"error": "Forbidden"}), 403
        return None


def get_user_by_id(user_id: int):
    return User.query.get(user_id)


def get_user_by_username(username: str):
    return User.query.filter_by(username=username).first()


def get_user_by_identity(identity: str):
    return User.query.filter(
        or_(
            User.username == identity,
            User.email == identity,
        )
    ).first()


def create_user(username, email, password, role="Analyst"):
    if get_user_by_username(username):
        raise ValueError("Username already exists")
    if User.query.filter_by(email=email).first():
        raise ValueError("Email already exists")

    user = User(username=username, email=email, password_hash=hash_password(password), role=role)
    db.session.add(user)
    db.session.commit()
    return user


def authenticate_user(username, password):
    user = get_user_by_identity(username)
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user
