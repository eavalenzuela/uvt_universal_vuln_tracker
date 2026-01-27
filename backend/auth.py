import datetime
from functools import wraps

import jwt
from flask import current_app, request, jsonify
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash

from .database import db
from .models import User


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

def _get_bearer_token():
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = _get_bearer_token()
        if not token:
            return jsonify({"error": "Missing Bearer token"}), 401
        try:
            claims = verify_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        user = User.query.get(int(claims["sub"]))
        if not user or not user.is_active:
            return jsonify({"error": "User inactive or not found"}), 401

        token_version = int(claims.get("token_version", 0))
        if token_version != int(user.token_version or 0):
            return jsonify({"error": "Token revoked"}), 401

        issued_at = claims.get("iat")
        last_revoked_at = user.last_revoked_at
        if issued_at and last_revoked_at:
            try:
                issued_dt = datetime.datetime.utcfromtimestamp(issued_at) if isinstance(issued_at, (int, float)) else issued_at
                if issued_dt <= last_revoked_at:
                    return jsonify({"error": "Token revoked"}), 401
            except Exception:
                return jsonify({"error": "Invalid token"}), 401

        request.user = user  # simple attachment for downstream use
        request.jwt_claims = claims
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
