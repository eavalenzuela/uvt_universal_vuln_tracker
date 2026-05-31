from datetime import date, datetime, timezone

from ..database import db, TZDateTime

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))

    role = db.Column(db.String(20), default="Analyst", nullable=False)  # Admin/Analyst/Viewer
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=True, nullable=False)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    token_version = db.Column(db.Integer, default=1, nullable=False)
    last_revoked_at = db.Column(TZDateTime)
    refresh_tokens = db.relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    api_tokens = db.relationship("ApiToken", back_populates="owner", cascade="all, delete-orphan")

class ApiToken(db.Model):
    __tablename__ = "api_tokens"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    secret_hash = db.Column(db.String(128), unique=True, nullable=False, index=True)
    scopes = db.Column(db.JSON, default=list, nullable=False)
    expires_at = db.Column(TZDateTime, index=True)
    last_used_at = db.Column(TZDateTime)
    revoked_at = db.Column(TZDateTime)

    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    owner = db.relationship("User", back_populates="api_tokens")

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

class RefreshToken(db.Model):
    __tablename__ = "refresh_tokens"

    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(128), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    expires_at = db.Column(TZDateTime, nullable=False, index=True)
    revoked = db.Column(db.Boolean, default=False, nullable=False, index=True)
    revoked_at = db.Column(TZDateTime)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    user = db.relationship("User", back_populates="refresh_tokens")

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    action = db.Column(db.String(100))
    table_name = db.Column(db.String(100))
    record_id = db.Column(db.Integer)
    # F15: team context at time of mutation. NULL for cross-cutting actions
    # (login, user-admin) or records outside any team.
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id", ondelete="SET NULL"), index=True)

    old_values = db.Column(db.JSON)
    new_values = db.Column(db.JSON)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    user = db.relationship("User")
