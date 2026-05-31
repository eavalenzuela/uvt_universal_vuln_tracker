from datetime import datetime, timezone

from ..database import db, TZDateTime


class EmailVerificationToken(db.Model):
    __tablename__ = "email_verification_tokens"

    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(128), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    expires_at = db.Column(TZDateTime, nullable=False)
    used_at = db.Column(TZDateTime)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    user = db.relationship("User")
