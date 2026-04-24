from datetime import datetime, timezone

from ..database import db, TZDateTime


class Team(db.Model):
    __tablename__ = "teams"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(64), nullable=False, unique=True, index=True)
    description = db.Column(db.Text)
    is_default = db.Column(db.Boolean, default=False, nullable=False, index=True)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(
        TZDateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    memberships = db.relationship("UserTeam", back_populates="team", cascade="all, delete-orphan")


class UserTeam(db.Model):
    __tablename__ = "user_teams"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    team_id = db.Column(
        db.Integer, db.ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    role_in_team = db.Column(db.String(20))
    is_default = db.Column(db.Boolean, default=False, nullable=False, index=True)
    joined_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    user = db.relationship("User", foreign_keys=[user_id])
    team = db.relationship("Team", back_populates="memberships")

    __table_args__ = (
        db.UniqueConstraint("user_id", "team_id", name="unique_user_team"),
    )
