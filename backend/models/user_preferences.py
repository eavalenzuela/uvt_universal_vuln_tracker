from datetime import datetime, timezone

from ..database import db, TZDateTime


class UserPreferences(db.Model):
    """Per-user preferences (F16).

    One row per user. Created lazily on first GET/PUT; the row's absence means
    "use defaults", not "explicit opt-out".
    """

    __tablename__ = "user_preferences"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    timezone = db.Column(db.String(64), default="UTC", nullable=False)
    theme = db.Column(db.String(16), default="auto", nullable=False)  # auto / light / dark
    language = db.Column(db.String(8), default="en", nullable=False)

    default_vuln_filter_id = db.Column(
        db.Integer,
        db.ForeignKey("saved_vulnerability_filters.id", ondelete="SET NULL"),
        index=True,
    )
    default_dashboard_preset_id = db.Column(
        db.Integer,
        db.ForeignKey("dashboard_layout_presets.id", ondelete="SET NULL"),
        index=True,
    )

    notify_on_mention = db.Column(db.Boolean, default=True, nullable=False)
    notify_on_assignment = db.Column(db.Boolean, default=True, nullable=False)
    notify_on_watched_vuln_update = db.Column(db.Boolean, default=True, nullable=False)
    notify_on_sla_breach = db.Column(db.Boolean, default=True, nullable=False)

    email_digest_frequency = db.Column(db.String(16), default="off", nullable=False)  # off / daily / weekly

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(
        TZDateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    user = db.relationship("User", foreign_keys=[user_id])
    default_vuln_filter = db.relationship("SavedVulnerabilityFilter", foreign_keys=[default_vuln_filter_id])
    default_dashboard_preset = db.relationship("DashboardLayoutPreset", foreign_keys=[default_dashboard_preset_id])

    __table_args__ = (
        db.CheckConstraint("theme IN ('auto', 'light', 'dark')", name="ck_user_preferences_theme"),
        db.CheckConstraint(
            "email_digest_frequency IN ('off', 'daily', 'weekly')",
            name="ck_user_preferences_email_digest_frequency",
        ),
    )
