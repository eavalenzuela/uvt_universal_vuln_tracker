from datetime import datetime, timezone

from ..database import db, TZDateTime


class WebhookEndpoint(db.Model):
    __tablename__ = "webhook_endpoints"
    __table_args__ = (
        db.CheckConstraint(
            "source_type IN ('generic', 'github', 'dependabot', 'trivy', 'nessus', 'qualys')",
            name="ck_webhook_endpoints_source_type",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    source_type = db.Column(db.String(40), default="generic", nullable=False, index=True)
    secret_hash = db.Column(db.String(128), unique=True, nullable=False, index=True)
    is_enabled = db.Column(db.Boolean, default=True, nullable=False, index=True)

    product_version_id = db.Column(
        db.Integer,
        db.ForeignKey("product_versions.id", ondelete="SET NULL"),
        index=True,
    )

    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), index=True)
    owner = db.relationship("User", foreign_keys=[owner_id])
    product_version = db.relationship("ProductVersion", foreign_keys=[product_version_id])

    # F15: authoritative stamp on incoming payloads — endpoint declares which
    # team owns the vulns it ingests. If product_version_id is set, both must
    # agree (enforced at creation).
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id", ondelete="SET NULL"), index=True)
    team = db.relationship("Team", foreign_keys=[team_id])

    last_delivery_at = db.Column(TZDateTime)
    delivery_count = db.Column(db.Integer, default=0, nullable=False)
    failure_count = db.Column(db.Integer, default=0, nullable=False)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(
        TZDateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class WebhookDeliveryLog(db.Model):
    __tablename__ = "webhook_delivery_logs"

    id = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(
        db.Integer,
        db.ForeignKey("webhook_endpoints.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status = db.Column(db.String(20), nullable=False, index=True)  # success / rejected / error
    status_code = db.Column(db.Integer)
    payload_bytes = db.Column(db.Integer)
    vulnerabilities_ingested = db.Column(db.Integer, default=0, nullable=False)
    error_message = db.Column(db.Text)
    client_ip = db.Column(db.String(64))

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    endpoint = db.relationship("WebhookEndpoint")
