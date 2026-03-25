from datetime import date, datetime, timezone

from ..database import db, TZDateTime

class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id"))
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    user = db.relationship("User")
    vulnerability = db.relationship("Vulnerability")

class NotificationRule(db.Model):
    __tablename__ = "notification_rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    is_enabled = db.Column(db.Boolean, default=True, nullable=False)

    delivery_adapter = db.Column(db.String(20), nullable=False, default="slack")
    delivery_config = db.Column(db.JSON)

    severity_threshold = db.Column(db.String(20), nullable=False, default="Medium")
    notify_on_status_change = db.Column(db.Boolean, default=True, nullable=False)
    notify_on_assignment_change = db.Column(db.Boolean, default=True, nullable=False)
    product_scope = db.Column(db.JSON)
    frequency_days = db.Column(db.Integer, nullable=False, default=3)
    escalation_after_days = db.Column(db.Integer, nullable=False, default=7)
    channels = db.Column(db.JSON)
    recipients = db.Column(db.JSON)

    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    creator = db.relationship("User", foreign_keys=[created_by])

class NotificationDeliveryLog(db.Model):
    __tablename__ = "notification_delivery_logs"

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("notification_rules.id", ondelete="SET NULL"), index=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="SET NULL"), index=True)
    event_type = db.Column(db.String(50), nullable=False)
    delivery_adapter = db.Column(db.String(20), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    response_payload = db.Column(db.JSON)
    error_message = db.Column(db.Text)
    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    rule = db.relationship("NotificationRule")
    vulnerability = db.relationship("Vulnerability")

class NotificationDeliveryCheckpoint(db.Model):
    __tablename__ = "notification_delivery_checkpoints"

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("notification_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    last_notified_at = db.Column(TZDateTime)
    last_escalation_step = db.Column(db.Integer, nullable=False, default=0)
    last_event_type = db.Column(db.String(50))
    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    rule = db.relationship("NotificationRule")
    vulnerability = db.relationship("Vulnerability")

    __table_args__ = (
        db.UniqueConstraint("rule_id", "vulnerability_id", name="unique_notification_delivery_checkpoint"),
    )
