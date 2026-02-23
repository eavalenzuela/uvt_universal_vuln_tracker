from datetime import date, datetime

from ..database import db

class ReportSchedule(db.Model):
    __tablename__ = "report_schedules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    report_type = db.Column(db.String(30), nullable=False, default="vulnerabilities")
    frequency = db.Column(db.String(20), nullable=False, default="daily")
    delivery_channel = db.Column(db.String(20), nullable=False, default="email")
    recipient = db.Column(db.String(255), nullable=False)
    recipients_json = db.Column(db.JSON, default=list, nullable=False)
    timezone = db.Column(db.String(64), nullable=False, default="UTC")
    filter_preset = db.Column(db.String(120))
    filters_json = db.Column(db.JSON)
    delivery_preferences_json = db.Column(db.JSON, default=dict, nullable=False)
    report_template_id = db.Column(db.Integer, db.ForeignKey("report_templates.id", ondelete="SET NULL"), index=True)

    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    last_run_at = db.Column(db.DateTime)
    last_run_status = db.Column(db.String(30), nullable=False, default="never")
    last_failure_reason = db.Column(db.Text)
    last_attempted_at = db.Column(db.DateTime)
    retry_count = db.Column(db.Integer, nullable=False, default=0)
    next_retry_at = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    creator = db.relationship("User", foreign_keys=[created_by])
    report_template = db.relationship("ReportTemplate", foreign_keys=[report_template_id])

class ReportTemplate(db.Model):
    __tablename__ = "report_templates"
    __table_args__ = (
        db.CheckConstraint("visibility IN ('private', 'team')", name="ck_report_templates_visibility"),
        db.UniqueConstraint("owner_id", "name", name="unique_report_template_owner_name"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    report_type = db.Column(db.String(30), nullable=False, default="vulnerabilities")
    fields_json = db.Column(db.JSON, default=list, nullable=False)
    filters_json = db.Column(db.JSON, default=dict, nullable=False)
    export_format = db.Column(db.String(10), nullable=False, default="csv")
    delivery_channel = db.Column(db.String(20), nullable=False, default="email")
    recipients_json = db.Column(db.JSON, default=list, nullable=False)
    delivery_preferences_json = db.Column(db.JSON, default=dict, nullable=False)
    visibility = db.Column(db.String(20), default="private", nullable=False, index=True)

    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    owner = db.relationship("User", foreign_keys=[owner_id])

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

class ReportArtifact(db.Model):
    __tablename__ = "report_artifacts"

    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(30), nullable=False, index=True)
    format = db.Column(db.String(10), nullable=False)
    storage_path = db.Column(db.String(1024), nullable=False)
    checksum = db.Column(db.String(256))
    size = db.Column(db.BigInteger)
    content_type = db.Column(db.String(255))
    filters_json = db.Column(db.JSON)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    creator = db.relationship("User", foreign_keys=[created_by])
