from datetime import date, datetime, timezone

from ..database import db, TZDateTime

class PluginConfig(db.Model):
    __tablename__ = "plugin_configs"

    id = db.Column(db.Integer, primary_key=True)
    plugin_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    config_json = db.Column(db.JSON)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    schedule_cron = db.Column(db.String(120))
    interval_minutes = db.Column(db.Integer)

class PluginRun(db.Model):
    __tablename__ = "plugin_runs"

    id = db.Column(db.Integer, primary_key=True)
    plugin_id = db.Column(db.String(255), nullable=False, index=True)
    started_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    finished_at = db.Column(TZDateTime)
    status = db.Column(db.String(30), nullable=False)
    error = db.Column(db.Text)
    stats_json = db.Column(db.JSON)

    artifacts = db.relationship("PluginRunArtifact", back_populates="plugin_run", cascade="all, delete-orphan")

class PluginRunArtifact(db.Model):
    __tablename__ = "plugin_run_artifacts"

    id = db.Column(db.Integer, primary_key=True)
    plugin_run_id = db.Column(db.Integer, db.ForeignKey("plugin_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_type = db.Column(db.String(100), nullable=False, index=True)
    storage_path = db.Column(db.String(1024), nullable=False)
    checksum = db.Column(db.String(256))
    size = db.Column(db.BigInteger)
    content_type = db.Column(db.String(255))
    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    plugin_run = db.relationship("PluginRun", back_populates="artifacts")
    links = db.relationship("PluginRunArtifactLink", back_populates="artifact", cascade="all, delete-orphan")

class PluginRunArtifactLink(db.Model):
    __tablename__ = "plugin_run_artifact_links"

    id = db.Column(db.Integer, primary_key=True)
    artifact_id = db.Column(db.Integer, db.ForeignKey("plugin_run_artifacts.id", ondelete="CASCADE"), nullable=False, index=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    product_version_id = db.Column(db.Integer, db.ForeignKey("product_versions.id", ondelete="CASCADE"), index=True)
    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    artifact = db.relationship("PluginRunArtifact", back_populates="links")
    vulnerability = db.relationship("Vulnerability")
    product_version = db.relationship("ProductVersion")

    __table_args__ = (
        db.CheckConstraint(
            "vulnerability_id IS NOT NULL OR product_version_id IS NOT NULL",
            name="ck_plugin_run_artifact_links_has_target",
        ),
        db.UniqueConstraint(
            "artifact_id",
            "vulnerability_id",
            "product_version_id",
            name="unique_plugin_run_artifact_link",
        ),
    )

class ExternalSourceState(db.Model):
    __tablename__ = "external_source_states"

    id = db.Column(db.Integer, primary_key=True)
    plugin_id = db.Column(db.String(255), nullable=False, index=True)
    source_key = db.Column(db.String(255), nullable=False, index=True)
    last_cursor = db.Column(db.Text)
    last_sync_at = db.Column(TZDateTime)

    __table_args__ = (
        db.UniqueConstraint("plugin_id", "source_key", name="unique_external_source_state"),
    )
