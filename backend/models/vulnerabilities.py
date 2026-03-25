from datetime import date, datetime, timezone

from ..database import db, TZDateTime

class SavedVulnerabilityFilter(db.Model):
    __tablename__ = "saved_vulnerability_filters"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    filter_json = db.Column(db.JSON, nullable=False)
    visibility = db.Column(db.String(20), default="private", nullable=False, index=True)
    is_default = db.Column(db.Boolean, default=False, nullable=False)

    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    owner = db.relationship("User", foreign_keys=[owner_id])

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

class DashboardLayoutPreset(db.Model):
    __tablename__ = "dashboard_layout_presets"
    __table_args__ = (
        db.CheckConstraint("visibility IN ('private', 'team')", name="ck_dashboard_layout_presets_visibility"),
        db.UniqueConstraint("owner_id", "name", name="unique_dashboard_layout_preset_owner_name"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    widget_config_json = db.Column(db.JSON, nullable=False)
    visibility = db.Column(db.String(20), default="private", nullable=False, index=True)
    is_default = db.Column(db.Boolean, default=False, nullable=False)

    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    owner = db.relationship("User", foreign_keys=[owner_id])

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        db.CheckConstraint("severity IN ('Critical', 'High', 'Medium', 'Low', 'None')", name="ck_vulnerabilities_severity"),
        db.CheckConstraint("status IN ('Open', 'In Progress', 'Resolved', 'Closed')", name="ck_vulnerabilities_status"),
        db.CheckConstraint("cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)", name="ck_vulnerabilities_cvss_score"),
    )

    id = db.Column(db.Integer, primary_key=True)

    cve_id = db.Column(db.String(20), unique=True, index=True)
    title = db.Column(db.String(500), nullable=False, index=True)
    description = db.Column(db.Text)

    severity = db.Column(db.String(20), default="Medium", nullable=False)  # Critical/High/Medium/Low/None
    cvss_score = db.Column(db.Numeric(3, 1))
    cvss_vector = db.Column(db.String(255))
    cvss_version = db.Column(db.String(16))
    cwe_id = db.Column(db.String(32), index=True)
    references_json = db.Column(db.JSON, default=list, nullable=False)
    attack_complexity = db.Column(db.String(20), default="Not Defined", nullable=False)
    confidentiality_impact = db.Column(db.String(20), default="Not Defined", nullable=False)
    integrity_impact = db.Column(db.String(20), default="Not Defined", nullable=False)
    availability_impact = db.Column(db.String(20), default="Not Defined", nullable=False)

    published_date = db.Column(db.Date)
    last_modified_date = db.Column(db.Date)

    status = db.Column(db.String(20), default="Open", nullable=False, index=True)  # Open/In Progress/Resolved/Closed
    sla_due_at = db.Column(TZDateTime)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    is_merged = db.Column(db.Boolean, default=False, nullable=False, index=True)
    merged_into_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="SET NULL"), index=True)
    merge_metadata_json = db.Column(db.JSON, default=dict, nullable=False)

    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    assigned_to = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)

    creator = db.relationship("User", foreign_keys=[created_by])
    assignee = db.relationship("User", foreign_keys=[assigned_to])
    merged_into = db.relationship("Vulnerability", remote_side=[id], foreign_keys=[merged_into_id])

    versions = db.relationship("VulnerabilityVersion", back_populates="vulnerability", cascade="all, delete-orphan")
    attack_vectors = db.relationship("VulnerabilityAttackVector", back_populates="vulnerability", cascade="all, delete-orphan")
    terminal_impacts = db.relationship("VulnerabilityTerminalImpact", back_populates="vulnerability", cascade="all, delete-orphan")
    sources = db.relationship("VulnerabilitySource", back_populates="vulnerability", cascade="all, delete-orphan")
    affected_components = db.relationship("VulnerabilityComponent", back_populates="vulnerability", cascade="all, delete-orphan")
    comments = db.relationship("VulnerabilityComment", back_populates="vulnerability", cascade="all, delete-orphan")
    watchers = db.relationship("VulnerabilityWatcher", back_populates="vulnerability", cascade="all, delete-orphan")

class VulnerabilityComment(db.Model):
    __tablename__ = "vulnerability_comments"

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), index=True)

    vulnerability = db.relationship("Vulnerability", back_populates="comments")
    author = db.relationship("User", foreign_keys=[author_id])
    updater = db.relationship("User", foreign_keys=[updated_by])

class VulnerabilityWatcher(db.Model):
    __tablename__ = "vulnerability_watchers"

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    added_by = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), index=True)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    vulnerability = db.relationship("Vulnerability", back_populates="watchers")
    user = db.relationship("User", foreign_keys=[user_id])
    added_by_user = db.relationship("User", foreign_keys=[added_by])

    __table_args__ = (
        db.UniqueConstraint("vulnerability_id", "user_id", name="unique_vulnerability_watcher"),
    )

class VulnerabilityComponent(db.Model):
    __tablename__ = "vulnerability_components"

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    component_id = db.Column(db.Integer, db.ForeignKey("software_components.id", ondelete="CASCADE"), nullable=False, index=True)
    source = db.Column(db.String(100), nullable=False, index=True)
    match_type = db.Column(db.String(50), nullable=False)
    dependency_path = db.Column(db.Text)
    transitive_depth = db.Column(db.Integer, default=0, nullable=False)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    vulnerability = db.relationship("Vulnerability", back_populates="affected_components")
    component = db.relationship("SoftwareComponent", back_populates="vulnerability_links")

    __table_args__ = (
        db.UniqueConstraint("vulnerability_id", "component_id", "source", name="unique_vulnerability_component"),
    )

class VulnerabilityVersion(db.Model):
    __tablename__ = "vulnerability_versions"

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    product_version_id = db.Column(db.Integer, db.ForeignKey("product_versions.id", ondelete="CASCADE"), nullable=False, index=True)

    affected = db.Column(db.Boolean, default=True, nullable=False)
    fixed_in_version = db.Column(db.String(50))

    mitigation_status = db.Column(db.String(30), default="Not Started", nullable=False)
    notes = db.Column(db.Text)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    vulnerability = db.relationship("Vulnerability", back_populates="versions")
    product_version = db.relationship("ProductVersion")

    __table_args__ = (
        db.UniqueConstraint("vulnerability_id", "product_version_id", name="unique_vuln_version"),
    )

class AttackVector(db.Model):
    __tablename__ = "attack_vectors"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True, index=True)
    description = db.Column(db.Text)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    vulnerability_links = db.relationship("VulnerabilityAttackVector", back_populates="attack_vector", cascade="all, delete-orphan")

class TerminalImpact(db.Model):
    __tablename__ = "terminal_impacts"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True, index=True)
    description = db.Column(db.Text)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    vulnerability_links = db.relationship("VulnerabilityTerminalImpact", back_populates="terminal_impact", cascade="all, delete-orphan")

class VulnerabilityAttackVector(db.Model):
    __tablename__ = "vulnerability_attack_vectors"

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    attack_vector_id = db.Column(db.Integer, db.ForeignKey("attack_vectors.id", ondelete="CASCADE"), nullable=False, index=True)
    product_version_id = db.Column(db.Integer, db.ForeignKey("product_versions.id", ondelete="SET NULL"), index=True)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    vulnerability = db.relationship("Vulnerability", back_populates="attack_vectors")
    attack_vector = db.relationship("AttackVector", back_populates="vulnerability_links")
    product_version = db.relationship("ProductVersion")

    __table_args__ = (
        db.UniqueConstraint("vulnerability_id", "attack_vector_id", "product_version_id", name="unique_vuln_attack_vector"),
    )

class VulnerabilityTerminalImpact(db.Model):
    __tablename__ = "vulnerability_terminal_impacts"

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    terminal_impact_id = db.Column(db.Integer, db.ForeignKey("terminal_impacts.id", ondelete="CASCADE"), nullable=False, index=True)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    vulnerability = db.relationship("Vulnerability", back_populates="terminal_impacts")
    terminal_impact = db.relationship("TerminalImpact", back_populates="vulnerability_links")

    __table_args__ = (
        db.UniqueConstraint("vulnerability_id", "terminal_impact_id", name="unique_vuln_terminal_impact"),
    )

class VulnerabilitySource(db.Model):
    __tablename__ = "vulnerability_sources"

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    source = db.Column(db.String(100), nullable=False, index=True)
    source_id = db.Column(db.String(200), index=True)
    raw_json = db.Column(db.JSON)

    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    vulnerability = db.relationship("Vulnerability", back_populates="sources")

    __table_args__ = (
        db.UniqueConstraint("vulnerability_id", "source", "source_id", name="unique_vuln_source"),
    )

class SlaPolicy(db.Model):
    __tablename__ = "sla_policies"

    id = db.Column(db.Integer, primary_key=True)
    policy_json = db.Column(db.JSON, nullable=False)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    updater = db.relationship("User", foreign_keys=[updated_by])
