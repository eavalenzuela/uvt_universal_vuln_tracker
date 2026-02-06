from datetime import datetime, date
from .database import db

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

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    token_version = db.Column(db.Integer, default=1, nullable=False)
    last_revoked_at = db.Column(db.DateTime)


class SavedVulnerabilityFilter(db.Model):
    __tablename__ = "saved_vulnerability_filters"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    filter_json = db.Column(db.JSON, nullable=False)
    visibility = db.Column(db.String(20), default="private", nullable=False, index=True)
    is_default = db.Column(db.Boolean, default=False, nullable=False)

    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    owner = db.relationship("User", foreign_keys=[owner_id])

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Product(db.Model):
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    creator = db.relationship("User", foreign_keys=[created_by])

    owners = db.relationship("ProductOwner", back_populates="product", cascade="all, delete-orphan")
    versions = db.relationship("ProductVersion", back_populates="product", cascade="all, delete-orphan")
    control_links = db.relationship("ProductControl", back_populates="product", cascade="all, delete-orphan")
    controls = db.relationship("Control", secondary="product_controls", viewonly=True)

class ProductOwner(db.Model):
    __tablename__ = "product_owners"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    product = db.relationship("Product", back_populates="owners")
    user = db.relationship("User")

    __table_args__ = (
        db.UniqueConstraint("product_id", "user_id", name="unique_product_owner"),
    )

class ProductVersion(db.Model):
    __tablename__ = "product_versions"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, index=True)
    version = db.Column(db.String(50), nullable=False)
    release_date = db.Column(db.Date)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    product = db.relationship("Product", back_populates="versions")
    components = db.relationship("SoftwareComponent", back_populates="product_version", cascade="all, delete-orphan")

    __table_args__ = (
        db.UniqueConstraint("product_id", "version", name="unique_product_version"),
    )

class Control(db.Model):
    __tablename__ = "controls"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    framework = db.Column(db.String(255), index=True)
    description = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    product_links = db.relationship("ProductControl", back_populates="control", cascade="all, delete-orphan")
    products = db.relationship("Product", secondary="product_controls", viewonly=True)
    sources = db.relationship("ControlSource", back_populates="control", cascade="all, delete-orphan")


class ControlSource(db.Model):
    __tablename__ = "control_sources"

    id = db.Column(db.Integer, primary_key=True)
    control_id = db.Column(db.Integer, db.ForeignKey("controls.id", ondelete="CASCADE"), nullable=False, index=True)
    source = db.Column(db.String(100), nullable=False, index=True)
    source_control_id = db.Column(db.String(200), index=True)
    version = db.Column(db.String(100))
    source_url = db.Column(db.Text)
    raw_json = db.Column(db.JSON)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    control = db.relationship("Control", back_populates="sources")

    __table_args__ = (
        db.UniqueConstraint(
            "control_id",
            "source",
            "source_control_id",
            "version",
            name="unique_control_source",
        ),
    )

class ProductControl(db.Model):
    __tablename__ = "product_controls"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = db.Column(db.Integer, db.ForeignKey("controls.id", ondelete="CASCADE"), nullable=False, index=True)
    implementation_status = db.Column(db.String(50), default="Not Started", nullable=False)
    notes = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    product = db.relationship("Product", back_populates="control_links")
    control = db.relationship("Control", back_populates="product_links")

    __table_args__ = (
        db.UniqueConstraint("product_id", "control_id", name="unique_product_control"),
    )

class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)

    cve_id = db.Column(db.String(20), unique=True, index=True)
    title = db.Column(db.String(500), nullable=False, index=True)
    description = db.Column(db.Text)

    severity = db.Column(db.String(20), default="Medium", nullable=False)  # Critical/High/Medium/Low/None
    cvss_score = db.Column(db.Numeric(3, 1))
    attack_complexity = db.Column(db.String(20), default="Not Defined", nullable=False)
    confidentiality_impact = db.Column(db.String(20), default="Not Defined", nullable=False)
    integrity_impact = db.Column(db.String(20), default="Not Defined", nullable=False)
    availability_impact = db.Column(db.String(20), default="Not Defined", nullable=False)

    published_date = db.Column(db.Date)
    last_modified_date = db.Column(db.Date)

    status = db.Column(db.String(20), default="Open", nullable=False)  # Open/In Progress/Resolved/Closed
    sla_due_at = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    assigned_to = db.Column(db.Integer, db.ForeignKey("users.id"))

    creator = db.relationship("User", foreign_keys=[created_by])
    assignee = db.relationship("User", foreign_keys=[assigned_to])

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

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
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

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    vulnerability = db.relationship("Vulnerability", back_populates="watchers")
    user = db.relationship("User", foreign_keys=[user_id])
    added_by_user = db.relationship("User", foreign_keys=[added_by])

    __table_args__ = (
        db.UniqueConstraint("vulnerability_id", "user_id", name="unique_vulnerability_watcher"),
    )


class SoftwareComponent(db.Model):
    __tablename__ = "software_components"

    id = db.Column(db.Integer, primary_key=True)
    product_version_id = db.Column(db.Integer, db.ForeignKey("product_versions.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    version = db.Column(db.String(120), index=True)
    ecosystem = db.Column(db.String(80), index=True)
    purl = db.Column(db.String(500), index=True)
    cpe = db.Column(db.String(500), index=True)
    bom_ref = db.Column(db.String(500), index=True)
    component_type = db.Column(db.String(80), default="library", nullable=False)
    metadata_json = db.Column(db.JSON)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    product_version = db.relationship("ProductVersion", back_populates="components")
    parent_edges = db.relationship(
        "ComponentDependency",
        foreign_keys="ComponentDependency.parent_component_id",
        back_populates="parent_component",
        cascade="all, delete-orphan",
    )
    child_edges = db.relationship(
        "ComponentDependency",
        foreign_keys="ComponentDependency.child_component_id",
        back_populates="child_component",
        cascade="all, delete-orphan",
    )
    vulnerability_links = db.relationship("VulnerabilityComponent", back_populates="component", cascade="all, delete-orphan")

    __table_args__ = (
        db.UniqueConstraint("product_version_id", "bom_ref", name="unique_component_bom_ref"),
    )


class ComponentDependency(db.Model):
    __tablename__ = "component_dependencies"

    id = db.Column(db.Integer, primary_key=True)
    product_version_id = db.Column(db.Integer, db.ForeignKey("product_versions.id", ondelete="CASCADE"), nullable=False, index=True)
    parent_component_id = db.Column(db.Integer, db.ForeignKey("software_components.id", ondelete="CASCADE"), nullable=False, index=True)
    child_component_id = db.Column(db.Integer, db.ForeignKey("software_components.id", ondelete="CASCADE"), nullable=False, index=True)
    dependency_path = db.Column(db.Text)
    depth = db.Column(db.Integer, default=1, nullable=False)
    is_direct = db.Column(db.Boolean, default=True, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    parent_component = db.relationship("SoftwareComponent", foreign_keys=[parent_component_id], back_populates="parent_edges")
    child_component = db.relationship("SoftwareComponent", foreign_keys=[child_component_id], back_populates="child_edges")
    product_version = db.relationship("ProductVersion")

    __table_args__ = (
        db.UniqueConstraint("product_version_id", "parent_component_id", "child_component_id", name="unique_component_dependency"),
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

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

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

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

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

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    vulnerability_links = db.relationship("VulnerabilityAttackVector", back_populates="attack_vector", cascade="all, delete-orphan")

class TerminalImpact(db.Model):
    __tablename__ = "terminal_impacts"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True, index=True)
    description = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    vulnerability_links = db.relationship("VulnerabilityTerminalImpact", back_populates="terminal_impact", cascade="all, delete-orphan")

class VulnerabilityAttackVector(db.Model):
    __tablename__ = "vulnerability_attack_vectors"

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    attack_vector_id = db.Column(db.Integer, db.ForeignKey("attack_vectors.id", ondelete="CASCADE"), nullable=False, index=True)
    product_version_id = db.Column(db.Integer, db.ForeignKey("product_versions.id", ondelete="SET NULL"), index=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

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

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

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

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    vulnerability = db.relationship("Vulnerability", back_populates="sources")

    __table_args__ = (
        db.UniqueConstraint("vulnerability_id", "source", "source_id", name="unique_vuln_source"),
    )

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(100))
    table_name = db.Column(db.String(100))
    record_id = db.Column(db.Integer)

    old_values = db.Column(db.JSON)
    new_values = db.Column(db.JSON)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User")

class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id"))
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

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

    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    rule = db.relationship("NotificationRule")
    vulnerability = db.relationship("Vulnerability")


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
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    finished_at = db.Column(db.DateTime)
    status = db.Column(db.String(30), nullable=False)
    error = db.Column(db.Text)
    stats_json = db.Column(db.JSON)


class ExternalSourceState(db.Model):
    __tablename__ = "external_source_states"

    id = db.Column(db.Integer, primary_key=True)
    plugin_id = db.Column(db.String(255), nullable=False, index=True)
    source_key = db.Column(db.String(255), nullable=False, index=True)
    last_cursor = db.Column(db.Text)
    last_sync_at = db.Column(db.DateTime)

    __table_args__ = (
        db.UniqueConstraint("plugin_id", "source_key", name="unique_external_source_state"),
    )


class SlaPolicy(db.Model):
    __tablename__ = "sla_policies"

    id = db.Column(db.Integer, primary_key=True)
    policy_json = db.Column(db.JSON, nullable=False)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    updater = db.relationship("User", foreign_keys=[updated_by])


class ReportSchedule(db.Model):
    __tablename__ = "report_schedules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    report_type = db.Column(db.String(30), nullable=False, default="vulnerabilities")
    frequency = db.Column(db.String(20), nullable=False, default="daily")
    delivery_channel = db.Column(db.String(20), nullable=False, default="email")
    recipient = db.Column(db.String(255), nullable=False)
    filters_json = db.Column(db.JSON)

    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    last_run_at = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    creator = db.relationship("User", foreign_keys=[created_by])
