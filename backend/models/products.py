from datetime import date, datetime

from ..database import db

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
