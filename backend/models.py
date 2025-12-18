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

class Product(db.Model):
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    creator = db.relationship("User", foreign_keys=[created_by])

    versions = db.relationship("ProductVersion", back_populates="product", cascade="all, delete-orphan")

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

    __table_args__ = (
        db.UniqueConstraint("product_id", "version", name="unique_product_version"),
    )

class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)

    cve_id = db.Column(db.String(20), unique=True, index=True)
    title = db.Column(db.String(500), nullable=False, index=True)
    description = db.Column(db.Text)

    severity = db.Column(db.String(20), default="Medium", nullable=False)  # Critical/High/Medium/Low/None
    cvss_score = db.Column(db.Numeric(3, 1))

    published_date = db.Column(db.Date)
    last_modified_date = db.Column(db.Date)

    status = db.Column(db.String(20), default="Open", nullable=False)  # Open/In Progress/Resolved/Closed

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    assigned_to = db.Column(db.Integer, db.ForeignKey("users.id"))

    creator = db.relationship("User", foreign_keys=[created_by])
    assignee = db.relationship("User", foreign_keys=[assigned_to])

    versions = db.relationship("VulnerabilityVersion", back_populates="vulnerability", cascade="all, delete-orphan")

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
