"""Product service — DB operations extracted from product route handlers."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import asc
from sqlalchemy.exc import IntegrityError

from flask import request

from ..database import db
from ..models import Product, ProductOwner, ProductVersion, User, Control, ProductControl
from ..api.validation import ValidationError
from ..services.audit import model_snapshot, record_audit
from ..services.team_scope import team_scope, user_can_access_team


def _parse_date(date_str):
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str).date()
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Products
# ---------------------------------------------------------------------------

def list_products():
    """Return a query of products ordered by name, scoped to the caller's teams."""
    user = getattr(request, "user", None) if request else None
    return team_scope(Product.query, Product, user).order_by(asc(Product.name))


def get_product(product_id: int):
    """Fetch a single product visible to the caller, else 404.

    404 (not 403) matches the plan's "avoid existence oracle" rule.
    """
    user = getattr(request, "user", None) if request else None
    scoped = team_scope(Product.query, Product, user).filter(Product.id == product_id)
    product = scoped.first()
    if product is None:
        from flask import abort
        abort(404)
    return product


def create_product(name: str, description: str | None, created_by: int | None, team_id: int | None = None):
    """Create a new product, flush to obtain its id, and return it.

    F15: if ``team_id`` is not provided, derive it from the caller's active
    team (``request.current_team_id``). Non-admins cannot stamp a team they
    are not a member of.
    """
    name = (name or "").strip()
    if not name:
        raise ValidationError(error="name is required", field="name")

    user = getattr(request, "user", None) if request else None
    if team_id is None:
        team_id = getattr(request, "current_team_id", None) if request else None

    if not user_can_access_team(user, team_id):
        raise ValidationError(error="you are not a member of this team", field="team_id", status_code=403)

    p = Product(
        name=name,
        description=description,
        created_by=created_by,
        team_id=team_id,
    )
    db.session.add(p)
    db.session.flush()
    record_audit("CREATE", "products", p.id, new_values=model_snapshot(p))
    db.session.commit()
    return p


def update_product(product_id: int, data: dict):
    """Apply partial updates to a product and return the updated instance.

    Handles name, description, owner_ids, and controls.
    Raises ValidationError for invalid input.
    """
    p = get_product(product_id)
    old_values = model_snapshot(p)

    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            raise ValidationError(error="name cannot be empty", field="name")
        p.name = name

    if "description" in data:
        p.description = data.get("description")

    if "owner_ids" in data:
        owner_ids = data.get("owner_ids") or []
        if not isinstance(owner_ids, list):
            raise ValidationError(error="owner_ids must be a list", field="owner_ids")
        owner_ids = [int(oid) for oid in owner_ids]
        if owner_ids:
            owners = User.query.filter(User.id.in_(owner_ids), User.is_active.is_(True)).all()
            found_ids = {o.id for o in owners}
            missing = set(owner_ids) - found_ids
            if missing:
                raise ValidationError(
                    error=f"Invalid owners: {', '.join(map(str, sorted(missing)))}",
                    field="owner_ids",
                )
        else:
            owners = []

        existing = {o.user_id: o for o in p.owners}
        new_links = []
        for owner in owners:
            link = existing.get(owner.id)
            if not link:
                link = ProductOwner(product=p, user=owner)
            new_links.append(link)
        p.owners = new_links

    if "controls" in data:
        controls_data = data.get("controls") or []
        if not isinstance(controls_data, list):
            raise ValidationError(error="controls must be a list", field="controls")
        control_ids = []
        for entry in controls_data:
            if not isinstance(entry, dict):
                raise ValidationError(error="controls entries must be objects", field="controls")
            control_id = entry.get("control_id")
            if not control_id:
                raise ValidationError(error="control_id is required for each control", field="control_id")
            control_ids.append(int(control_id))
        if len(control_ids) != len(set(control_ids)):
            raise ValidationError(error="Duplicate control_id values are not allowed", field="controls")

        controls = []
        if control_ids:
            controls = Control.query.filter(Control.id.in_(control_ids)).all()
            found_ids = {c.id for c in controls}
            missing = set(control_ids) - found_ids
            if missing:
                raise ValidationError(
                    error=f"Invalid controls: {', '.join(map(str, sorted(missing)))}",
                    field="controls",
                )

        control_map = {c.id: c for c in controls}
        existing_links = {link.control_id: link for link in p.control_links}
        new_links = []
        for entry in controls_data:
            control_id = int(entry["control_id"])
            control = control_map.get(control_id)
            if not control:
                continue
            link = existing_links.get(control_id)
            if not link:
                link = ProductControl(product=p, control=control)
            link.implementation_status = entry.get("implementation_status") or link.implementation_status or "Not Started"
            link.notes = entry.get("notes")
            new_links.append(link)
        p.control_links = new_links

    record_audit("UPDATE", "products", p.id, old_values=old_values, new_values=model_snapshot(p))
    db.session.commit()
    return p


def delete_product(product_id: int):
    """Delete a product and return a snapshot of the old record."""
    p = get_product(product_id)
    snapshot = model_snapshot(p)
    record_audit("DELETE", "products", p.id, old_values=snapshot)
    db.session.delete(p)
    db.session.commit()
    return snapshot


# ---------------------------------------------------------------------------
# Product Versions
# ---------------------------------------------------------------------------

def list_versions(product_id: int):
    """Return versions for a product ordered by version string."""
    return (
        ProductVersion.query
        .filter_by(product_id=product_id)
        .order_by(asc(ProductVersion.version))
        .all()
    )


def create_version(product_id: int, version: str, release_date: str | None, is_active: bool = True):
    """Create a product version. Raises ValidationError on duplicate/integrity issues."""
    version = (version or "").strip()
    if not version:
        raise ValidationError(error="version is required", field="version")

    parsed_date = _parse_date(release_date)
    if release_date and not parsed_date:
        raise ValidationError(error="Invalid release_date format; expected ISO date", field="release_date")

    v = ProductVersion(
        product_id=product_id,
        version=version,
        release_date=parsed_date,
        is_active=bool(is_active),
    )
    db.session.add(v)
    try:
        db.session.flush()
        record_audit("CREATE", "product_versions", v.id, new_values=model_snapshot(v))
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise ValidationError(error="Duplicate version for product (or invalid data)", field="version")

    return v


def update_version(product_id: int, version_id: int, data: dict):
    """Apply partial updates to a product version.

    Raises ValidationError on invalid input or integrity constraint violations.
    """
    v = ProductVersion.query.filter_by(product_id=product_id, id=version_id).first_or_404()
    old_values = model_snapshot(v)

    if "version" in data:
        version_value = (data.get("version") or "").strip()
        if not version_value:
            raise ValidationError(error="version cannot be empty", field="version")
        v.version = version_value

    if "release_date" in data:
        parsed_date = _parse_date(data.get("release_date"))
        if data.get("release_date") and not parsed_date:
            raise ValidationError(error="Invalid release_date format; expected ISO date", field="release_date")
        v.release_date = parsed_date

    if "is_active" in data:
        v.is_active = bool(data.get("is_active"))

    try:
        record_audit("UPDATE", "product_versions", v.id, old_values=old_values, new_values=model_snapshot(v))
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise ValidationError(error="Unable to update version (duplicate?)", field="version")

    return v


def delete_version(product_id: int, version_id: int):
    """Delete a product version and return a snapshot of the old record."""
    v = ProductVersion.query.filter_by(product_id=product_id, id=version_id).first_or_404()
    snapshot = model_snapshot(v)
    record_audit("DELETE", "product_versions", v.id, old_values=snapshot)
    db.session.delete(v)
    db.session.commit()
    return snapshot
