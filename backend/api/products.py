from datetime import datetime

from flask import Blueprint, jsonify, request
from sqlalchemy import asc

from ..database import db
from ..models import Product, ProductOwner, ProductVersion, User
from ..auth import login_required, role_required

bp = Blueprint("products_api", __name__, url_prefix="/api")

def _version_json(v: ProductVersion):
    return {
        "id": v.id,
        "product_id": v.product_id,
        "version": v.version,
        "release_date": v.release_date.isoformat() if v.release_date else None,
        "is_active": v.is_active,
        "created_at": v.created_at.isoformat(),
        "updated_at": v.updated_at.isoformat(),
    }


def _product_json(p: Product, include_details: bool = False):
    data = {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "created_at": p.created_at.isoformat(),
        "updated_at": p.updated_at.isoformat(),
        "version_count": len(p.versions or []),
    }

    if include_details:
        data["owners"] = [{
            "id": o.user.id,
            "username": o.user.username,
            "email": o.user.email,
            "full_name": " ".join(filter(None, [o.user.first_name, o.user.last_name])).strip() or o.user.username,
        } for o in p.owners]
        data["owner_ids"] = [o.user_id for o in p.owners]
        data["versions"] = [_version_json(v) for v in sorted(p.versions, key=lambda x: x.version)]
        if p.creator:
            data["created_by"] = {
                "id": p.creator.id,
                "username": p.creator.username,
                "full_name": " ".join(filter(None, [p.creator.first_name, p.creator.last_name])).strip() or p.creator.username,
            }

    return data


def _parse_date(date_str):
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str).date()
    except ValueError:
        return None


@bp.get("/products")
@login_required
def list_products():
    products = Product.query.order_by(asc(Product.name)).all()
    return jsonify([_product_json(p) for p in products])

@bp.post("/products")
@role_required("Admin", "Analyst")
def create_product():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    p = Product(
        name=name,
        description=data.get("description"),
        created_by=getattr(request, "user", None).id if getattr(request, "user", None) else None,
    )
    db.session.add(p)
    db.session.commit()
    return jsonify({"id": p.id, "name": p.name, "description": p.description}), 201

@bp.get("/products/<int:product_id>")
@login_required
def get_product(product_id: int):
    p = Product.query.get_or_404(product_id)
    return jsonify(_product_json(p, include_details=True))


@bp.patch("/products/<int:product_id>")
@role_required("Admin", "Analyst")
def update_product(product_id: int):
    p = Product.query.get_or_404(product_id)
    data = request.get_json(silent=True) or {}

    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name cannot be empty"}), 400
        p.name = name

    if "description" in data:
        p.description = data.get("description")

    if "owner_ids" in data:
        owner_ids = data.get("owner_ids") or []
        if not isinstance(owner_ids, list):
            return jsonify({"error": "owner_ids must be a list"}), 400
        owner_ids = [int(oid) for oid in owner_ids]
        if owner_ids:
            owners = User.query.filter(User.id.in_(owner_ids), User.is_active.is_(True)).all()
            found_ids = {o.id for o in owners}
            missing = set(owner_ids) - found_ids
            if missing:
                return jsonify({"error": f"Invalid owners: {', '.join(map(str, sorted(missing)))}"}), 400
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

    db.session.commit()
    return jsonify(_product_json(p, include_details=True))


@bp.delete("/products/<int:product_id>")
@role_required("Admin")
def delete_product(product_id: int):
    p = Product.query.get_or_404(product_id)
    db.session.delete(p)
    db.session.commit()
    return jsonify({"ok": True})


@bp.get("/products/<int:product_id>/versions")
@login_required
def list_versions(product_id: int):
    versions = ProductVersion.query.filter_by(product_id=product_id).order_by(asc(ProductVersion.version)).all()
    return jsonify([_version_json(v) for v in versions])

@bp.post("/products/<int:product_id>/versions")
@role_required("Admin", "Analyst")
def create_version(product_id: int):
    data = request.get_json(silent=True) or {}
    version = (data.get("version") or "").strip()
    if not version:
        return jsonify({"error": "version is required"}), 400

    release_date = _parse_date(data.get("release_date"))
    if data.get("release_date") and not release_date:
        return jsonify({"error": "Invalid release_date format; expected ISO date"}), 400

    v = ProductVersion(
        product_id=product_id,
        version=version,
        release_date=release_date,
        is_active=bool(data.get("is_active", True)),
    )
    db.session.add(v)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Duplicate version for product (or invalid data)"}), 400

    return jsonify(_version_json(v)), 201


@bp.patch("/products/<int:product_id>/versions/<int:version_id>")
@role_required("Admin", "Analyst")
def update_version(product_id: int, version_id: int):
    v = ProductVersion.query.filter_by(product_id=product_id, id=version_id).first_or_404()
    data = request.get_json(silent=True) or {}

    if "version" in data:
        version_value = (data.get("version") or "").strip()
        if not version_value:
            return jsonify({"error": "version cannot be empty"}), 400
        v.version = version_value

    if "release_date" in data:
        release_date = _parse_date(data.get("release_date"))
        if data.get("release_date") and not release_date:
            return jsonify({"error": "Invalid release_date format; expected ISO date"}), 400
        v.release_date = release_date

    if "is_active" in data:
        v.is_active = bool(data.get("is_active"))

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Unable to update version (duplicate?)"}), 400

    return jsonify(_version_json(v))


@bp.delete("/products/<int:product_id>/versions/<int:version_id>")
@role_required("Admin", "Analyst")
def delete_version(product_id: int, version_id: int):
    v = ProductVersion.query.filter_by(product_id=product_id, id=version_id).first_or_404()
    db.session.delete(v)
    db.session.commit()
    return jsonify({"ok": True})
