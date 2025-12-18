from flask import Blueprint, jsonify, request
from sqlalchemy import asc

from ..database import db
from ..models import Product, ProductVersion
from ..auth import login_required, role_required

bp = Blueprint("products_api", __name__, url_prefix="/api")

@bp.get("/products")
@login_required
def list_products():
    products = Product.query.order_by(asc(Product.name)).all()
    return jsonify([{
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "created_at": p.created_at.isoformat(),
        "updated_at": p.updated_at.isoformat(),
    } for p in products])

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

@bp.get("/products/<int:product_id>/versions")
@login_required
def list_versions(product_id: int):
    versions = ProductVersion.query.filter_by(product_id=product_id).order_by(asc(ProductVersion.version)).all()
    return jsonify([{
        "id": v.id,
        "product_id": v.product_id,
        "version": v.version,
        "release_date": v.release_date.isoformat() if v.release_date else None,
        "is_active": v.is_active,
    } for v in versions])

@bp.post("/products/<int:product_id>/versions")
@role_required("Admin", "Analyst")
def create_version(product_id: int):
    data = request.get_json(silent=True) or {}
    version = (data.get("version") or "").strip()
    if not version:
        return jsonify({"error": "version is required"}), 400

    v = ProductVersion(
        product_id=product_id,
        version=version,
        release_date=data.get("release_date"),
        is_active=bool(data.get("is_active", True)),
    )
    db.session.add(v)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Duplicate version for product (or invalid data)"}), 400

    return jsonify({"id": v.id, "product_id": v.product_id, "version": v.version}), 201
