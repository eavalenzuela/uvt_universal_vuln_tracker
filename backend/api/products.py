from flask import Blueprint, jsonify, request

from ..auth import login_required, role_required
from ..services.product_service import (
    create_product as svc_create_product,
    create_version as svc_create_version,
    delete_product as svc_delete_product,
    delete_version as svc_delete_version,
    get_product as svc_get_product,
    list_products as svc_list_products,
    list_versions as svc_list_versions,
    update_product as svc_update_product,
    update_version as svc_update_version,
)
from .validation import ValidationError, error_response, paginate_query
from ..serializers.product_serializers import product_json as _product_json, version_json as _version_json

bp = Blueprint("products_api", __name__, url_prefix="/api")


@bp.get("/products")
@login_required
def list_products():
    query = svc_list_products()
    try:
        products, meta = paginate_query(query)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify({"items": [_product_json(p) for p in products], **meta})


@bp.post("/products")
@role_required("Admin", "Analyst")
def create_product():
    data = request.get_json(silent=True) or {}
    try:
        p = svc_create_product(
            name=data.get("name"),
            description=data.get("description"),
            created_by=getattr(request, "user", None).id if getattr(request, "user", None) else None,
        )
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify({"id": p.id, "name": p.name, "description": p.description}), 201


@bp.get("/products/<int:product_id>")
@login_required
def get_product(product_id: int):
    p = svc_get_product(product_id)
    return jsonify(_product_json(p, include_details=True))


@bp.patch("/products/<int:product_id>")
@role_required("Admin", "Analyst")
def update_product(product_id: int):
    data = request.get_json(silent=True) or {}
    try:
        p = svc_update_product(product_id, data)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify(_product_json(p, include_details=True))


@bp.delete("/products/<int:product_id>")
@role_required("Admin")
def delete_product(product_id: int):
    svc_delete_product(product_id)
    return jsonify({"ok": True})


@bp.get("/products/<int:product_id>/versions")
@login_required
def list_versions(product_id: int):
    versions = svc_list_versions(product_id)
    return jsonify([_version_json(v) for v in versions])


@bp.post("/products/<int:product_id>/versions")
@role_required("Admin", "Analyst")
def create_version(product_id: int):
    data = request.get_json(silent=True) or {}
    try:
        v = svc_create_version(
            product_id=product_id,
            version=data.get("version"),
            release_date=data.get("release_date"),
            is_active=data.get("is_active", True),
        )
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify(_version_json(v)), 201


@bp.patch("/products/<int:product_id>/versions/<int:version_id>")
@role_required("Admin", "Analyst")
def update_version(product_id: int, version_id: int):
    data = request.get_json(silent=True) or {}
    try:
        v = svc_update_version(product_id, version_id, data)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify(_version_json(v))


@bp.delete("/products/<int:product_id>/versions/<int:version_id>")
@role_required("Admin", "Analyst")
def delete_version(product_id: int, version_id: int):
    svc_delete_version(product_id, version_id)
    return jsonify({"ok": True})
