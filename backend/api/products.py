from flask import Blueprint, current_app, jsonify, request

from ..auth import login_required, role_required
from ..cache import cache_get, cache_set, cache_invalidate
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
    """List all products with pagination.
    ---
    get:
      summary: List all products with pagination
      security:
        - BearerAuth: []
      parameters:
        - in: query
          name: page
          schema:
            type: integer
            default: 1
        - in: query
          name: per_page
          schema:
            type: integer
            default: 25
      responses:
        200:
          description: Paginated list of products
          content:
            application/json:
              schema:
                type: object
                properties:
                  items:
                    type: array
                    items:
                      $ref: '#/components/schemas/Product'
                  page:
                    type: integer
                  per_page:
                    type: integer
                  total:
                    type: integer
                  pages:
                    type: integer
        422:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    cache_params = {"page": request.args.get("page", "1"), "per_page": request.args.get("per_page", "25")}
    cached = cache_get("products_list", cache_params)
    if cached is not None:
        return jsonify(cached)
    query = svc_list_products()
    try:
        products, meta = paginate_query(query)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    payload = {"items": [_product_json(p) for p in products], **meta}
    cache_set("products_list", cache_params, payload, ttl=current_app.config.get("CACHE_PRODUCTS_TTL", 60))
    return jsonify(payload)


@bp.post("/products")
@role_required("Admin", "Analyst")
def create_product():
    """Create a new product.
    ---
    post:
      summary: Create a new product
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - name
              properties:
                name:
                  type: string
                description:
                  type: string
      responses:
        201:
          description: Product created
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: integer
                  name:
                    type: string
                  description:
                    type: string
        422:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    data = request.get_json(silent=True) or {}
    try:
        p = svc_create_product(
            name=data.get("name"),
            description=data.get("description"),
            created_by=getattr(request, "user", None).id if getattr(request, "user", None) else None,
        )
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    cache_invalidate("products_list")
    return jsonify({"id": p.id, "name": p.name, "description": p.description}), 201


@bp.get("/products/<int:product_id>")
@login_required
def get_product(product_id: int):
    """Get a single product with full details.
    ---
    get:
      summary: Get a single product with full details
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: product_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Product detail
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ProductDetail'
        404:
          description: Product not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    p = svc_get_product(product_id)
    return jsonify(_product_json(p, include_details=True))


@bp.patch("/products/<int:product_id>")
@role_required("Admin", "Analyst")
def update_product(product_id: int):
    """Update an existing product.
    ---
    patch:
      summary: Update an existing product
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: product_id
          required: true
          schema:
            type: integer
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                description:
                  type: string
      responses:
        200:
          description: Updated product detail
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ProductDetail'
        404:
          description: Product not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        422:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    data = request.get_json(silent=True) or {}
    try:
        p = svc_update_product(product_id, data)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    cache_invalidate("products_list")
    return jsonify(_product_json(p, include_details=True))


@bp.delete("/products/<int:product_id>")
@role_required("Admin")
def delete_product(product_id: int):
    """Delete a product.
    ---
    delete:
      summary: Delete a product
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: product_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Product deleted
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Ok'
        404:
          description: Product not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    svc_delete_product(product_id)
    cache_invalidate("products_list")
    return jsonify({"ok": True})


@bp.get("/products/<int:product_id>/versions")
@login_required
def list_versions(product_id: int):
    """List all versions for a product.
    ---
    get:
      summary: List all versions for a product
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: product_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: List of product versions
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/ProductVersion'
        404:
          description: Product not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    versions = svc_list_versions(product_id)
    return jsonify([_version_json(v) for v in versions])


@bp.post("/products/<int:product_id>/versions")
@role_required("Admin", "Analyst")
def create_version(product_id: int):
    """Create a new version for a product.
    ---
    post:
      summary: Create a new version for a product
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: product_id
          required: true
          schema:
            type: integer
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - version
              properties:
                version:
                  type: string
                release_date:
                  type: string
                  format: date
                is_active:
                  type: boolean
                  default: true
      responses:
        201:
          description: Version created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ProductVersion'
        404:
          description: Product not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        422:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
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
    """Update an existing product version.
    ---
    patch:
      summary: Update an existing product version
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: product_id
          required: true
          schema:
            type: integer
        - in: path
          name: version_id
          required: true
          schema:
            type: integer
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                version:
                  type: string
                release_date:
                  type: string
                  format: date
                is_active:
                  type: boolean
      responses:
        200:
          description: Updated product version
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ProductVersion'
        404:
          description: Product or version not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        422:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    data = request.get_json(silent=True) or {}
    try:
        v = svc_update_version(product_id, version_id, data)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify(_version_json(v))


@bp.delete("/products/<int:product_id>/versions/<int:version_id>")
@role_required("Admin", "Analyst")
def delete_version(product_id: int, version_id: int):
    """Delete a product version.
    ---
    delete:
      summary: Delete a product version
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: product_id
          required: true
          schema:
            type: integer
        - in: path
          name: version_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Version deleted
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Ok'
        404:
          description: Product or version not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    svc_delete_version(product_id, version_id)
    return jsonify({"ok": True})
