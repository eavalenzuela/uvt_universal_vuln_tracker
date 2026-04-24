from __future__ import annotations

from flask import Blueprint, jsonify, request
from sqlalchemy import asc

from ..auth import login_required, role_required
from ..rate_limiter import rate_limit
from ..models import ComponentDependency, Product, ProductVersion, SoftwareComponent, Vulnerability, VulnerabilityComponent
from .validation import error_response
from ..services.component_diff import compare_product_version_components
from ..services.sbom_ingest import SbomFormatError, ingest_sbom
from ..services.team_scope import team_scope as _team_scope


def _get_product_version_or_404(product_version_id: int) -> ProductVersion:
    """Fetch a ProductVersion whose parent Product is in the caller's teams."""
    from flask import abort
    user = getattr(request, "user", None)
    q = ProductVersion.query.join(Product, ProductVersion.product_id == Product.id).filter(
        ProductVersion.id == product_version_id
    )
    pv = _team_scope(q, Product, user).first()
    if pv is None:
        abort(404)
    return pv

bp = Blueprint("components_api", __name__, url_prefix="/api")


@bp.get("/product_versions/<int:product_version_id>/components")
@login_required
def list_components(product_version_id: int):
    """List all software components for a product version.
    ---
    get:
      summary: List all software components for a product version
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: product_version_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: List of software components with dependencies
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/SoftwareComponent'
        404:
          description: Product version not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    _get_product_version_or_404(product_version_id)
    components = (
        SoftwareComponent.query
        .filter_by(product_version_id=product_version_id)
        .order_by(asc(SoftwareComponent.ecosystem), asc(SoftwareComponent.name), asc(SoftwareComponent.version))
        .all()
    )
    deps = ComponentDependency.query.filter_by(product_version_id=product_version_id).all()
    dep_index: dict[int, list[dict]] = {}
    for dep in deps:
        dep_index.setdefault(dep.parent_component_id, []).append({
            "id": dep.id,
            "child_component_id": dep.child_component_id,
            "dependency_path": dep.dependency_path,
            "depth": dep.depth,
            "is_direct": dep.is_direct,
        })

    return jsonify([
        {
            "id": c.id,
            "product_version_id": c.product_version_id,
            "name": c.name,
            "version": c.version,
            "ecosystem": c.ecosystem,
            "purl": c.purl,
            "cpe": c.cpe,
            "bom_ref": c.bom_ref,
            "component_type": c.component_type,
            "metadata": c.metadata_json,
            "dependencies": dep_index.get(c.id, []),
        }
        for c in components
    ])


@bp.post("/product_versions/<int:product_version_id>/sbom")
@role_required("Admin", "Analyst")
@rate_limit("RATE_LIMIT_SENSITIVE_LIMIT", "RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", identifier="sbom_import")
def import_sbom(product_version_id: int):
    """Import an SBOM for a product version.
    ---
    post:
      summary: Import an SBOM for a product version
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: product_version_id
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
                - format
                - sbom
              properties:
                format:
                  type: string
                  enum:
                    - cyclonedx
                    - spdx
                sbom:
                  type: object
                  description: The SBOM document object
      responses:
        200:
          description: SBOM imported successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  ok:
                    type: boolean
                  stats:
                    type: object
        422:
          description: Validation or format error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    payload = request.get_json(silent=True) or {}
    fmt = (payload.get("format") or "").strip().lower()
    sbom = payload.get("sbom")

    if fmt not in {"cyclonedx", "spdx"}:
        return error_response("format must be one of cyclonedx, spdx", field="format")
    if not isinstance(sbom, dict):
        return error_response("sbom must be an object", field="sbom")

    try:
        stats = ingest_sbom(product_version_id=product_version_id, sbom_payload=sbom, fmt=fmt)
    except SbomFormatError as exc:
        return error_response(str(exc))

    return jsonify({"ok": True, "stats": stats})


@bp.get("/product_versions/compare/components")
@login_required
def compare_components_between_versions():
    """Compare software components between two product versions.
    ---
    get:
      summary: Compare software components between two product versions
      security:
        - BearerAuth: []
      parameters:
        - in: query
          name: from_product_version_id
          required: true
          schema:
            type: integer
        - in: query
          name: to_product_version_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Component comparison result
          content:
            application/json:
              schema:
                type: object
        422:
          description: Missing required query parameters
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    from_product_version_id = request.args.get("from_product_version_id", type=int)
    to_product_version_id = request.args.get("to_product_version_id", type=int)

    if not from_product_version_id or not to_product_version_id:
        return error_response("from_product_version_id and to_product_version_id are required")

    result = compare_product_version_components(
        from_product_version_id=from_product_version_id,
        to_product_version_id=to_product_version_id,
    )
    return jsonify(result)


@bp.get("/product_versions/<int:product_version_id>/dependency_graph")
@login_required
def get_dependency_graph(product_version_id: int):
    """Get the dependency graph for a product version.
    ---
    get:
      summary: Get the dependency graph for a product version
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: product_version_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Dependency graph with nodes, edges, and root node IDs
          content:
            application/json:
              schema:
                type: object
                properties:
                  product_version_id:
                    type: integer
                  nodes:
                    type: array
                    items:
                      type: object
                      properties:
                        id:
                          type: integer
                        name:
                          type: string
                        version:
                          type: string
                        ecosystem:
                          type: string
                        component_type:
                          type: string
                        bom_ref:
                          type: string
                        vulnerability_count:
                          type: integer
                        max_severity:
                          type: string
                          nullable: true
                        vulnerabilities:
                          type: array
                          items:
                            type: object
                            properties:
                              id:
                                type: integer
                              title:
                                type: string
                              severity:
                                type: string
                              status:
                                type: string
                  edges:
                    type: array
                    items:
                      type: object
                      properties:
                        id:
                          type: integer
                        parent_component_id:
                          type: integer
                        child_component_id:
                          type: integer
                        dependency_path:
                          type: string
                        depth:
                          type: integer
                        is_direct:
                          type: boolean
                  root_node_ids:
                    type: array
                    items:
                      type: integer
        404:
          description: Product version not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    _get_product_version_or_404(product_version_id)

    components = (
        SoftwareComponent.query
        .filter_by(product_version_id=product_version_id)
        .order_by(asc(SoftwareComponent.ecosystem), asc(SoftwareComponent.name), asc(SoftwareComponent.version))
        .all()
    )
    component_ids = [component.id for component in components]

    dependencies = (
        ComponentDependency.query
        .filter_by(product_version_id=product_version_id)
        .order_by(asc(ComponentDependency.depth), asc(ComponentDependency.id))
        .all()
    )

    vulnerability_map: dict[int, list[dict]] = {component_id: [] for component_id in component_ids}
    if component_ids:
        vulnerability_rows = (
            VulnerabilityComponent.query
            .join(Vulnerability, Vulnerability.id == VulnerabilityComponent.vulnerability_id)
            .filter(VulnerabilityComponent.component_id.in_(component_ids))
            .all()
        )
        for row in vulnerability_rows:
            vulnerability_map.setdefault(row.component_id, []).append({
                "id": row.vulnerability.id,
                "title": row.vulnerability.title,
                "severity": row.vulnerability.severity,
                "status": row.vulnerability.status,
            })

    severity_order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "None": 1}

    incoming_node_ids = {dependency.child_component_id for dependency in dependencies}

    return jsonify({
        "product_version_id": product_version_id,
        "nodes": [
            {
                "id": component.id,
                "name": component.name,
                "version": component.version,
                "ecosystem": component.ecosystem,
                "component_type": component.component_type,
                "bom_ref": component.bom_ref,
                "vulnerability_count": len(vulnerability_map.get(component.id, [])),
                "max_severity": max(
                    [vuln.get("severity") for vuln in vulnerability_map.get(component.id, [])],
                    key=lambda severity: severity_order.get(severity or "", 0),
                    default=None,
                ),
                "vulnerabilities": vulnerability_map.get(component.id, []),
            }
            for component in components
        ],
        "edges": [
            {
                "id": dependency.id,
                "parent_component_id": dependency.parent_component_id,
                "child_component_id": dependency.child_component_id,
                "dependency_path": dependency.dependency_path,
                "depth": dependency.depth,
                "is_direct": dependency.is_direct,
            }
            for dependency in dependencies
        ],
        "root_node_ids": [component_id for component_id in component_ids if component_id not in incoming_node_ids],
    })
