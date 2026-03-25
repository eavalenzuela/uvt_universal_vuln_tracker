from __future__ import annotations

from flask import Blueprint, jsonify, request
from sqlalchemy import asc

from ..auth import login_required, role_required
from ..rate_limiter import rate_limit
from ..models import ComponentDependency, ProductVersion, SoftwareComponent, Vulnerability, VulnerabilityComponent
from ..services.component_diff import compare_product_version_components
from ..services.sbom_ingest import SbomFormatError, ingest_sbom

bp = Blueprint("components_api", __name__, url_prefix="/api")


@bp.get("/product_versions/<int:product_version_id>/components")
@login_required
def list_components(product_version_id: int):
    ProductVersion.query.get_or_404(product_version_id)
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
    payload = request.get_json(silent=True) or {}
    fmt = (payload.get("format") or "").strip().lower()
    sbom = payload.get("sbom")

    if fmt not in {"cyclonedx", "spdx"}:
        return jsonify({"error": "format must be one of cyclonedx, spdx"}), 400
    if not isinstance(sbom, dict):
        return jsonify({"error": "sbom must be an object"}), 400

    try:
        stats = ingest_sbom(product_version_id=product_version_id, sbom_payload=sbom, fmt=fmt)
    except SbomFormatError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"ok": True, "stats": stats})


@bp.get("/product_versions/compare/components")
@login_required
def compare_components_between_versions():
    from_product_version_id = request.args.get("from_product_version_id", type=int)
    to_product_version_id = request.args.get("to_product_version_id", type=int)

    if not from_product_version_id or not to_product_version_id:
        return jsonify({"error": "from_product_version_id and to_product_version_id are required"}), 400

    result = compare_product_version_components(
        from_product_version_id=from_product_version_id,
        to_product_version_id=to_product_version_id,
    )
    return jsonify(result)


@bp.get("/product_versions/<int:product_version_id>/dependency_graph")
@login_required
def get_dependency_graph(product_version_id: int):
    ProductVersion.query.get_or_404(product_version_id)

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
