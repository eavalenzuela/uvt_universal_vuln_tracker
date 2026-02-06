from __future__ import annotations

from flask import Blueprint, jsonify, request
from sqlalchemy import asc

from ..auth import login_required, role_required
from ..models import ComponentDependency, ProductVersion, SoftwareComponent
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
