from flask import Blueprint, jsonify, request
from sqlalchemy import asc

from ..database import db
from ..models import AttackVector, Vulnerability, VulnerabilityAttackVector, ProductVersion
from ..auth import login_required, role_required

bp = Blueprint("attack_vectors_api", __name__, url_prefix="/api")


def _attack_vector_json(attack_vector: AttackVector):
    return {
        "id": attack_vector.id,
        "name": attack_vector.name,
        "description": attack_vector.description,
        "created_at": attack_vector.created_at.isoformat(),
        "updated_at": attack_vector.updated_at.isoformat(),
    }


def _mapping_json(mapping: VulnerabilityAttackVector):
    pv = ProductVersion.query.get(mapping.product_version_id) if mapping.product_version_id else None
    return {
        "id": mapping.id,
        "vulnerability_id": mapping.vulnerability_id,
        "attack_vector_id": mapping.attack_vector_id,
        "attack_vector_name": mapping.attack_vector.name if mapping.attack_vector else None,
        "attack_vector_description": mapping.attack_vector.description if mapping.attack_vector else None,
        "product_version_id": mapping.product_version_id,
        "product_id": pv.product_id if pv else None,
        "product_name": pv.product.name if getattr(pv, "product", None) else None,
        "version": pv.version if pv else None,
        "release_date": pv.release_date.isoformat() if getattr(pv, "release_date", None) else None,
    }


@bp.get("/attack_vectors")
@login_required
def list_attack_vectors():
    vectors = AttackVector.query.order_by(asc(AttackVector.name)).all()
    return jsonify([_attack_vector_json(v) for v in vectors])


@bp.post("/attack_vectors")
@role_required("Admin", "Analyst")
def create_attack_vector():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    attack_vector = AttackVector(
        name=name,
        description=data.get("description"),
    )
    db.session.add(attack_vector)
    db.session.commit()
    return jsonify(_attack_vector_json(attack_vector)), 201


@bp.get("/attack_vectors/<int:vector_id>")
@login_required
def get_attack_vector(vector_id: int):
    vector = AttackVector.query.get_or_404(vector_id)
    return jsonify(_attack_vector_json(vector))


@bp.patch("/attack_vectors/<int:vector_id>")
@role_required("Admin", "Analyst")
def update_attack_vector(vector_id: int):
    vector = AttackVector.query.get_or_404(vector_id)
    data = request.get_json(silent=True) or {}

    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name cannot be empty"}), 400
        vector.name = name

    if "description" in data:
        vector.description = data.get("description")

    db.session.commit()
    return jsonify(_attack_vector_json(vector))


@bp.delete("/attack_vectors/<int:vector_id>")
@role_required("Admin")
def delete_attack_vector(vector_id: int):
    vector = AttackVector.query.get_or_404(vector_id)
    db.session.delete(vector)
    db.session.commit()
    return jsonify({"ok": True})


@bp.get("/vulnerabilities/<int:vuln_id>/attack_vectors")
@login_required
def list_vulnerability_attack_vectors(vuln_id: int):
    Vulnerability.query.get_or_404(vuln_id)
    mappings = VulnerabilityAttackVector.query.filter_by(vulnerability_id=vuln_id).all()
    return jsonify([_mapping_json(m) for m in mappings])


@bp.post("/vulnerabilities/<int:vuln_id>/attack_vectors")
@role_required("Admin", "Analyst")
def attach_vulnerability_attack_vectors(vuln_id: int):
    """
    Body:
      {
        "mappings": [{"attack_vector_id": 1, "product_version_id": 2}]
      }
    """
    Vulnerability.query.get_or_404(vuln_id)
    data = request.get_json(silent=True) or {}
    mappings = data.get("mappings") or []
    added = 0

    for item in mappings:
        attack_vector_id = item.get("attack_vector_id")
        product_version_id = item.get("product_version_id")
        if not attack_vector_id:
            return jsonify({"error": "attack_vector_id is required"}), 400

        vector = AttackVector.query.get(int(attack_vector_id))
        if not vector:
            return jsonify({"error": f"Invalid attack vector {attack_vector_id}"}), 400

        pv_id = int(product_version_id) if product_version_id is not None else None
        if pv_id is not None:
            pv = ProductVersion.query.get(pv_id)
            if not pv:
                return jsonify({"error": f"Invalid product version {pv_id}"}), 400

        existing = VulnerabilityAttackVector.query.filter_by(
            vulnerability_id=vuln_id,
            attack_vector_id=vector.id,
            product_version_id=pv_id,
        ).first()
        if existing:
            continue
        db.session.add(VulnerabilityAttackVector(
            vulnerability_id=vuln_id,
            attack_vector_id=vector.id,
            product_version_id=pv_id,
        ))
        added += 1

    db.session.commit()
    return jsonify({"ok": True, "added": added})


@bp.patch("/vulnerabilities/<int:vuln_id>/attack_vectors/<int:mapping_id>")
@role_required("Admin", "Analyst")
def update_vulnerability_attack_vector(vuln_id: int, mapping_id: int):
    Vulnerability.query.get_or_404(vuln_id)
    mapping = VulnerabilityAttackVector.query.filter_by(id=mapping_id, vulnerability_id=vuln_id).first_or_404()
    data = request.get_json(silent=True) or {}

    if "attack_vector_id" in data:
        vector_id = data.get("attack_vector_id")
        vector = AttackVector.query.get(int(vector_id)) if vector_id else None
        if not vector:
            return jsonify({"error": f"Invalid attack vector {vector_id}"}), 400
        mapping.attack_vector_id = vector.id

    if "product_version_id" in data:
        pv_id = data.get("product_version_id")
        if pv_id is None:
            mapping.product_version_id = None
        else:
            pv = ProductVersion.query.get(int(pv_id))
            if not pv:
                return jsonify({"error": f"Invalid product version {pv_id}"}), 400
            mapping.product_version_id = pv.id

    db.session.commit()
    return jsonify(_mapping_json(mapping))


@bp.delete("/vulnerabilities/<int:vuln_id>/attack_vectors/<int:mapping_id>")
@role_required("Admin", "Analyst")
def delete_vulnerability_attack_vector(vuln_id: int, mapping_id: int):
    Vulnerability.query.get_or_404(vuln_id)
    mapping = VulnerabilityAttackVector.query.filter_by(id=mapping_id, vulnerability_id=vuln_id).first_or_404()
    db.session.delete(mapping)
    db.session.commit()
    return jsonify({"ok": True})
