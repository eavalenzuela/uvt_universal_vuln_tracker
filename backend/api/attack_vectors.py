from flask import Blueprint, jsonify, request

from ..auth import login_required, role_required
from ..services.attack_vector_service import (
    attach_vulnerability_attack_vectors as svc_attach,
    create_attack_vector as svc_create,
    delete_attack_vector as svc_delete,
    delete_vulnerability_attack_vector as svc_delete_mapping,
    get_attack_vector as svc_get,
    list_attack_vectors as svc_list,
    list_vulnerability_attack_vectors as svc_list_mappings,
    serialize_mapping,
    update_attack_vector as svc_update,
    update_vulnerability_attack_vector as svc_update_mapping,
)
from .validation import ValidationError, error_response, required_string

bp = Blueprint("attack_vectors_api", __name__, url_prefix="/api")


def _attack_vector_json(attack_vector):
    return {
        "id": attack_vector.id,
        "name": attack_vector.name,
        "description": attack_vector.description,
        "created_at": attack_vector.created_at.isoformat(),
        "updated_at": attack_vector.updated_at.isoformat(),
    }


@bp.get("/attack_vectors")
@login_required
def list_attack_vectors():
    vectors = svc_list()
    return jsonify([_attack_vector_json(v) for v in vectors])


@bp.post("/attack_vectors")
@role_required("Admin", "Analyst")
def create_attack_vector():
    data = request.get_json(silent=True) or {}
    try:
        name = required_string(data, "name")
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    vector = svc_create(name=name, description=data.get("description"))
    return jsonify(_attack_vector_json(vector)), 201


@bp.get("/attack_vectors/<int:vector_id>")
@login_required
def get_attack_vector(vector_id: int):
    vector = svc_get(vector_id)
    return jsonify(_attack_vector_json(vector))


@bp.patch("/attack_vectors/<int:vector_id>")
@role_required("Admin", "Analyst")
def update_attack_vector(vector_id: int):
    data = request.get_json(silent=True) or {}
    try:
        vector = svc_update(vector_id, data)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify(_attack_vector_json(vector))


@bp.delete("/attack_vectors/<int:vector_id>")
@role_required("Admin")
def delete_attack_vector(vector_id: int):
    svc_delete(vector_id)
    return jsonify({"ok": True})


@bp.get("/vulnerabilities/<int:vuln_id>/attack_vectors")
@login_required
def list_vulnerability_attack_vectors(vuln_id: int):
    mappings = svc_list_mappings(vuln_id)
    return jsonify([serialize_mapping(m) for m in mappings])


@bp.post("/vulnerabilities/<int:vuln_id>/attack_vectors")
@role_required("Admin", "Analyst")
def attach_vulnerability_attack_vectors(vuln_id: int):
    data = request.get_json(silent=True) or {}
    mappings = data.get("mappings") or []
    try:
        added = svc_attach(vuln_id, mappings)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify({"ok": True, "added": added})


@bp.patch("/vulnerabilities/<int:vuln_id>/attack_vectors/<int:mapping_id>")
@role_required("Admin", "Analyst")
def update_vulnerability_attack_vector(vuln_id: int, mapping_id: int):
    data = request.get_json(silent=True) or {}
    try:
        mapping = svc_update_mapping(vuln_id, mapping_id, data)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify(serialize_mapping(mapping))


@bp.delete("/vulnerabilities/<int:vuln_id>/attack_vectors/<int:mapping_id>")
@role_required("Admin", "Analyst")
def delete_vulnerability_attack_vector(vuln_id: int, mapping_id: int):
    svc_delete_mapping(vuln_id, mapping_id)
    return jsonify({"ok": True})
