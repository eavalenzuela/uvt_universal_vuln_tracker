from flask import Blueprint, jsonify, request

from ..auth import login_required, role_required
from ..services.team_scope import get_vulnerability_or_404
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
    """List all attack vectors.
    ---
    get:
      summary: List all attack vectors
      security:
        - BearerAuth: []
      responses:
        200:
          description: Success
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/AttackVector'
    """
    vectors = svc_list()
    return jsonify([_attack_vector_json(v) for v in vectors])


@bp.post("/attack_vectors")
@role_required("Admin", "Analyst")
def create_attack_vector():
    """Create a new attack vector.
    ---
    post:
      summary: Create a new attack vector
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
          description: Attack vector created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AttackVector'
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
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
    """Get a single attack vector by ID.
    ---
    get:
      summary: Get a single attack vector by ID
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vector_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Success
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AttackVector'
        404:
          description: Attack vector not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    vector = svc_get(vector_id)
    return jsonify(_attack_vector_json(vector))


@bp.patch("/attack_vectors/<int:vector_id>")
@role_required("Admin", "Analyst")
def update_attack_vector(vector_id: int):
    """Update an existing attack vector.
    ---
    patch:
      summary: Update an existing attack vector
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vector_id
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
          description: Attack vector updated
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AttackVector'
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        404:
          description: Attack vector not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    data = request.get_json(silent=True) or {}
    try:
        vector = svc_update(vector_id, data)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify(_attack_vector_json(vector))


@bp.delete("/attack_vectors/<int:vector_id>")
@role_required("Admin")
def delete_attack_vector(vector_id: int):
    """Delete an attack vector.
    ---
    delete:
      summary: Delete an attack vector
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vector_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Attack vector deleted
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Ok'
        404:
          description: Attack vector not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    svc_delete(vector_id)
    return jsonify({"ok": True})


@bp.get("/vulnerabilities/<int:vuln_id>/attack_vectors")
@login_required
def list_vulnerability_attack_vectors(vuln_id: int):
    """List attack vector mappings for a vulnerability.
    ---
    get:
      summary: List attack vector mappings for a vulnerability
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vuln_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Success
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
        404:
          description: Vulnerability not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    mappings = svc_list_mappings(vuln_id)
    return jsonify([serialize_mapping(m) for m in mappings])


@bp.post("/vulnerabilities/<int:vuln_id>/attack_vectors")
@role_required("Admin", "Analyst")
def attach_vulnerability_attack_vectors(vuln_id: int):
    """Attach attack vectors to a vulnerability.
    ---
    post:
      summary: Attach attack vectors to a vulnerability
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vuln_id
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
                mappings:
                  type: array
                  items:
                    type: object
      responses:
        200:
          description: Attack vectors attached
          content:
            application/json:
              schema:
                type: object
                properties:
                  ok:
                    type: boolean
                  added:
                    type: integer
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        404:
          description: Vulnerability not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
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
    """Update a vulnerability-attack-vector mapping.
    ---
    patch:
      summary: Update a vulnerability-attack-vector mapping
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vuln_id
          required: true
          schema:
            type: integer
        - in: path
          name: mapping_id
          required: true
          schema:
            type: integer
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
      responses:
        200:
          description: Mapping updated
          content:
            application/json:
              schema:
                type: object
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        404:
          description: Mapping not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    data = request.get_json(silent=True) or {}
    try:
        mapping = svc_update_mapping(vuln_id, mapping_id, data)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify(serialize_mapping(mapping))


@bp.delete("/vulnerabilities/<int:vuln_id>/attack_vectors/<int:mapping_id>")
@role_required("Admin", "Analyst")
def delete_vulnerability_attack_vector(vuln_id: int, mapping_id: int):
    """Delete a vulnerability-attack-vector mapping.
    ---
    delete:
      summary: Delete a vulnerability-attack-vector mapping
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vuln_id
          required: true
          schema:
            type: integer
        - in: path
          name: mapping_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Mapping deleted
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Ok'
        404:
          description: Mapping not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    svc_delete_mapping(vuln_id, mapping_id)
    return jsonify({"ok": True})
