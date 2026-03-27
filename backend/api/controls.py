from flask import Blueprint, jsonify, request
from sqlalchemy import asc

from ..database import db
from ..models import Control
from ..auth import login_required, role_required
from .validation import ValidationError, error_response, required_string
from ..services.audit import model_snapshot, record_audit as _audit
from ..serializers.control_serializers import control_json as _control_json

bp = Blueprint("controls_api", __name__, url_prefix="/api")


@bp.get("/controls")
@login_required
def list_controls():
    """List all controls.
    ---
    get:
      summary: List all controls
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
                  $ref: '#/components/schemas/Control'
    """
    controls = Control.query.order_by(asc(Control.framework), asc(Control.name)).all()
    return jsonify([_control_json(c) for c in controls])


@bp.post("/controls")
@role_required("Admin", "Analyst")
def create_control():
    """Create a new control.
    ---
    post:
      summary: Create a new control
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
                framework:
                  type: string
                description:
                  type: string
      responses:
        201:
          description: Control created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Control'
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return error_response("name is required", field="name")

    control = Control(
        name=name,
        framework=(data.get("framework") or "").strip() or None,
        description=data.get("description"),
    )
    db.session.add(control)
    db.session.flush()
    _audit("CREATE", "controls", control.id, new_values=model_snapshot(control))
    db.session.commit()
    return jsonify(_control_json(control)), 201


@bp.get("/controls/<int:control_id>")
@login_required
def get_control(control_id: int):
    """Get a single control by ID.
    ---
    get:
      summary: Get a single control by ID
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: control_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Success
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Control'
        404:
          description: Control not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    control = Control.query.get_or_404(control_id)
    return jsonify(_control_json(control))


@bp.patch("/controls/<int:control_id>")
@role_required("Admin", "Analyst")
def update_control(control_id: int):
    """Update an existing control.
    ---
    patch:
      summary: Update an existing control
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: control_id
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
                framework:
                  type: string
                description:
                  type: string
      responses:
        200:
          description: Control updated
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Control'
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        404:
          description: Control not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    control = Control.query.get_or_404(control_id)
    data = request.get_json(silent=True) or {}

    old_values = model_snapshot(control)

    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            return error_response("name cannot be empty", field="name")
        control.name = name

    if "framework" in data:
        control.framework = (data.get("framework") or "").strip() or None

    if "description" in data:
        control.description = data.get("description")

    _audit("UPDATE", "controls", control.id, old_values=old_values, new_values=model_snapshot(control))
    db.session.commit()
    return jsonify(_control_json(control))


@bp.delete("/controls/<int:control_id>")
@role_required("Admin")
def delete_control(control_id: int):
    """Delete a control.
    ---
    delete:
      summary: Delete a control
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: control_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Control deleted
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Ok'
        404:
          description: Control not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    control = Control.query.get_or_404(control_id)
    _audit("DELETE", "controls", control.id, old_values=model_snapshot(control))
    db.session.delete(control)
    db.session.commit()
    return jsonify({"ok": True})
