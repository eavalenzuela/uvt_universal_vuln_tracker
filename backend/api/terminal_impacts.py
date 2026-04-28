from flask import Blueprint, jsonify, request
from sqlalchemy import asc

from ..database import db
from ..models import TerminalImpact, Vulnerability, VulnerabilityTerminalImpact
from ..auth import login_required, role_required
from ..services.team_scope import get_vulnerability_or_404
from ..services.audit import record_audit
from .validation import ValidationError, error_response, required_string

bp = Blueprint("terminal_impacts_api", __name__, url_prefix="/api")


def _terminal_impact_json(impact: TerminalImpact):
    return {
        "id": impact.id,
        "name": impact.name,
        "description": impact.description,
        "created_at": impact.created_at.isoformat(),
        "updated_at": impact.updated_at.isoformat(),
    }


def _mapping_json(mapping: VulnerabilityTerminalImpact):
    return {
        "id": mapping.id,
        "vulnerability_id": mapping.vulnerability_id,
        "terminal_impact_id": mapping.terminal_impact_id,
        "terminal_impact_name": mapping.terminal_impact.name if mapping.terminal_impact else None,
        "terminal_impact_description": mapping.terminal_impact.description if mapping.terminal_impact else None,
    }


@bp.get("/terminal_impacts")
@login_required
def list_terminal_impacts():
    """List all terminal impacts.
    ---
    get:
      summary: List all terminal impacts
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
                  $ref: '#/components/schemas/TerminalImpact'
    """
    impacts = TerminalImpact.query.order_by(asc(TerminalImpact.name)).all()
    return jsonify([_terminal_impact_json(i) for i in impacts])


@bp.post("/terminal_impacts")
@role_required("Admin", "Analyst")
def create_terminal_impact():
    """Create a new terminal impact.
    ---
    post:
      summary: Create a new terminal impact
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
          description: Terminal impact created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TerminalImpact'
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

    impact = TerminalImpact(
        name=name,
        description=data.get("description"),
    )
    db.session.add(impact)
    db.session.commit()
    return jsonify(_terminal_impact_json(impact)), 201


@bp.get("/terminal_impacts/<int:impact_id>")
@login_required
def get_terminal_impact(impact_id: int):
    """Get a single terminal impact by ID.
    ---
    get:
      summary: Get a single terminal impact by ID
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: impact_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Success
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TerminalImpact'
        404:
          description: Terminal impact not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    impact = TerminalImpact.query.get_or_404(impact_id)
    return jsonify(_terminal_impact_json(impact))


@bp.patch("/terminal_impacts/<int:impact_id>")
@role_required("Admin", "Analyst")
def update_terminal_impact(impact_id: int):
    """Update an existing terminal impact.
    ---
    patch:
      summary: Update an existing terminal impact
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: impact_id
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
          description: Terminal impact updated
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TerminalImpact'
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        404:
          description: Terminal impact not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    impact = TerminalImpact.query.get_or_404(impact_id)
    data = request.get_json(silent=True) or {}

    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            return error_response("name cannot be empty", field="name")
        impact.name = name

    if "description" in data:
        impact.description = data.get("description")

    db.session.commit()
    return jsonify(_terminal_impact_json(impact))


@bp.delete("/terminal_impacts/<int:impact_id>")
@role_required("Admin")
def delete_terminal_impact(impact_id: int):
    """Delete a terminal impact.
    ---
    delete:
      summary: Delete a terminal impact
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: impact_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Terminal impact deleted
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Ok'
        404:
          description: Terminal impact not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    impact = TerminalImpact.query.get_or_404(impact_id)
    record_audit("DELETE", "terminal_impacts", impact.id,
                 old_values={"name": impact.name, "description": impact.description})
    db.session.delete(impact)
    db.session.commit()
    return jsonify({"ok": True})


@bp.get("/vulnerabilities/<int:vuln_id>/terminal_impacts")
@login_required
def list_vulnerability_terminal_impacts(vuln_id: int):
    """List terminal impact mappings for a vulnerability.
    ---
    get:
      summary: List terminal impact mappings for a vulnerability
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
    get_vulnerability_or_404(vuln_id)
    mappings = VulnerabilityTerminalImpact.query.filter_by(vulnerability_id=vuln_id).all()
    return jsonify([_mapping_json(m) for m in mappings])


@bp.post("/vulnerabilities/<int:vuln_id>/terminal_impacts")
@role_required("Admin", "Analyst")
def attach_vulnerability_terminal_impacts(vuln_id: int):
    """Attach terminal impacts to a vulnerability.
    ---
    post:
      summary: Attach terminal impacts to a vulnerability
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
                terminal_impact_ids:
                  type: array
                  items:
                    type: integer
      responses:
        200:
          description: Terminal impacts attached
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
    get_vulnerability_or_404(vuln_id)
    data = request.get_json(silent=True) or {}
    impact_ids = data.get("terminal_impact_ids") or []
    added = 0

    for impact_id in impact_ids:
        if not impact_id:
            return error_response("terminal_impact_ids must include valid ids", field="terminal_impact_ids")
        impact = db.session.get(TerminalImpact, int(impact_id))
        if not impact:
            return error_response(f"Invalid terminal impact {impact_id}", field="terminal_impact_ids")

        existing = VulnerabilityTerminalImpact.query.filter_by(
            vulnerability_id=vuln_id,
            terminal_impact_id=impact.id,
        ).first()
        if existing:
            continue
        db.session.add(VulnerabilityTerminalImpact(
            vulnerability_id=vuln_id,
            terminal_impact_id=impact.id,
        ))
        added += 1

    db.session.commit()
    return jsonify({"ok": True, "added": added})


@bp.patch("/vulnerabilities/<int:vuln_id>/terminal_impacts/<int:mapping_id>")
@role_required("Admin", "Analyst")
def update_vulnerability_terminal_impact(vuln_id: int, mapping_id: int):
    """Update a vulnerability-terminal-impact mapping.
    ---
    patch:
      summary: Update a vulnerability-terminal-impact mapping
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
              properties:
                terminal_impact_id:
                  type: integer
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
    get_vulnerability_or_404(vuln_id)
    mapping = VulnerabilityTerminalImpact.query.filter_by(id=mapping_id, vulnerability_id=vuln_id).first_or_404()
    data = request.get_json(silent=True) or {}

    if "terminal_impact_id" in data:
        impact_id = data.get("terminal_impact_id")
        impact = db.session.get(TerminalImpact, int(impact_id)) if impact_id else None
        if not impact:
            return error_response(f"Invalid terminal impact {impact_id}", field="terminal_impact_id")
        mapping.terminal_impact_id = impact.id

    db.session.commit()
    return jsonify(_mapping_json(mapping))


@bp.delete("/vulnerabilities/<int:vuln_id>/terminal_impacts/<int:mapping_id>")
@role_required("Admin", "Analyst")
def delete_vulnerability_terminal_impact(vuln_id: int, mapping_id: int):
    """Delete a vulnerability-terminal-impact mapping.
    ---
    delete:
      summary: Delete a vulnerability-terminal-impact mapping
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
    get_vulnerability_or_404(vuln_id)
    mapping = VulnerabilityTerminalImpact.query.filter_by(id=mapping_id, vulnerability_id=vuln_id).first_or_404()
    db.session.delete(mapping)
    db.session.commit()
    return jsonify({"ok": True})
