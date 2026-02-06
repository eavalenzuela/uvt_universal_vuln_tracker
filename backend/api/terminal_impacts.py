from flask import Blueprint, jsonify, request
from sqlalchemy import asc

from ..database import db
from ..models import TerminalImpact, Vulnerability, VulnerabilityTerminalImpact
from ..auth import login_required, role_required
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
    impacts = TerminalImpact.query.order_by(asc(TerminalImpact.name)).all()
    return jsonify([_terminal_impact_json(i) for i in impacts])


@bp.post("/terminal_impacts")
@role_required("Admin", "Analyst")
def create_terminal_impact():
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
    impact = TerminalImpact.query.get_or_404(impact_id)
    return jsonify(_terminal_impact_json(impact))


@bp.patch("/terminal_impacts/<int:impact_id>")
@role_required("Admin", "Analyst")
def update_terminal_impact(impact_id: int):
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
    impact = TerminalImpact.query.get_or_404(impact_id)
    db.session.delete(impact)
    db.session.commit()
    return jsonify({"ok": True})


@bp.get("/vulnerabilities/<int:vuln_id>/terminal_impacts")
@login_required
def list_vulnerability_terminal_impacts(vuln_id: int):
    Vulnerability.query.get_or_404(vuln_id)
    mappings = VulnerabilityTerminalImpact.query.filter_by(vulnerability_id=vuln_id).all()
    return jsonify([_mapping_json(m) for m in mappings])


@bp.post("/vulnerabilities/<int:vuln_id>/terminal_impacts")
@role_required("Admin", "Analyst")
def attach_vulnerability_terminal_impacts(vuln_id: int):
    """
    Body:
      {
        "terminal_impact_ids": [1,2,3]
      }
    """
    Vulnerability.query.get_or_404(vuln_id)
    data = request.get_json(silent=True) or {}
    impact_ids = data.get("terminal_impact_ids") or []
    added = 0

    for impact_id in impact_ids:
        if not impact_id:
            return jsonify({"error": "terminal_impact_ids must include valid ids"}), 400
        impact = TerminalImpact.query.get(int(impact_id))
        if not impact:
            return jsonify({"error": f"Invalid terminal impact {impact_id}"}), 400

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
    Vulnerability.query.get_or_404(vuln_id)
    mapping = VulnerabilityTerminalImpact.query.filter_by(id=mapping_id, vulnerability_id=vuln_id).first_or_404()
    data = request.get_json(silent=True) or {}

    if "terminal_impact_id" in data:
        impact_id = data.get("terminal_impact_id")
        impact = TerminalImpact.query.get(int(impact_id)) if impact_id else None
        if not impact:
            return jsonify({"error": f"Invalid terminal impact {impact_id}"}), 400
        mapping.terminal_impact_id = impact.id

    db.session.commit()
    return jsonify(_mapping_json(mapping))


@bp.delete("/vulnerabilities/<int:vuln_id>/terminal_impacts/<int:mapping_id>")
@role_required("Admin", "Analyst")
def delete_vulnerability_terminal_impact(vuln_id: int, mapping_id: int):
    Vulnerability.query.get_or_404(vuln_id)
    mapping = VulnerabilityTerminalImpact.query.filter_by(id=mapping_id, vulnerability_id=vuln_id).first_or_404()
    db.session.delete(mapping)
    db.session.commit()
    return jsonify({"ok": True})
