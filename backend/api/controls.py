from flask import Blueprint, jsonify, request
from sqlalchemy import asc

from ..database import db
from ..models import Control
from ..auth import login_required, role_required

bp = Blueprint("controls_api", __name__, url_prefix="/api")


def _control_json(control: Control):
    return {
        "id": control.id,
        "name": control.name,
        "framework": control.framework,
        "description": control.description,
        "created_at": control.created_at.isoformat(),
        "updated_at": control.updated_at.isoformat(),
    }


@bp.get("/controls")
@login_required
def list_controls():
    controls = Control.query.order_by(asc(Control.framework), asc(Control.name)).all()
    return jsonify([_control_json(c) for c in controls])


@bp.post("/controls")
@role_required("Admin", "Analyst")
def create_control():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    control = Control(
        name=name,
        framework=(data.get("framework") or "").strip() or None,
        description=data.get("description"),
    )
    db.session.add(control)
    db.session.commit()
    return jsonify(_control_json(control)), 201


@bp.get("/controls/<int:control_id>")
@login_required
def get_control(control_id: int):
    control = Control.query.get_or_404(control_id)
    return jsonify(_control_json(control))


@bp.patch("/controls/<int:control_id>")
@role_required("Admin", "Analyst")
def update_control(control_id: int):
    control = Control.query.get_or_404(control_id)
    data = request.get_json(silent=True) or {}

    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name cannot be empty"}), 400
        control.name = name

    if "framework" in data:
        control.framework = (data.get("framework") or "").strip() or None

    if "description" in data:
        control.description = data.get("description")

    db.session.commit()
    return jsonify(_control_json(control))


@bp.delete("/controls/<int:control_id>")
@role_required("Admin")
def delete_control(control_id: int):
    control = Control.query.get_or_404(control_id)
    db.session.delete(control)
    db.session.commit()
    return jsonify({"ok": True})
