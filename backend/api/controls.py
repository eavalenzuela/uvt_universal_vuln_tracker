from flask import Blueprint, jsonify, request
from sqlalchemy import asc

from ..database import db
from ..models import Control
from ..auth import login_required, role_required
from .validation import ValidationError, error_response, required_string
from ..services.audit import log_audit_event, model_snapshot

bp = Blueprint("controls_api", __name__, url_prefix="/api")


def _audit(action, resource, record_id, *, old_values=None, new_values=None):
    actor = getattr(request, "user", None)
    db.session.add(log_audit_event(
        actor_id=actor.id if actor else None,
        action=action,
        resource=resource,
        record_id=record_id,
        old_values=old_values,
        new_values=new_values,
    ))


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
    control = Control.query.get_or_404(control_id)
    return jsonify(_control_json(control))


@bp.patch("/controls/<int:control_id>")
@role_required("Admin", "Analyst")
def update_control(control_id: int):
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
    control = Control.query.get_or_404(control_id)
    _audit("DELETE", "controls", control.id, old_values=model_snapshot(control))
    db.session.delete(control)
    db.session.commit()
    return jsonify({"ok": True})
