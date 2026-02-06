from flask import Blueprint, jsonify, request

from ..database import db
from ..auth import login_required, role_required
from ..models import SlaPolicy
from ..services.audit import log_audit_event
from ..services.sla import get_sla_policy, normalize_sla_policy

bp = Blueprint("sla_policy_api", __name__, url_prefix="/api")


@bp.get("/sla_policy")
@login_required
def get_policy():
    return jsonify(get_sla_policy())


@bp.put("/sla_policy")
@role_required("Admin")
def update_policy():
    payload = request.get_json(silent=True) or {}
    normalized = normalize_sla_policy(payload)
    row = SlaPolicy.query.order_by(SlaPolicy.id.desc()).first()
    old_values = row.policy_json if row else None
    if not row:
        row = SlaPolicy(policy_json=normalized, updated_by=request.user.id)
        db.session.add(row)
    else:
        row.policy_json = normalized
        row.updated_by = request.user.id

    db.session.add(log_audit_event(
        actor_id=request.user.id,
        action="UPDATE",
        resource="sla_policies",
        record_id=row.id,
        old_values=old_values,
        new_values=normalized,
    ))
    db.session.commit()
    return jsonify(normalized)
