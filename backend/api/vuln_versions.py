from flask import Blueprint, jsonify, request

from ..database import db
from ..models import (
    Vulnerability,
    VulnerabilityVersion,
)
from ..auth import role_required
from ..services.audit import record_audit
from ..services.notification_rules import NotificationEvent, trigger_notifications_for_event
from .validation import error_response

bp = Blueprint("vuln_versions_api", __name__, url_prefix="/api")


@bp.post("/vulnerabilities/<int:vuln_id>/versions")
@role_required("Admin", "Analyst")
def attach_versions(vuln_id: int):
    """
    Body:
      {
        "product_version_ids": [1,2,3]
      }
    """
    v = Vulnerability.query.get_or_404(vuln_id)
    data = request.get_json(silent=True) or {}
    pv_ids = data.get("product_version_ids") or []
    added = 0

    for pv_id in pv_ids:
        pv_id = int(pv_id)
        existing = VulnerabilityVersion.query.filter_by(vulnerability_id=v.id, product_version_id=pv_id).first()
        if existing:
            continue
        db.session.add(VulnerabilityVersion(vulnerability_id=v.id, product_version_id=pv_id, affected=True))
        added += 1

    record_audit("ATTACH", "vulnerability_versions", v.id, old_values=None, new_values={
        "added": added, "product_version_ids": pv_ids
    })

    if added > 0:
        trigger_notifications_for_event(NotificationEvent(
            event_type="product_scope_change",
            vulnerability_id=v.id,
            actor_id=request.user.id,
            new_values={"added_product_version_ids": pv_ids},
        ))

    db.session.commit()
    return jsonify({"ok": True, "added": added})


@bp.patch("/vulnerabilities/<int:vuln_id>/versions/<int:mapping_id>")
@role_required("Admin", "Analyst")
def update_vulnerability_version(vuln_id: int, mapping_id: int):
    Vulnerability.query.get_or_404(vuln_id)
    mapping = VulnerabilityVersion.query.filter_by(id=mapping_id, vulnerability_id=vuln_id).first_or_404()
    data = request.get_json(silent=True) or {}

    old_values = {
        "affected": mapping.affected,
        "fixed_in_version": mapping.fixed_in_version,
        "mitigation_status": mapping.mitigation_status,
        "notes": mapping.notes,
    }

    if "affected" in data:
        val = data.get("affected")
        if isinstance(val, str):
            mapping.affected = val.lower() in {"true", "1", "yes", "on"}
        else:
            mapping.affected = bool(val)
    for field in ["fixed_in_version", "mitigation_status", "notes"]:
        if field in data:
            setattr(mapping, field, data.get(field))

    record_audit("UPDATE", "vulnerability_versions", mapping.id, old_values=old_values, new_values={
        "affected": mapping.affected,
        "fixed_in_version": mapping.fixed_in_version,
        "mitigation_status": mapping.mitigation_status,
        "notes": mapping.notes,
    })

    trigger_notifications_for_event(NotificationEvent(
        event_type="product_scope_change",
        vulnerability_id=vuln_id,
        actor_id=request.user.id,
        old_values=old_values,
        new_values={"affected": mapping.affected, "mitigation_status": mapping.mitigation_status},
    ))

    db.session.commit()

    return jsonify({
        "id": mapping.id,
        "vulnerability_id": mapping.vulnerability_id,
        "product_version_id": mapping.product_version_id,
        "affected": mapping.affected,
        "fixed_in_version": mapping.fixed_in_version,
        "mitigation_status": mapping.mitigation_status,
        "notes": mapping.notes,
    })


@bp.delete("/vulnerabilities/<int:vuln_id>/versions/<int:mapping_id>")
@role_required("Admin", "Analyst")
def delete_vulnerability_version(vuln_id: int, mapping_id: int):
    Vulnerability.query.get_or_404(vuln_id)
    mapping = VulnerabilityVersion.query.filter_by(id=mapping_id, vulnerability_id=vuln_id).first_or_404()

    record_audit("DELETE", "vulnerability_versions", mapping.id, old_values={
        "product_version_id": mapping.product_version_id,
        "affected": mapping.affected,
        "fixed_in_version": mapping.fixed_in_version,
    }, new_values=None)

    trigger_notifications_for_event(NotificationEvent(
        event_type="product_scope_change",
        vulnerability_id=vuln_id,
        actor_id=request.user.id,
        old_values={"product_version_id": mapping.product_version_id},
        new_values=None,
    ))

    db.session.delete(mapping)
    db.session.commit()
    return jsonify({"ok": True})
