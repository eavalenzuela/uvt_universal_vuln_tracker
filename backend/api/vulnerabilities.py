from datetime import datetime

from flask import Blueprint, jsonify, request
from sqlalchemy import asc, desc, or_

from ..database import db
from ..models import (
    Vulnerability,
    VulnerabilityVersion,
    VulnerabilityAttackVector,
    VulnerabilityTerminalImpact,
    AttackVector,
    ProductVersion,
    Product,
)
from ..auth import login_required, role_required
from ..services.audit import log_audit_event, model_snapshot
from ..services.notification_rules import NotificationEvent, trigger_notifications_for_event
from ..services.sla import compute_sla_state, get_sla_policy, recompute_vulnerability_sla
from ..rate_limiter import rate_limit

bp = Blueprint("vulns_api", __name__, url_prefix="/api")

ATTACK_COMPLEXITY_OPTIONS = {"Low", "High", "Not Defined"}
IMPACT_OPTIONS = {"Not Defined", "None", "Low", "Medium", "High"}
VULNERABILITY_SORT_FIELDS = {
    "id",
    "cve_id",
    "title",
    "severity",
    "cvss_score",
    "status",
    "published_date",
    "last_modified_date",
    "created_at",
    "updated_at",
    "assigned_to",
}
MAX_PAGE_SIZE = 100


def _parse_date(date_str):
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str).date()
    except ValueError:
        return None


def _parse_cvss(score):
    if score is None or score == "":
        return None
    try:
        return round(float(score), 1)
    except (TypeError, ValueError):
        return None


def _normalize_attack_complexity(value):
    if value is None or value == "":
        return None
    if value not in ATTACK_COMPLEXITY_OPTIONS:
        return False
    return value


def _normalize_impact(value):
    if value is None or value == "":
        return None
    if value not in IMPACT_OPTIONS:
        return False
    return value

def _audit(user_id, action, table, record_id, old_values=None, new_values=None):
    db.session.add(log_audit_event(
        actor_id=user_id,
        action=action,
        resource=table,
        record_id=record_id,
        old_values=old_values,
        new_values=new_values,
    ))

def _attach_attack_vectors(vuln, items):
    for item in items:
        if isinstance(item, dict):
            attack_vector_id = item.get("attack_vector_id") or item.get("id")
            product_version_id = item.get("product_version_id")
        else:
            attack_vector_id = item
            product_version_id = None

        if not attack_vector_id:
            db.session.rollback()
            return jsonify({"error": "attack_vector_id is required"}), 400

        attack_vector = AttackVector.query.get(int(attack_vector_id))
        if not attack_vector:
            db.session.rollback()
            return jsonify({"error": f"Invalid attack vector {attack_vector_id}"}), 400

        pv_id = int(product_version_id) if product_version_id is not None else None
        if pv_id is not None:
            pv = ProductVersion.query.get(pv_id)
            if not pv:
                db.session.rollback()
                return jsonify({"error": f"Invalid product version {pv_id}"}), 400

        existing = VulnerabilityAttackVector.query.filter_by(
            vulnerability_id=vuln.id,
            attack_vector_id=attack_vector.id,
            product_version_id=pv_id,
        ).first()
        if existing:
            continue
        db.session.add(VulnerabilityAttackVector(
            vulnerability_id=vuln.id,
            attack_vector_id=attack_vector.id,
            product_version_id=pv_id,
        ))
    return None

@bp.get("/product_versions")
@login_required
@rate_limit("RATE_LIMIT_VULN_LIST_LIMIT", "RATE_LIMIT_VULN_LIST_WINDOW_SECONDS", identifier="product_versions")
def list_product_versions():
    include_inactive = str(request.args.get("include_inactive", "")).lower() == "true"
    q = ProductVersion.query.join(Product, ProductVersion.product_id == Product.id)
    if not include_inactive:
        q = q.filter(ProductVersion.is_active.is_(True))

    versions = q.order_by(asc(Product.name), asc(ProductVersion.version)).all()
    return jsonify([
        {
            "id": pv.id,
            "product_id": pv.product_id,
            "product_name": pv.product.name if pv.product else None,
            "version": pv.version,
            "release_date": pv.release_date.isoformat() if pv.release_date else None,
            "is_active": pv.is_active,
        }
        for pv in versions
    ])


@bp.get("/vulnerabilities")
@login_required
@rate_limit("RATE_LIMIT_VULN_LIST_LIMIT", "RATE_LIMIT_VULN_LIST_WINDOW_SECONDS", identifier="list_vulnerabilities")
def list_vulnerabilities():
    q = Vulnerability.query

    severity = request.args.get("severity")
    status = request.args.get("status")
    search = request.args.get("search")
    attack_complexity = request.args.get("attack_complexity")
    confidentiality_impact = request.args.get("confidentiality_impact")
    integrity_impact = request.args.get("integrity_impact")
    availability_impact = request.args.get("availability_impact")
    assigned_to = request.args.get("assigned_to")

    if severity:
        q = q.filter(Vulnerability.severity == severity)
    if status:
        q = q.filter(Vulnerability.status == status)
    if attack_complexity:
        q = q.filter(Vulnerability.attack_complexity == attack_complexity)
    if confidentiality_impact:
        q = q.filter(Vulnerability.confidentiality_impact == confidentiality_impact)
    if integrity_impact:
        q = q.filter(Vulnerability.integrity_impact == integrity_impact)
    if availability_impact:
        q = q.filter(Vulnerability.availability_impact == availability_impact)
    if assigned_to:
        if assigned_to == "unassigned":
            q = q.filter(Vulnerability.assigned_to.is_(None))
        else:
            try:
                q = q.filter(Vulnerability.assigned_to == int(assigned_to))
            except ValueError:
                return jsonify({"error": "assigned_to must be a user id or 'unassigned'"}), 400
    if search:
        like = f"%{search}%"
        q = q.filter(or_(Vulnerability.title.ilike(like), Vulnerability.cve_id.ilike(like)))

    sort = request.args.get("sort", "updated_at")
    if sort not in VULNERABILITY_SORT_FIELDS:
        return jsonify({
            "error": f"sort must be one of {sorted(VULNERABILITY_SORT_FIELDS)}"
        }), 400

    order = request.args.get("order", "desc").lower()
    if order not in {"asc", "desc"}:
        return jsonify({"error": "order must be 'asc' or 'desc'"}), 400

    page_raw = request.args.get("page", 1)
    try:
        page = int(page_raw)
    except (TypeError, ValueError):
        return jsonify({"error": "page must be a positive integer"}), 400
    if page < 1:
        return jsonify({"error": "page must be a positive integer"}), 400

    page_size_raw = request.args.get("page_size", 25)
    try:
        page_size = int(page_size_raw)
    except (TypeError, ValueError):
        return jsonify({"error": f"page_size must be an integer between 1 and {MAX_PAGE_SIZE}"}), 400
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        return jsonify({"error": f"page_size must be an integer between 1 and {MAX_PAGE_SIZE}"}), 400

    sort_col = getattr(Vulnerability, sort)
    q = q.order_by(desc(sort_col) if order == "desc" else asc(sort_col))

    items = q.paginate(page=page, per_page=page_size, error_out=False)
    policy = get_sla_policy()

    return jsonify({
        "items": [{
            "id": v.id,
            "cve_id": v.cve_id,
            "title": v.title,
            "severity": v.severity,
            "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
            "attack_complexity": v.attack_complexity,
            "confidentiality_impact": v.confidentiality_impact,
            "integrity_impact": v.integrity_impact,
            "availability_impact": v.availability_impact,
            "status": v.status,
            "assigned_to": v.assigned_to,
            "published_date": v.published_date.isoformat() if v.published_date else None,
            "last_modified_date": v.last_modified_date.isoformat() if v.last_modified_date else None,
            "created_at": v.created_at.isoformat(),
            "updated_at": v.updated_at.isoformat(),
            "sla_due_at": v.sla_due_at.isoformat() if v.sla_due_at else None,
            "sla_state": compute_sla_state(v, policy),
        } for v in items.items],
        "page": page,
        "page_size": page_size,
        "total": items.total
    })

@bp.post("/vulnerabilities")
@role_required("Admin", "Analyst")
def create_vulnerability():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "title is required"}), 400

    attack_complexity = _normalize_attack_complexity(data.get("attack_complexity"))
    if attack_complexity is False:
        return jsonify({"error": f"Invalid attack_complexity; must be one of {sorted(ATTACK_COMPLEXITY_OPTIONS)}"}), 400
    if attack_complexity is None:
        attack_complexity = "Not Defined"

    confidentiality_impact = _normalize_impact(data.get("confidentiality_impact"))
    if confidentiality_impact is False:
        return jsonify({"error": f"Invalid confidentiality_impact; must be one of {sorted(IMPACT_OPTIONS)}"}), 400
    if confidentiality_impact is None:
        confidentiality_impact = "Not Defined"

    integrity_impact = _normalize_impact(data.get("integrity_impact"))
    if integrity_impact is False:
        return jsonify({"error": f"Invalid integrity_impact; must be one of {sorted(IMPACT_OPTIONS)}"}), 400
    if integrity_impact is None:
        integrity_impact = "Not Defined"

    availability_impact = _normalize_impact(data.get("availability_impact"))
    if availability_impact is False:
        return jsonify({"error": f"Invalid availability_impact; must be one of {sorted(IMPACT_OPTIONS)}"}), 400
    if availability_impact is None:
        availability_impact = "Not Defined"

    published_date = _parse_date(data.get("published_date"))
    if data.get("published_date") and published_date is None:
        return jsonify({"error": "Invalid published_date; expected ISO date"}), 400

    last_modified_date = _parse_date(data.get("last_modified_date"))
    if data.get("last_modified_date") and last_modified_date is None:
        return jsonify({"error": "Invalid last_modified_date; expected ISO date"}), 400

    v = Vulnerability(
        cve_id=(data.get("cve_id") or None),
        title=title,
        description=data.get("description"),
        severity=data.get("severity", "Medium"),
        cvss_score=_parse_cvss(data.get("cvss_score")),
        attack_complexity=attack_complexity,
        confidentiality_impact=confidentiality_impact,
        integrity_impact=integrity_impact,
        availability_impact=availability_impact,
        published_date=published_date,
        last_modified_date=last_modified_date,
        status=data.get("status", "Open"),
        created_by=request.user.id,
        assigned_to=data.get("assigned_to"),
    )
    db.session.add(v)
    db.session.flush()  # get v.id before commit

    # optional: attach affected versions immediately
    affected_versions = data.get("affected_versions") or []
    for pv_id in affected_versions:
        pv = ProductVersion.query.get(int(pv_id))
        if not pv:
            db.session.rollback()
            return jsonify({"error": f"Invalid product version {pv_id}"}), 400
        db.session.add(VulnerabilityVersion(
            vulnerability_id=v.id,
            product_version_id=pv.id,
            affected=True
        ))

    attack_vectors = data.get("attack_vectors") or []
    if attack_vectors:
        err = _attach_attack_vectors(v, attack_vectors)
        if err:
            return err

    recompute_vulnerability_sla(v)

    _audit(request.user.id, "CREATE", "vulnerabilities", v.id, old_values=None, new_values={
        "cve_id": v.cve_id, "title": v.title, "severity": v.severity, "status": v.status,
        "attack_complexity": v.attack_complexity,
        "confidentiality_impact": v.confidentiality_impact,
        "integrity_impact": v.integrity_impact,
        "availability_impact": v.availability_impact,
    })

    trigger_notifications_for_event(NotificationEvent(
        event_type="created",
        vulnerability_id=v.id,
        actor_id=request.user.id,
        old_values=None,
        new_values={"status": v.status, "assigned_to": v.assigned_to},
    ))

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Failed to create vulnerability (duplicate CVE? invalid data?)"}), 400

    return jsonify({"id": v.id}), 201

@bp.get("/vulnerabilities/<int:vuln_id>")
@login_required
def get_vulnerability(vuln_id: int):
    v = Vulnerability.query.get_or_404(vuln_id)

    mappings = VulnerabilityVersion.query.filter_by(vulnerability_id=v.id).all()
    version_rows = []
    for m in mappings:
        pv = ProductVersion.query.get(m.product_version_id)
        version_rows.append({
            "id": m.id,
            "product_version_id": m.product_version_id,
            "affected": m.affected,
            "fixed_in_version": m.fixed_in_version,
            "mitigation_status": m.mitigation_status,
            "notes": m.notes,
            "product_id": pv.product_id if pv else None,
            "product_name": pv.product.name if getattr(pv, "product", None) else None,
            "version": pv.version if pv else None,
            "release_date": pv.release_date.isoformat() if getattr(pv, "release_date", None) else None,
        })

    attack_vector_mappings = VulnerabilityAttackVector.query.filter_by(vulnerability_id=v.id).all()
    attack_vector_rows = []
    for mapping in attack_vector_mappings:
        pv = ProductVersion.query.get(mapping.product_version_id) if mapping.product_version_id else None
        attack_vector_rows.append({
            "id": mapping.id,
            "attack_vector_id": mapping.attack_vector_id,
            "attack_vector_name": mapping.attack_vector.name if mapping.attack_vector else None,
            "attack_vector_description": mapping.attack_vector.description if mapping.attack_vector else None,
            "product_version_id": mapping.product_version_id,
            "product_id": pv.product_id if pv else None,
            "product_name": pv.product.name if getattr(pv, "product", None) else None,
            "version": pv.version if pv else None,
            "release_date": pv.release_date.isoformat() if getattr(pv, "release_date", None) else None,
        })

    terminal_impact_mappings = VulnerabilityTerminalImpact.query.filter_by(vulnerability_id=v.id).all()
    terminal_impact_rows = []
    for mapping in terminal_impact_mappings:
        terminal_impact_rows.append({
            "id": mapping.id,
            "terminal_impact_id": mapping.terminal_impact_id,
            "terminal_impact_name": mapping.terminal_impact.name if mapping.terminal_impact else None,
            "terminal_impact_description": mapping.terminal_impact.description if mapping.terminal_impact else None,
        })

    return jsonify({
        "id": v.id,
        "cve_id": v.cve_id,
        "title": v.title,
        "description": v.description,
        "severity": v.severity,
        "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
        "attack_complexity": v.attack_complexity,
        "confidentiality_impact": v.confidentiality_impact,
        "integrity_impact": v.integrity_impact,
        "availability_impact": v.availability_impact,
        "published_date": v.published_date.isoformat() if v.published_date else None,
        "last_modified_date": v.last_modified_date.isoformat() if v.last_modified_date else None,
        "status": v.status,
        "created_by": v.created_by,
        "assigned_to": v.assigned_to,
        "created_at": v.created_at.isoformat(),
        "updated_at": v.updated_at.isoformat(),
        "sla_due_at": v.sla_due_at.isoformat() if v.sla_due_at else None,
        "sla_state": compute_sla_state(v),
        "affected_versions": version_rows,
        "attack_vectors": attack_vector_rows,
        "terminal_impacts": terminal_impact_rows,
    })

@bp.put("/vulnerabilities/<int:vuln_id>")
@role_required("Admin", "Analyst")
def update_vulnerability(vuln_id: int):
    v = Vulnerability.query.get_or_404(vuln_id)
    data = request.get_json(silent=True) or {}

    old = {
        "cve_id": v.cve_id,
        "title": v.title,
        "severity": v.severity,
        "status": v.status,
        "assigned_to": v.assigned_to,
        "attack_complexity": v.attack_complexity,
        "confidentiality_impact": v.confidentiality_impact,
        "integrity_impact": v.integrity_impact,
        "availability_impact": v.availability_impact,
    }

    for field in ["cve_id", "title", "description", "severity", "cvss_score", "published_date",
                  "last_modified_date", "status", "assigned_to", "attack_complexity",
                  "confidentiality_impact", "integrity_impact", "availability_impact"]:
        if field in data:
            if field == "title":
                title_value = (data.get(field) or "").strip()
                if not title_value:
                    return jsonify({"error": "title cannot be empty"}), 400
                setattr(v, field, title_value)
            elif field in {"published_date", "last_modified_date"}:
                parsed = _parse_date(data.get(field))
                if data.get(field) and parsed is None:
                    return jsonify({"error": f"Invalid {field}; expected ISO date"}), 400
                setattr(v, field, parsed)
            elif field == "cvss_score":
                setattr(v, field, _parse_cvss(data.get(field)))
            elif field == "attack_complexity":
                normalized = _normalize_attack_complexity(data.get(field))
                if normalized is False:
                    return jsonify({"error": f"Invalid attack_complexity; must be one of {sorted(ATTACK_COMPLEXITY_OPTIONS)}"}), 400
                setattr(v, field, normalized if normalized is not None else "Not Defined")
            elif field in {"confidentiality_impact", "integrity_impact", "availability_impact"}:
                normalized = _normalize_impact(data.get(field))
                if normalized is False:
                    return jsonify({"error": f"Invalid {field}; must be one of {sorted(IMPACT_OPTIONS)}"}), 400
                setattr(v, field, normalized if normalized is not None else "Not Defined")
            else:
                setattr(v, field, data[field])

    if "attack_vectors" in data:
        VulnerabilityAttackVector.query.filter_by(vulnerability_id=v.id).delete(synchronize_session=False)
        err = _attach_attack_vectors(v, data.get("attack_vectors") or [])
        if err:
            return err

    recompute_vulnerability_sla(v)

    _audit(request.user.id, "UPDATE", "vulnerabilities", v.id, old_values=old, new_values={
        "cve_id": v.cve_id, "title": v.title, "severity": v.severity, "status": v.status,
        "attack_complexity": v.attack_complexity,
        "confidentiality_impact": v.confidentiality_impact,
        "integrity_impact": v.integrity_impact,
        "availability_impact": v.availability_impact,
    })

    event_type = "updated"
    status_changed = old.get("status") != v.status
    assignment_changed = data.get("assigned_to", old.get("assigned_to")) != old.get("assigned_to") if "assigned_to" in data else False
    if status_changed:
        event_type = "status_change"
    elif assignment_changed:
        event_type = "assignment_change"

    trigger_notifications_for_event(NotificationEvent(
        event_type=event_type,
        vulnerability_id=v.id,
        actor_id=request.user.id,
        old_values=old,
        new_values={"status": v.status, "assigned_to": v.assigned_to},
        status_changed=status_changed,
        assignment_changed=assignment_changed,
    ))

    db.session.commit()
    return jsonify({"ok": True})

@bp.delete("/vulnerabilities/<int:vuln_id>")
@role_required("Admin", "Analyst")
def delete_vulnerability(vuln_id: int):
    v = Vulnerability.query.get_or_404(vuln_id)
    old = model_snapshot(v)

    _audit(request.user.id, "DELETE", "vulnerabilities", v.id, old_values=old, new_values=None)

    trigger_notifications_for_event(NotificationEvent(
        event_type="deleted",
        vulnerability_id=v.id,
        actor_id=request.user.id,
        old_values=old,
        new_values=None,
    ))

    db.session.delete(v)
    db.session.commit()
    return jsonify({"ok": True})

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

    _audit(request.user.id, "ATTACH", "vulnerability_versions", v.id, old_values=None, new_values={
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

    _audit(request.user.id, "UPDATE", "vulnerability_versions", mapping.id, old_values=old_values, new_values={
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

    _audit(request.user.id, "DELETE", "vulnerability_versions", mapping.id, old_values={
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
