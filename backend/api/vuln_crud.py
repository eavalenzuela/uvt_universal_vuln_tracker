from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import asc

from sqlalchemy.exc import IntegrityError

from ..database import db
from ..models import (
    AuditLog,
    Vulnerability,
    VulnerabilityVersion,
    VulnerabilityAttackVector,
    VulnerabilityTerminalImpact,
    AttackVector,
    ProductVersion,
    Product,
    VulnerabilityComponent,
)
from ..auth import login_required, role_required
from ..services.audit import build_field_diff, model_snapshot, record_audit
from ..services.notification_rules import NotificationEvent, trigger_notifications_for_event
from ..services.sla import compute_sla_state, get_sla_policy, recompute_vulnerability_sla
from ..services.cve_enrichment import (
    CveNotFoundError,
    CveUpstreamRequestError,
    CveUpstreamTimeoutError,
    fetch_cve_enrichment,
)
from ..rate_limiter import rate_limit
from .validation import ValidationError, error_response, normalize_cve_id, parse_float, parse_int, parse_iso_date, parse_query_bool, required_string
from ..services.vulnerability_query import build_vulnerability_query
from ..services.dedup import list_merge_candidates as get_merge_candidates, merge_vulnerabilities
from ..services.dashboard_live_metrics import classify_vulnerability_metric_action, publish_vulnerability_metric_event
from ..services.vulnerability_service import (
    ATTACK_COMPLEXITY_OPTIONS,
    IMPACT_OPTIONS,
    SEVERITY_OPTIONS,
    STATUS_OPTIONS,
    attach_attack_vectors,
    create_vulnerability as create_vulnerability_workflow,
    parse_sla_due_at,
    update_vulnerability as update_vulnerability_workflow,
)
from ..serializers.vulnerability_serializers import (
    audit_field_diff_payload,
    serialize_vulnerability_history_item,
)

bp = Blueprint("vulns_api", __name__, url_prefix="/api")

MAX_PAGE_SIZE = 100


def _parse_sla_due_at(value, *, field="sla_due_at"):
    return parse_sla_due_at(value, field=field)


def _is_empty_value(value):
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, list):
        return len(value) == 0
    return False


def _attach_attack_vectors(vuln, items):
    try:
        attach_attack_vectors(vuln, items)
    except ValidationError as exc:
        db.session.rollback()
        return error_response(exc.error, field=exc.field, details=exc.details)
    return None


def _audit_field_diff_payload(log):
    return audit_field_diff_payload(log)


def _serialize_vulnerability_history_item(log):
    return serialize_vulnerability_history_item(log)


@bp.get("/product_versions")
@login_required
@rate_limit("RATE_LIMIT_VULN_LIST_LIMIT", "RATE_LIMIT_VULN_LIST_WINDOW_SECONDS", identifier="product_versions")
def list_product_versions():
    try:
        include_inactive = parse_query_bool(request.args.get("include_inactive"), field="include_inactive") or False
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
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
    try:
        q, query_meta = build_vulnerability_query(
            request.args,
            base_query=Vulnerability.query,
            default_page=1,
            default_page_size=25,
            max_page_size=MAX_PAGE_SIZE,
        )
    except ValueError as exc:
        message = str(exc)
        field = None
        if message.startswith("page "):
            field = "page"
        elif message.startswith("page_size "):
            field = "page_size"
        return error_response(message, field=field, status_code=400)

    page = query_meta["page"]
    page_size = query_meta["page_size"]

    items = q.paginate(page=page, per_page=page_size, error_out=False)
    policy = get_sla_policy()

    return jsonify({
        "items": [{
            "id": v.id,
            "cve_id": v.cve_id,
            "title": v.title,
            "severity": v.severity,
            "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
            "cvss_vector": v.cvss_vector,
            "cvss_version": v.cvss_version,
            "cwe_id": v.cwe_id,
            "references_json": v.references_json or [],
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
            "affected_components_count": len(v.affected_components or []),
            "is_merged": bool(v.is_merged),
            "merged_into_id": v.merged_into_id,
            "merge_metadata_json": v.merge_metadata_json or {},
        } for v in items.items],
        "page": page,
        "page_size": page_size,
        "total": items.total
    })

@bp.post("/vulnerabilities")
@role_required("Admin", "Analyst")
def create_vulnerability():
    data = request.get_json(silent=True) or {}

    try:
        v = create_vulnerability_workflow(data=data, actor_id=request.user.id)
    except ValidationError as exc:
        db.session.rollback()
        return error_response(exc.error, field=exc.field, details=exc.details)

    record_audit("CREATE", "vulnerabilities", v.id, old_values=None, new_values={
        "cve_id": v.cve_id, "title": v.title, "severity": v.severity, "status": v.status,
        "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
        "assigned_to": v.assigned_to,
        "sla_due_at": v.sla_due_at.isoformat() if v.sla_due_at else None,
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
    except IntegrityError:
        current_app.logger.exception("Failed to create vulnerability")
        db.session.rollback()
        return error_response("Failed to create vulnerability (duplicate CVE? invalid data?)", status_code=400)

    publish_vulnerability_metric_event(vulnerability=v, action="created")
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

    component_rows = []
    for mapping in v.affected_components:
        component = mapping.component
        component_rows.append({
            "id": mapping.id,
            "component_id": component.id if component else None,
            "name": component.name if component else None,
            "version": component.version if component else None,
            "ecosystem": component.ecosystem if component else None,
            "purl": component.purl if component else None,
            "cpe": component.cpe if component else None,
            "source": mapping.source,
            "match_type": mapping.match_type,
            "dependency_path": mapping.dependency_path,
            "transitive_depth": mapping.transitive_depth,
        })

    return jsonify({
        "id": v.id,
        "cve_id": v.cve_id,
        "title": v.title,
        "description": v.description,
        "severity": v.severity,
        "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
        "cvss_vector": v.cvss_vector,
        "cvss_version": v.cvss_version,
        "cwe_id": v.cwe_id,
        "references_json": v.references_json or [],
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
        "affected_components": component_rows,
        "is_merged": bool(v.is_merged),
        "merged_into_id": v.merged_into_id,
        "merge_metadata_json": v.merge_metadata_json or {},
    })


@bp.get("/vulnerabilities/<int:vuln_id>/merge_candidates")
@role_required("Admin", "Analyst")
def list_vulnerability_merge_candidates(vuln_id: int):
    v = Vulnerability.query.get_or_404(vuln_id)
    try:
        limit = parse_int(request.args.get("limit"), field="limit", minimum=1) or 20
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    return jsonify({"items": get_merge_candidates(v, limit=limit)})


@bp.post("/vulnerabilities/<int:target_vuln_id>/merge")
@role_required("Admin", "Analyst")
def merge_vulnerability_into_target(target_vuln_id: int):
    target = Vulnerability.query.get_or_404(target_vuln_id)
    data = request.get_json(silent=True) or {}
    try:
        source_vuln_id = parse_int(data.get("source_vulnerability_id"), field="source_vulnerability_id", minimum=1, required=True)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    if source_vuln_id == target_vuln_id:
        return error_response("source_vulnerability_id must be different from target", field="source_vulnerability_id")

    source = Vulnerability.query.get(source_vuln_id)
    if not source:
        return error_response("Source vulnerability not found", field="source_vulnerability_id", status_code=404)

    reason = (data.get("reason") or "").strip() or None

    try:
        result = merge_vulnerabilities(target=target, source=source, actor_id=request.user.id, reason=reason)
    except ValueError as exc:
        return error_response(str(exc), status_code=400)

    record_audit("MERGE", "vulnerabilities", target.id,
                 old_values={"target_id": target.id, "source_id": source.id},
                 new_values={"target_id": target.id, "source_id": source.id, "reason": reason})

    db.session.commit()
    return jsonify({"ok": True, **result})


@bp.get("/vulnerabilities/<int:vuln_id>/activity")
@login_required
def get_vulnerability_activity(vuln_id: int):
    Vulnerability.query.get_or_404(vuln_id)

    logs = (
        AuditLog.query
        .filter(
            AuditLog.table_name.in_(["vulnerabilities", "vulnerability_versions"]),
            AuditLog.record_id == vuln_id,
        )
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(250)
        .all()
    )

    return jsonify([
        {
            "id": log.id,
            "action": log.action,
            "table_name": log.table_name,
            "record_id": log.record_id,
            "old_values": log.old_values,
            "new_values": log.new_values,
            "created_at": log.created_at.isoformat() if log.created_at else None,
            "user": {
                "id": log.user.id,
                "username": log.user.username,
                "email": log.user.email,
            } if log.user else None,
        }
        for log in logs
    ])


@bp.get("/vulnerabilities/<int:vuln_id>/history")
@login_required
def get_vulnerability_history(vuln_id: int):
    Vulnerability.query.get_or_404(vuln_id)
    logs = (
        AuditLog.query
        .filter(
            AuditLog.table_name == "vulnerabilities",
            AuditLog.record_id == vuln_id,
        )
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(250)
        .all()
    )

    return jsonify([_serialize_vulnerability_history_item(log) for log in logs])

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
        "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
        "assigned_to": v.assigned_to,
        "sla_due_at": v.sla_due_at.isoformat() if v.sla_due_at else None,
        "attack_complexity": v.attack_complexity,
        "confidentiality_impact": v.confidentiality_impact,
        "integrity_impact": v.integrity_impact,
        "availability_impact": v.availability_impact,
    }

    try:
        update_vulnerability_workflow(v, data)
    except ValidationError as exc:
        db.session.rollback()
        return error_response(exc.error, field=exc.field, details=exc.details)

    new_values = {
        "cve_id": v.cve_id,
        "title": v.title,
        "severity": v.severity,
        "status": v.status,
        "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
        "assigned_to": v.assigned_to,
        "sla_due_at": v.sla_due_at.isoformat() if v.sla_due_at else None,
        "attack_complexity": v.attack_complexity,
        "confidentiality_impact": v.confidentiality_impact,
        "integrity_impact": v.integrity_impact,
        "availability_impact": v.availability_impact,
    }
    new_values["field_diff"] = build_field_diff(
        old,
        new_values,
        ["severity", "status", "cvss_score", "assigned_to", "sla_due_at"],
    )

    record_audit("UPDATE", "vulnerabilities", v.id, old_values=old, new_values=new_values)

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

    publish_vulnerability_metric_event(
        vulnerability=v,
        action=classify_vulnerability_metric_action(previous_status=old.get("status"), current_status=v.status),
        previous={"status": old.get("status"), "severity": old.get("severity")},
    )
    return jsonify({"ok": True})

@bp.delete("/vulnerabilities/<int:vuln_id>")
@role_required("Admin", "Analyst")
def delete_vulnerability(vuln_id: int):
    v = Vulnerability.query.get_or_404(vuln_id)
    old = model_snapshot(v)

    record_audit("DELETE", "vulnerabilities", v.id, old_values=old, new_values=None)

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


@bp.post("/vulnerabilities/<int:vuln_id>/enrich")
@role_required("Admin", "Analyst")
def enrich_vulnerability(vuln_id: int):
    v = Vulnerability.query.get_or_404(vuln_id)
    try:
        force = parse_query_bool(request.args.get("force"), field="force") or False
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    if not v.cve_id:
        return jsonify({
            "ok": False,
            "enrichment": {
                "status": "error",
                "error": "vulnerability has no cve_id",
                "applied_fields": [],
            },
        }), 400

    try:
        enriched = fetch_cve_enrichment(v.cve_id)
    except CveNotFoundError as exc:
        return jsonify({"ok": False, "enrichment": {"status": "not_found", "error": str(exc), "applied_fields": []}}), 404
    except CveUpstreamTimeoutError as exc:
        return jsonify({"ok": False, "enrichment": {"status": "timeout", "error": str(exc), "applied_fields": []}}), 504
    except CveUpstreamRequestError as exc:
        return jsonify({"ok": False, "enrichment": {"status": "error", "error": str(exc), "applied_fields": []}}), 502

    old = {
        "title": v.title,
        "description": v.description,
        "severity": v.severity,
        "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
        "cvss_vector": v.cvss_vector,
        "cvss_version": v.cvss_version,
        "cwe_id": v.cwe_id,
        "references_json": v.references_json or [],
        "published_date": v.published_date.isoformat() if v.published_date else None,
        "last_modified_date": v.last_modified_date.isoformat() if v.last_modified_date else None,
        "sla_due_at": v.sla_due_at.isoformat() if v.sla_due_at else None,
    }

    updates = {
        "title": enriched.title,
        "description": enriched.description,
        "severity": enriched.severity,
        "cvss_score": round(enriched.cvss_score, 1) if enriched.cvss_score is not None else None,
        "cvss_vector": enriched.cvss_vector,
        "cvss_version": enriched.cvss_version,
        "cwe_id": enriched.cwe_id,
        "references_json": enriched.references_json,
        "published_date": enriched.published_date,
        "last_modified_date": enriched.last_modified_date,
    }

    applied_fields = []
    for field, value in updates.items():
        if value is None:
            continue
        if not force and not _is_empty_value(getattr(v, field)):
            continue
        setattr(v, field, value)
        applied_fields.append(field)

    if old["severity"] != v.severity or old["cvss_score"] != (float(v.cvss_score) if v.cvss_score is not None else None):
        recompute_vulnerability_sla(v)

    new_values = {
        "title": v.title,
        "description": v.description,
        "severity": v.severity,
        "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
        "cvss_vector": v.cvss_vector,
        "cvss_version": v.cvss_version,
        "cwe_id": v.cwe_id,
        "references_json": v.references_json or [],
        "published_date": v.published_date.isoformat() if v.published_date else None,
        "last_modified_date": v.last_modified_date.isoformat() if v.last_modified_date else None,
        "sla_due_at": v.sla_due_at.isoformat() if v.sla_due_at else None,
        "force": force,
        "applied_fields": applied_fields,
    }

    record_audit("ENRICH", "vulnerabilities", v.id, old_values=old, new_values=new_values)
    trigger_notifications_for_event(NotificationEvent(
        event_type="updated",
        vulnerability_id=v.id,
        actor_id=request.user.id,
        old_values=old,
        new_values={"status": v.status, "assigned_to": v.assigned_to},
    ))

    db.session.commit()
    return jsonify({
        "ok": True,
        "enrichment": {
            "status": "enriched",
            "error": None,
            "force": force,
            "applied_fields": applied_fields,
        },
        "vulnerability": {
            "id": v.id,
            "severity": v.severity,
            "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
            "cvss_vector": v.cvss_vector,
            "cvss_version": v.cvss_version,
            "cwe_id": v.cwe_id,
            "references_json": v.references_json or [],
            "sla_due_at": v.sla_due_at.isoformat() if v.sla_due_at else None,
        },
    })
