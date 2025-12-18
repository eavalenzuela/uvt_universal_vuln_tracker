from flask import Blueprint, jsonify, request
from sqlalchemy import asc, desc, or_

from ..database import db
from ..models import Vulnerability, VulnerabilityVersion, ProductVersion, AuditLog
from ..auth import login_required, role_required

bp = Blueprint("vulns_api", __name__, url_prefix="/api")

def _audit(user_id, action, table, record_id, old_values=None, new_values=None):
    db.session.add(AuditLog(
        user_id=user_id,
        action=action,
        table_name=table,
        record_id=record_id,
        old_values=old_values,
        new_values=new_values,
    ))

@bp.get("/vulnerabilities")
@login_required
def list_vulnerabilities():
    q = Vulnerability.query

    severity = request.args.get("severity")
    status = request.args.get("status")
    search = request.args.get("search")

    if severity:
        q = q.filter(Vulnerability.severity == severity)
    if status:
        q = q.filter(Vulnerability.status == status)
    if search:
        like = f"%{search}%"
        q = q.filter(or_(Vulnerability.title.ilike(like), Vulnerability.cve_id.ilike(like)))

    sort = request.args.get("sort", "updated_at")
    order = request.args.get("order", "desc")
    sort_col = getattr(Vulnerability, sort, Vulnerability.updated_at)
    q = q.order_by(desc(sort_col) if order.lower() == "desc" else asc(sort_col))

    page = int(request.args.get("page", 1))
    page_size = min(int(request.args.get("page_size", 25)), 100)

    items = q.paginate(page=page, per_page=page_size, error_out=False)

    return jsonify({
        "items": [{
            "id": v.id,
            "cve_id": v.cve_id,
            "title": v.title,
            "severity": v.severity,
            "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
            "status": v.status,
            "published_date": v.published_date.isoformat() if v.published_date else None,
            "last_modified_date": v.last_modified_date.isoformat() if v.last_modified_date else None,
            "updated_at": v.updated_at.isoformat(),
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

    v = Vulnerability(
        cve_id=(data.get("cve_id") or None),
        title=title,
        description=data.get("description"),
        severity=data.get("severity", "Medium"),
        cvss_score=data.get("cvss_score"),
        published_date=data.get("published_date"),
        last_modified_date=data.get("last_modified_date"),
        status=data.get("status", "Open"),
        created_by=request.user.id,
        assigned_to=data.get("assigned_to"),
    )
    db.session.add(v)
    db.session.flush()  # get v.id before commit

    # optional: attach affected versions immediately
    affected_versions = data.get("affected_versions") or []
    for pv_id in affected_versions:
        db.session.add(VulnerabilityVersion(
            vulnerability_id=v.id,
            product_version_id=int(pv_id),
            affected=True
        ))

    _audit(request.user.id, "CREATE", "vulnerabilities", v.id, old_values=None, new_values={
        "cve_id": v.cve_id, "title": v.title, "severity": v.severity, "status": v.status
    })

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
            "version": pv.version if pv else None,
        })

    return jsonify({
        "id": v.id,
        "cve_id": v.cve_id,
        "title": v.title,
        "description": v.description,
        "severity": v.severity,
        "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
        "published_date": v.published_date.isoformat() if v.published_date else None,
        "last_modified_date": v.last_modified_date.isoformat() if v.last_modified_date else None,
        "status": v.status,
        "created_by": v.created_by,
        "assigned_to": v.assigned_to,
        "created_at": v.created_at.isoformat(),
        "updated_at": v.updated_at.isoformat(),
        "affected_versions": version_rows
    })

@bp.put("/vulnerabilities/<int:vuln_id>")
@role_required("Admin", "Analyst")
def update_vulnerability(vuln_id: int):
    v = Vulnerability.query.get_or_404(vuln_id)
    data = request.get_json(silent=True) or {}

    old = {"cve_id": v.cve_id, "title": v.title, "severity": v.severity, "status": v.status}

    for field in ["cve_id", "title", "description", "severity", "cvss_score", "published_date",
                  "last_modified_date", "status", "assigned_to"]:
        if field in data:
            setattr(v, field, data[field])

    _audit(request.user.id, "UPDATE", "vulnerabilities", v.id, old_values=old, new_values={
        "cve_id": v.cve_id, "title": v.title, "severity": v.severity, "status": v.status
    })

    db.session.commit()
    return jsonify({"ok": True})

@bp.delete("/vulnerabilities/<int:vuln_id>")
@role_required("Admin", "Analyst")
def delete_vulnerability(vuln_id: int):
    v = Vulnerability.query.get_or_404(vuln_id)
    old = {"cve_id": v.cve_id, "title": v.title, "severity": v.severity, "status": v.status}

    _audit(request.user.id, "DELETE", "vulnerabilities", v.id, old_values=old, new_values=None)

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

    db.session.commit()
    return jsonify({"ok": True, "added": added})
