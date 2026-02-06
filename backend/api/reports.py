import csv
import io
from datetime import datetime

from flask import Blueprint, jsonify, request, Response
from sqlalchemy import asc, desc, func

from ..auth import login_required, role_required
from ..database import db
from ..models import ReportSchedule, Vulnerability
from ..services.slack_alerts import SlackWebhookClient, SlackWebhookError

bp = Blueprint("reports_api", __name__, url_prefix="/api")

EXPORT_FIELDS = [
    "id",
    "cve_id",
    "title",
    "severity",
    "cvss_score",
    "status",
    "attack_complexity",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    "assigned_to",
    "published_date",
    "last_modified_date",
    "created_at",
    "updated_at",
]

ALLOWED_FREQUENCIES = {"daily", "weekly"}
ALLOWED_CHANNELS = {"email", "slack"}
ALLOWED_REPORT_TYPES = {"vulnerabilities", "dashboard_summary"}


def _parse_filters(args):
    return {
        "severity": args.get("severity") or None,
        "status": args.get("status") or None,
        "search": args.get("search") or None,
        "attack_complexity": args.get("attack_complexity") or None,
        "confidentiality_impact": args.get("confidentiality_impact") or None,
        "integrity_impact": args.get("integrity_impact") or None,
        "availability_impact": args.get("availability_impact") or None,
        "assigned_to": args.get("assigned_to") or None,
        "sort": args.get("sort") or "updated_at",
        "order": (args.get("order") or "desc").lower(),
    }


def _build_vulnerability_query(filters):
    q = Vulnerability.query
    if filters.get("severity"):
        q = q.filter(Vulnerability.severity == filters["severity"])
    if filters.get("status"):
        q = q.filter(Vulnerability.status == filters["status"])
    if filters.get("attack_complexity"):
        q = q.filter(Vulnerability.attack_complexity == filters["attack_complexity"])
    if filters.get("confidentiality_impact"):
        q = q.filter(Vulnerability.confidentiality_impact == filters["confidentiality_impact"])
    if filters.get("integrity_impact"):
        q = q.filter(Vulnerability.integrity_impact == filters["integrity_impact"])
    if filters.get("availability_impact"):
        q = q.filter(Vulnerability.availability_impact == filters["availability_impact"])
    if filters.get("assigned_to"):
        if filters["assigned_to"] == "unassigned":
            q = q.filter(Vulnerability.assigned_to.is_(None))
        else:
            q = q.filter(Vulnerability.assigned_to == int(filters["assigned_to"]))
    if filters.get("search"):
        like = f"%{filters['search']}%"
        q = q.filter((Vulnerability.title.ilike(like)) | (Vulnerability.cve_id.ilike(like)))

    sort = filters.get("sort") or "updated_at"
    sort_col = getattr(Vulnerability, sort, Vulnerability.updated_at)
    q = q.order_by(desc(sort_col) if filters.get("order") != "asc" else asc(sort_col))
    return q


def _vuln_row(v):
    return {
        "id": v.id,
        "cve_id": v.cve_id or "",
        "title": v.title,
        "severity": v.severity,
        "cvss_score": float(v.cvss_score) if v.cvss_score is not None else "",
        "status": v.status,
        "attack_complexity": v.attack_complexity,
        "confidentiality_impact": v.confidentiality_impact,
        "integrity_impact": v.integrity_impact,
        "availability_impact": v.availability_impact,
        "assigned_to": v.assigned_to if v.assigned_to is not None else "",
        "published_date": v.published_date.isoformat() if v.published_date else "",
        "last_modified_date": v.last_modified_date.isoformat() if v.last_modified_date else "",
        "created_at": v.created_at.isoformat() if v.created_at else "",
        "updated_at": v.updated_at.isoformat() if v.updated_at else "",
    }


def _csv_response(filename, fieldnames, rows):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _dashboard_summary(filters):
    q = _build_vulnerability_query(filters)
    total = q.count()
    by_severity = dict(
        db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
        .select_from(Vulnerability)
        .filter(Vulnerability.id.in_(q.with_entities(Vulnerability.id)))
        .group_by(Vulnerability.severity)
        .all()
    )
    by_status = dict(
        db.session.query(Vulnerability.status, func.count(Vulnerability.id))
        .select_from(Vulnerability)
        .filter(Vulnerability.id.in_(q.with_entities(Vulnerability.id)))
        .group_by(Vulnerability.status)
        .all()
    )
    return {"total": total, "by_severity": by_severity, "by_status": by_status}


def _summary_rows(summary):
    rows = [{"metric": "total", "group": "all", "value": summary["total"]}]
    rows.extend({"metric": "severity", "group": k, "value": v} for k, v in sorted(summary["by_severity"].items()))
    rows.extend({"metric": "status", "group": k, "value": v} for k, v in sorted(summary["by_status"].items()))
    return rows


@bp.get("/reports/vulnerabilities/export")
@login_required
def export_vulnerabilities():
    filters = _parse_filters(request.args)
    items = _build_vulnerability_query(filters).all()
    rows = [_vuln_row(v) for v in items]
    return _csv_response("vulnerabilities_export.csv", EXPORT_FIELDS, rows)


@bp.get("/reports/dashboard/export")
@login_required
def export_dashboard_summary():
    filters = _parse_filters(request.args)
    summary = _dashboard_summary(filters)
    return _csv_response("dashboard_summary.csv", ["metric", "group", "value"], _summary_rows(summary))


@bp.post("/reports/schedules")
@role_required("Admin", "Analyst")
def create_report_schedule():
    payload = request.get_json(silent=True) or {}

    name = (payload.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    report_type = payload.get("report_type") or "vulnerabilities"
    if report_type not in ALLOWED_REPORT_TYPES:
        return jsonify({"error": f"report_type must be one of {sorted(ALLOWED_REPORT_TYPES)}"}), 400

    frequency = (payload.get("frequency") or "daily").lower()
    if frequency not in ALLOWED_FREQUENCIES:
        return jsonify({"error": f"frequency must be one of {sorted(ALLOWED_FREQUENCIES)}"}), 400

    delivery_channel = (payload.get("delivery_channel") or "email").lower()
    if delivery_channel not in ALLOWED_CHANNELS:
        return jsonify({"error": f"delivery_channel must be one of {sorted(ALLOWED_CHANNELS)}"}), 400

    recipient = (payload.get("recipient") or "").strip()
    if not recipient:
        return jsonify({"error": "recipient is required"}), 400

    schedule = ReportSchedule(
        name=name,
        report_type=report_type,
        frequency=frequency,
        delivery_channel=delivery_channel,
        recipient=recipient,
        filters_json=payload.get("filters") or {},
        created_by=request.user.id,
    )
    db.session.add(schedule)
    db.session.commit()
    return jsonify(_schedule_json(schedule)), 201


@bp.get("/reports/schedules")
@login_required
def list_report_schedules():
    q = ReportSchedule.query
    if request.user.role != "Admin":
        q = q.filter(ReportSchedule.created_by == request.user.id)
    rows = q.order_by(desc(ReportSchedule.created_at)).all()
    return jsonify([_schedule_json(r) for r in rows])


@bp.post("/reports/schedules/<int:schedule_id>/run")
@role_required("Admin", "Analyst")
def run_report_schedule(schedule_id):
    schedule = ReportSchedule.query.get_or_404(schedule_id)
    if request.user.role != "Admin" and schedule.created_by != request.user.id:
        return jsonify({"error": "Forbidden"}), 403

    filters = schedule.filters_json or {}
    if schedule.report_type == "dashboard_summary":
        content = _csv_content(["metric", "group", "value"], _summary_rows(_dashboard_summary(filters)))
    else:
        rows = [_vuln_row(v) for v in _build_vulnerability_query(filters).all()]
        content = _csv_content(EXPORT_FIELDS, rows)

    delivery_result = _deliver_report(schedule, content)
    schedule.last_run_at = datetime.utcnow()
    db.session.add(schedule)
    db.session.commit()
    return jsonify({"status": "sent", "delivery": delivery_result})


def _csv_content(fieldnames, rows):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def _deliver_report(schedule, content):
    if schedule.delivery_channel == "email":
        # Placeholder for real email integration.
        return {
            "channel": "email",
            "recipient": schedule.recipient,
            "bytes": len(content.encode("utf-8")),
            "note": "Email delivery stub executed",
        }

    try:
        client = SlackWebhookClient(schedule.recipient)
        response = client.send_message(
            text=(
                f"UVT scheduled report: {schedule.name} ({schedule.frequency})\n"
                f"Report type: {schedule.report_type}\n"
                f"CSV bytes: {len(content.encode('utf-8'))}"
            )
        )
        return {"channel": "slack", "status": response.status, "body": response.body}
    except SlackWebhookError as exc:
        return {"channel": "slack", "error": str(exc)}


def _schedule_json(schedule):
    return {
        "id": schedule.id,
        "name": schedule.name,
        "report_type": schedule.report_type,
        "frequency": schedule.frequency,
        "delivery_channel": schedule.delivery_channel,
        "recipient": schedule.recipient,
        "filters": schedule.filters_json or {},
        "created_by": schedule.created_by,
        "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
        "created_at": schedule.created_at.isoformat() if schedule.created_at else None,
    }
