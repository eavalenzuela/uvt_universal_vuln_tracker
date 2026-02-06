import csv
import io
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request, Response
from sqlalchemy import desc, func

from ..auth import login_required, role_required
from ..database import db
from ..models import Product, ProductVersion, ReportSchedule, Vulnerability, VulnerabilityVersion
from ..services.slack_alerts import SlackWebhookClient, SlackWebhookError
from ..rate_limiter import rate_limit
from .validation import ValidationError, enum_value, error_response, required_string
from ..services.vulnerability_query import build_vulnerability_query

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
    "component_ecosystems",
    "component_packages",
    "max_transitive_depth",
]

ALLOWED_FREQUENCIES = {"daily", "weekly"}
ALLOWED_CHANNELS = {"email", "slack"}
ALLOWED_REPORT_TYPES = {"vulnerabilities", "dashboard_summary"}
SEVERITY_WEIGHTS = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1, "None": 0}
OPEN_STATUSES = {"Open", "In Progress"}


def _parse_csv_ints(value):
    if not value:
        return []
    parts = str(value).split(",")
    parsed = []
    for part in parts:
        item = part.strip()
        if not item:
            continue
        try:
            parsed.append(int(item))
        except ValueError as exc:
            raise ValueError("Filter values must be integer ids") from exc
    return parsed


def _parse_iso_datetime(value, *, field):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise ValueError(f"{field} must be ISO-8601 datetime") from exc


def _range_start(range_value):
    now = datetime.utcnow()
    if range_value == "Month to date":
        return datetime(now.year, now.month, 1)
    if range_value == "Quarter to date":
        quarter_start_month = (now.month - 1) // 3 * 3 + 1
        return datetime(now.year, quarter_start_month, 1)
    if range_value:
        import re

        match = re.match(r"Last\s+(\d+)\s+days", range_value, flags=re.IGNORECASE)
        if match:
            return now - timedelta(days=int(match.group(1)))
    return now - timedelta(days=14)


def _dashboard_aggregate(filters, *, group_by="severity", range_value="Last 14 days"):
    q, _ = build_vulnerability_query(filters, base_query=Vulnerability.query)
    total = q.count()

    rows = q.with_entities(
        Vulnerability.id,
        Vulnerability.severity,
        Vulnerability.status,
        Vulnerability.assigned_to,
        Vulnerability.updated_at,
    ).all()

    by_severity = {}
    by_status = {}
    group_totals = {}
    group_attr = {
        "Severity": "severity",
        "Status": "status",
        "Assignee": "assigned_to",
    }.get(group_by, "severity")

    start = _range_start(range_value)
    end = datetime.utcnow()
    days = max(1, (end.date() - start.date()).days + 1)
    buckets = [
        {"date": (start.date() + timedelta(days=i)).isoformat(), "count": 0}
        for i in range(days)
    ]

    for _, severity, status, assigned_to, updated_at in rows:
        severity_key = severity or "Unknown"
        status_key = status or "Unknown"
        by_severity[severity_key] = by_severity.get(severity_key, 0) + 1
        by_status[status_key] = by_status.get(status_key, 0) + 1

        group_value = {
            "severity": severity_key,
            "status": status_key,
            "assigned_to": str(assigned_to) if assigned_to is not None else "Unassigned",
        }[group_attr]
        group_totals[group_value] = group_totals.get(group_value, 0) + 1

        if updated_at:
            updated_dt = updated_at if isinstance(updated_at, datetime) else datetime.fromisoformat(str(updated_at))
            if start <= updated_dt <= end:
                idx = (updated_dt.date() - start.date()).days
                if 0 <= idx < len(buckets):
                    buckets[idx]["count"] += 1

    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "group_by": group_by,
        "group_totals": group_totals,
        "trend": {
            "range": range_value,
            "start_date": start.date().isoformat(),
            "end_date": end.date().isoformat(),
            "buckets": buckets,
        },
    }


def _risk_trends(filters):
    bucket = (filters.get("bucket") or "week").lower()
    if bucket not in {"day", "week", "month"}:
        raise ValueError("bucket must be one of day, week, month")

    start = _parse_iso_datetime(filters.get("start_date"), field="start_date") or _range_start(filters.get("range") or "Last 30 days")
    end = _parse_iso_datetime(filters.get("end_date"), field="end_date") or datetime.utcnow()
    if start > end:
        raise ValueError("start_date must be <= end_date")

    product_ids = _parse_csv_ints(filters.get("product_ids"))
    product_version_ids = _parse_csv_ints(filters.get("product_version_ids"))

    q = (
        db.session.query(
            Vulnerability.updated_at,
            Vulnerability.severity,
            Vulnerability.status,
            Vulnerability.sla_due_at,
            Product.id,
            Product.name,
            ProductVersion.id,
            ProductVersion.version,
        )
        .select_from(Vulnerability)
        .join(VulnerabilityVersion, VulnerabilityVersion.vulnerability_id == Vulnerability.id)
        .join(ProductVersion, ProductVersion.id == VulnerabilityVersion.product_version_id)
        .join(Product, Product.id == ProductVersion.product_id)
        .filter(Vulnerability.updated_at >= start)
        .filter(Vulnerability.updated_at <= end)
    )

    if product_ids:
        q = q.filter(Product.id.in_(product_ids))
    if product_version_ids:
        q = q.filter(ProductVersion.id.in_(product_version_ids))

    rows = q.all()
    now = datetime.utcnow()
    grouped = {}

    for updated_at, severity, status, sla_due_at, product_id, product_name, product_version_id, product_version in rows:
        if not updated_at:
            continue
        if bucket == "day":
            bucket_value = updated_at.strftime("%Y-%m-%d")
        elif bucket == "week":
            iso_year, iso_week, _ = updated_at.isocalendar()
            bucket_value = f"{iso_year}-W{iso_week:02d}"
        else:
            bucket_value = updated_at.strftime("%Y-%m")

        key = (product_id, product_version_id, bucket_value)
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "product_id": product_id,
                "product_name": product_name,
                "product_version_id": product_version_id,
                "product_version": product_version,
                "bucket": bucket_value,
                "open_critical_count": 0,
                "overdue_sla_count": 0,
                "weighted_risk_score": 0,
            }
            grouped[key] = entry

        is_open = status in OPEN_STATUSES
        if is_open and severity == "Critical":
            entry["open_critical_count"] += 1
        if is_open and sla_due_at and sla_due_at < now:
            entry["overdue_sla_count"] += 1
        entry["weighted_risk_score"] += SEVERITY_WEIGHTS.get(severity, 0)

    trend_rows = sorted(
        grouped.values(),
        key=lambda item: (item["product_name"] or "", item["product_version"] or "", item["bucket"]),
    )
    top_risk = sorted(
        trend_rows,
        key=lambda item: (item["weighted_risk_score"], item["open_critical_count"], item["overdue_sla_count"]),
        reverse=True,
    )[:5]
    return {
        "bucket": bucket,
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "items": trend_rows,
        "top_risk_products": top_risk,
    }


def _vuln_row(v):
    components = [link.component for link in (v.affected_components or []) if link.component]
    ecosystems = sorted({c.ecosystem for c in components if c.ecosystem})
    packages = sorted({c.name for c in components if c.name})
    max_depth = max([link.transitive_depth for link in (v.affected_components or [])], default=0)
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
        "component_ecosystems": ";".join(ecosystems),
        "component_packages": ";".join(packages),
        "max_transitive_depth": max_depth,
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
    q, _ = build_vulnerability_query(filters, base_query=Vulnerability.query)
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
@rate_limit("RATE_LIMIT_VULN_EXPORT_LIMIT", "RATE_LIMIT_VULN_EXPORT_WINDOW_SECONDS", identifier="report_vuln_export")
def export_vulnerabilities():
    try:
        items, _ = build_vulnerability_query(request.args, base_query=Vulnerability.query)
        items = items.all()
    except ValueError as exc:
        return error_response(str(exc), status_code=400)
    rows = [_vuln_row(v) for v in items]
    return _csv_response("vulnerabilities_export.csv", EXPORT_FIELDS, rows)


@bp.get("/reports/dashboard/export")
@login_required
@rate_limit("RATE_LIMIT_VULN_EXPORT_LIMIT", "RATE_LIMIT_VULN_EXPORT_WINDOW_SECONDS", identifier="report_dashboard_export")
def export_dashboard_summary():
    try:
        summary = _dashboard_summary(request.args)
    except ValueError as exc:
        return error_response(str(exc), status_code=400)
    return _csv_response("dashboard_summary.csv", ["metric", "group", "value"], _summary_rows(summary))


@bp.get("/dashboard/summary")
@login_required
@rate_limit("RATE_LIMIT_VULN_LIST_LIMIT", "RATE_LIMIT_VULN_LIST_WINDOW_SECONDS", identifier="dashboard_summary")
def dashboard_summary():
    filters = request.args
    group_by = request.args.get("group_by") or "Severity"
    range_value = request.args.get("range") or "Last 14 days"
    try:
        payload = _dashboard_aggregate(filters, group_by=group_by, range_value=range_value)
    except ValueError as exc:
        return error_response(str(exc), status_code=400)
    return jsonify(payload)


@bp.get("/reports/risk-trends")
@login_required
@rate_limit("RATE_LIMIT_VULN_LIST_LIMIT", "RATE_LIMIT_VULN_LIST_WINDOW_SECONDS", identifier="risk_trends")
def report_risk_trends():
    try:
        payload = _risk_trends(request.args)
    except ValueError as exc:
        return error_response(str(exc), status_code=400)
    return jsonify(payload)


@bp.post("/reports/schedules")
@role_required("Admin", "Analyst")
def create_report_schedule():
    payload = request.get_json(silent=True) or {}

    try:
        name = required_string(payload, "name")
        report_type = enum_value(payload.get("report_type") or "vulnerabilities", field="report_type", options=ALLOWED_REPORT_TYPES, required=True)
        frequency = enum_value((payload.get("frequency") or "daily").lower(), field="frequency", options=ALLOWED_FREQUENCIES, required=True)
        delivery_channel = enum_value((payload.get("delivery_channel") or "email").lower(), field="delivery_channel", options=ALLOWED_CHANNELS, required=True)
        recipient = required_string(payload, "recipient")
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

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
        return error_response("Forbidden", status_code=403)

    filters = schedule.filters_json or {}
    try:
        if schedule.report_type == "dashboard_summary":
            content = _csv_content(["metric", "group", "value"], _summary_rows(_dashboard_summary(filters)))
        else:
            query, _ = build_vulnerability_query(filters, base_query=Vulnerability.query)
            rows = [_vuln_row(v) for v in query.all()]
            content = _csv_content(EXPORT_FIELDS, rows)
    except ValueError as exc:
        return error_response(str(exc), status_code=400)

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
