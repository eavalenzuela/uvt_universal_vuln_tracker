from flask import Blueprint, jsonify, request
from sqlalchemy import desc

from ..auth import login_required, role_required
from ..database import db
from ..models import ReportSchedule, Vulnerability
from ..rate_limiter import rate_limit
from .validation import ValidationError, enum_value, error_response, paginate_query, required_string
from ..serializers.report_serializers import serialize_template
from ..services.vulnerability_query import build_vulnerability_query
from .report_exports import (
    ALLOWED_CHANNELS,
    ALLOWED_FREQUENCIES,
    ALLOWED_REPORT_TYPES,
    EXPORT_FIELDS,
    RUN_STATUS_VALUES,
    _csv_content,
    _dashboard_summary,
    _deliver_report,
    _mark_schedule_delivery_state,
    _merged_schedule_settings,
    _parse_recipients,
    _resolve_template_for_user,
    _summary_rows,
    _vuln_row,
)

bp = Blueprint("report_schedules_api", __name__, url_prefix="/api")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize_template(template):
    return serialize_template(template)


def _schedule_json(schedule):
    status = schedule.last_run_status if schedule.last_run_status in RUN_STATUS_VALUES else "never"
    return {
        "id": schedule.id,
        "name": schedule.name,
        "report_type": schedule.report_type,
        "frequency": schedule.frequency,
        "delivery_channel": schedule.delivery_channel,
        "recipient": schedule.recipient,
        "recipients": (schedule.recipients_json or []) or ([schedule.recipient] if schedule.recipient else []),
        "timezone": schedule.timezone or "UTC",
        "filter_preset": schedule.filter_preset,
        "filters": schedule.filters_json or {},
        "delivery_preferences": schedule.delivery_preferences_json or {},
        "created_by": schedule.created_by,
        "report_template_id": schedule.report_template_id,
        "report_template": _serialize_template(schedule.report_template) if schedule.report_template else None,
        "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
        "last_attempted_at": schedule.last_attempted_at.isoformat() if schedule.last_attempted_at else None,
        "last_run_status": status,
        "last_failure_reason": schedule.last_failure_reason,
        "retry_count": schedule.retry_count or 0,
        "next_retry_at": schedule.next_retry_at.isoformat() if schedule.next_retry_at else None,
        "created_at": schedule.created_at.isoformat() if schedule.created_at else None,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bp.post("/reports/schedules")
@role_required("Admin", "Analyst")
def create_report_schedule():
    payload = request.get_json(silent=True) or {}

    try:
        name = required_string(payload, "name")
        report_type = enum_value(payload.get("report_type") or "vulnerabilities", field="report_type", options=ALLOWED_REPORT_TYPES, required=True)
        frequency = enum_value((payload.get("frequency") or "daily").lower(), field="frequency", options=ALLOWED_FREQUENCIES, required=True)
        report_template = _resolve_template_for_user(payload.get("report_template_id"), user=request.user)
        delivery_channel = enum_value((payload.get("delivery_channel") or "email").lower(), field="delivery_channel", options=ALLOWED_CHANNELS, required=True)
        if "recipient" in payload or "recipients" in payload:
            recipients = _parse_recipients(payload)
        elif report_template:
            recipients = report_template.recipients_json or []
        else:
            raise ValidationError("recipient is required", field="recipient")
        timezone = str(payload.get("timezone") or "UTC").strip() or "UTC"
        filter_preset = (str(payload.get("filter_preset")).strip() if payload.get("filter_preset") is not None else None)
        delivery_preferences = payload.get("delivery_preferences") or {}
        if not isinstance(delivery_preferences, dict):
            raise ValidationError("delivery_preferences must be an object", field="delivery_preferences")
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    if report_template:
        report_type = report_template.report_type
        delivery_channel = report_template.delivery_channel
        recipients = report_template.recipients_json or recipients
        payload["filters"] = report_template.filters_json or payload.get("filters")
        delivery_preferences = report_template.delivery_preferences_json or delivery_preferences

    schedule = ReportSchedule(
        name=name,
        report_type=report_type,
        frequency=frequency,
        delivery_channel=delivery_channel,
        recipient=recipients[0],
        recipients_json=recipients,
        timezone=timezone,
        filter_preset=filter_preset,
        filters_json=payload.get("filters") or {},
        delivery_preferences_json=delivery_preferences,
        created_by=request.user.id,
        report_template_id=(report_template.id if report_template else None),
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
    q = q.order_by(desc(ReportSchedule.created_at))
    try:
        rows, meta = paginate_query(q)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify({"items": [_schedule_json(r) for r in rows], **meta})


@bp.patch("/reports/schedules/<int:schedule_id>")
@role_required("Admin", "Analyst")
def update_report_schedule(schedule_id):
    schedule = ReportSchedule.query.get_or_404(schedule_id)
    if request.user.role != "Admin" and schedule.created_by != request.user.id:
        return error_response("Forbidden", status_code=403)

    payload = request.get_json(silent=True) or {}
    try:
        if "report_template_id" in payload:
            report_template = _resolve_template_for_user(payload.get("report_template_id"), user=request.user, required=payload.get("report_template_id") is not None)
            schedule.report_template_id = report_template.id if report_template else None

        if "name" in payload:
            schedule.name = required_string(payload, "name")
        if "report_type" in payload:
            schedule.report_type = enum_value(payload.get("report_type"), field="report_type", options=ALLOWED_REPORT_TYPES, required=True)
        if "frequency" in payload:
            schedule.frequency = enum_value(str(payload.get("frequency") or "").lower(), field="frequency", options=ALLOWED_FREQUENCIES, required=True)
        if "delivery_channel" in payload:
            schedule.delivery_channel = enum_value(str(payload.get("delivery_channel") or "").lower(), field="delivery_channel", options=ALLOWED_CHANNELS, required=True)
        if "recipient" in payload or "recipients" in payload:
            recipients = _parse_recipients(payload)
            schedule.recipient = recipients[0]
            schedule.recipients_json = recipients
        if "timezone" in payload:
            schedule.timezone = (str(payload.get("timezone") or "UTC").strip() or "UTC")
        if "filter_preset" in payload:
            raw = payload.get("filter_preset")
            schedule.filter_preset = (str(raw).strip() if raw is not None else None)
        if "filters" in payload:
            schedule.filters_json = payload.get("filters") or {}
        if "delivery_preferences" in payload:
            prefs = payload.get("delivery_preferences") or {}
            if not isinstance(prefs, dict):
                raise ValidationError("delivery_preferences must be an object", field="delivery_preferences")
            schedule.delivery_preferences_json = prefs
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    db.session.add(schedule)
    db.session.commit()
    return jsonify(_schedule_json(schedule))


@bp.delete("/reports/schedules/<int:schedule_id>")
@role_required("Admin", "Analyst")
def delete_report_schedule(schedule_id):
    schedule = ReportSchedule.query.get_or_404(schedule_id)
    if request.user.role != "Admin" and schedule.created_by != request.user.id:
        return error_response("Forbidden", status_code=403)
    db.session.delete(schedule)
    db.session.commit()
    return jsonify({"ok": True})


@bp.post("/reports/schedules/<int:schedule_id>/run")
@role_required("Admin", "Analyst")
@rate_limit("RATE_LIMIT_SENSITIVE_LIMIT", "RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", identifier="report_run")
def run_report_schedule(schedule_id):
    schedule = ReportSchedule.query.get_or_404(schedule_id)
    if request.user.role != "Admin" and schedule.created_by != request.user.id:
        return error_response("Forbidden", status_code=403)

    effective = _merged_schedule_settings(schedule)
    filters = effective["filters"]
    try:
        if effective["report_type"] == "dashboard_summary":
            content = _csv_content(["metric", "group", "value"], _summary_rows(_dashboard_summary(filters)))
        else:
            query, _ = build_vulnerability_query(filters, base_query=Vulnerability.query)
            rows = [_vuln_row(v) for v in query.all()]
            fieldnames = [f for f in effective["fields"] if f in EXPORT_FIELDS] or EXPORT_FIELDS
            content = _csv_content(fieldnames, [{k: row.get(k) for k in fieldnames} for row in rows])
    except ValueError as exc:
        return error_response(str(exc), status_code=400)

    delivery_result = _deliver_report(schedule, content)
    ok = delivery_result.get("ok", False)
    _mark_schedule_delivery_state(schedule, ok=ok, failure_reason=delivery_result.get("error"))

    db.session.add(schedule)
    db.session.commit()
    return jsonify({"status": "sent" if ok else "failed", "delivery": delivery_result, "schedule": _schedule_json(schedule)})
