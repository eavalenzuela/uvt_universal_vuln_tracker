from flask import Blueprint, jsonify, request
from sqlalchemy import asc, or_

from ..auth import login_required, role_required
from ..database import db
from ..models import ReportTemplate
from .validation import ValidationError, enum_value, error_response, paginate_query, required_string
from ..serializers.report_serializers import serialize_template
from .report_exports import (
    ALLOWED_CHANNELS,
    ALLOWED_EXPORT_FORMATS,
    ALLOWED_REPORT_TYPES,
    EXPORT_FIELDS,
    VISIBILITY_OPTIONS,
    _parse_recipients,
)

bp = Blueprint("report_templates_api", __name__, url_prefix="/api")


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

def _serialize_template(template):
    return serialize_template(template)


def _query_visible_templates(user):
    if user.role == "Admin":
        return ReportTemplate.query
    return ReportTemplate.query.filter(
        or_(
            ReportTemplate.owner_id == user.id,
            ReportTemplate.visibility == "team",
        )
    )


def _can_manage_template(user, template):
    return user.role == "Admin" or template.owner_id == user.id


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bp.get("/reports/templates")
@login_required
def list_report_templates():
    query = _query_visible_templates(request.user).order_by(
        asc(ReportTemplate.name),
        asc(ReportTemplate.id),
    )
    try:
        templates, meta = paginate_query(query)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify({"items": [_serialize_template(t) for t in templates], **meta})


@bp.post("/reports/templates")
@role_required("Admin", "Analyst")
def create_report_template():
    payload = request.get_json(silent=True) or {}
    user = request.user
    try:
        name = required_string(payload, "name")
        report_type = enum_value(payload.get("report_type") or "vulnerabilities", field="report_type", options=ALLOWED_REPORT_TYPES, required=True)
        export_format = enum_value((payload.get("format") or "csv").lower(), field="format", options=ALLOWED_EXPORT_FORMATS, required=True)
        delivery_channel = enum_value((payload.get("delivery_channel") or "email").lower(), field="delivery_channel", options=ALLOWED_CHANNELS, required=True)
        visibility = enum_value((payload.get("visibility") or "private").lower(), field="visibility", options=VISIBILITY_OPTIONS, required=True)
        recipients = _parse_recipients(payload)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    filters = payload.get("filters") or {}
    fields = payload.get("fields") or EXPORT_FIELDS
    preferences = payload.get("delivery_preferences") or {}
    if not isinstance(filters, dict):
        return error_response("filters must be an object", field="filters")
    if not isinstance(fields, list) or not all(isinstance(x, str) for x in fields):
        return error_response("fields must be an array of strings", field="fields")
    if not isinstance(preferences, dict):
        return error_response("delivery_preferences must be an object", field="delivery_preferences")

    template = ReportTemplate(
        name=name,
        report_type=report_type,
        fields_json=fields,
        filters_json=filters,
        export_format=export_format,
        delivery_channel=delivery_channel,
        recipients_json=recipients,
        delivery_preferences_json=preferences,
        visibility=visibility,
        owner_id=user.id,
    )
    db.session.add(template)
    db.session.commit()
    return jsonify(_serialize_template(template)), 201


@bp.patch("/reports/templates/<int:template_id>")
@role_required("Admin", "Analyst")
def update_report_template(template_id):
    user = request.user
    template = ReportTemplate.query.get_or_404(template_id)
    if not _can_manage_template(user, template):
        return error_response("Forbidden", status_code=403)

    payload = request.get_json(silent=True) or {}
    try:
        if "name" in payload:
            template.name = required_string(payload, "name")
        if "report_type" in payload:
            template.report_type = enum_value(payload.get("report_type"), field="report_type", options=ALLOWED_REPORT_TYPES, required=True)
        if "format" in payload:
            template.export_format = enum_value((payload.get("format") or "").lower(), field="format", options=ALLOWED_EXPORT_FORMATS, required=True)
        if "delivery_channel" in payload:
            template.delivery_channel = enum_value((payload.get("delivery_channel") or "").lower(), field="delivery_channel", options=ALLOWED_CHANNELS, required=True)
        if "visibility" in payload:
            template.visibility = enum_value((payload.get("visibility") or "").lower(), field="visibility", options=VISIBILITY_OPTIONS, required=True)
        if "recipient" in payload or "recipients" in payload:
            template.recipients_json = _parse_recipients(payload)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    if "filters" in payload:
        filters = payload.get("filters") or {}
        if not isinstance(filters, dict):
            return error_response("filters must be an object", field="filters")
        template.filters_json = filters
    if "fields" in payload:
        fields = payload.get("fields") or []
        if not isinstance(fields, list) or not all(isinstance(x, str) for x in fields):
            return error_response("fields must be an array of strings", field="fields")
        template.fields_json = fields
    if "delivery_preferences" in payload:
        prefs = payload.get("delivery_preferences") or {}
        if not isinstance(prefs, dict):
            return error_response("delivery_preferences must be an object", field="delivery_preferences")
        template.delivery_preferences_json = prefs

    db.session.add(template)
    db.session.commit()
    return jsonify(_serialize_template(template))


@bp.delete("/reports/templates/<int:template_id>")
@role_required("Admin", "Analyst")
def delete_report_template(template_id):
    user = request.user
    template = ReportTemplate.query.get_or_404(template_id)
    if not _can_manage_template(user, template):
        return error_response("Forbidden", status_code=403)
    db.session.delete(template)
    db.session.commit()
    return jsonify({"ok": True})
