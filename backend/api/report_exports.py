import csv
import hashlib
import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from flask import Blueprint, current_app, jsonify, request, Response, send_file
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy import func

from ..auth import login_required
from ..database import db
from ..models import ReportArtifact, Vulnerability
from ..rate_limiter import rate_limit
from .validation import ValidationError, error_response
from ..services.vulnerability_query import build_vulnerability_query
from ..services.reporting_service import dashboard_aggregate, risk_trends
from ..services.slack_alerts import SlackWebhookClient, SlackWebhookError
from ..services.email_delivery import EmailDeliveryError, send_email

bp = Blueprint("report_exports_api", __name__, url_prefix="/api")

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
RUN_STATUS_VALUES = {"never", "success", "failed", "retrying"}
SEVERITY_WEIGHTS = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1, "None": 0}
OPEN_STATUSES = {"Open", "In Progress"}

ALLOWED_EXPORT_FORMATS = {"csv", "json", "pdf"}
REPORT_EXPORT_TOKEN_SALT = "reports-artifact-download"


VISIBILITY_OPTIONS = {"private", "team"}


# ---------------------------------------------------------------------------
# Shared helper functions
# ---------------------------------------------------------------------------

def _merged_schedule_settings(schedule):
    template = schedule.report_template
    payload = {
        "report_type": schedule.report_type,
        "delivery_channel": schedule.delivery_channel,
        "recipients": (schedule.recipients_json or []) or ([schedule.recipient] if schedule.recipient else []),
        "filters": schedule.filters_json or {},
        "delivery_preferences": schedule.delivery_preferences_json or {},
        "format": "csv",
        "fields": EXPORT_FIELDS,
    }
    if template:
        payload["report_type"] = template.report_type or payload["report_type"]
        payload["delivery_channel"] = template.delivery_channel or payload["delivery_channel"]
        payload["recipients"] = template.recipients_json or payload["recipients"]
        payload["filters"] = template.filters_json or payload["filters"]
        payload["delivery_preferences"] = template.delivery_preferences_json or payload["delivery_preferences"]
        payload["format"] = template.export_format or payload["format"]
        payload["fields"] = template.fields_json or payload["fields"]
    return payload


def _parse_recipients(payload):
    recipients = payload.get("recipients")
    if recipients is None:
        from .validation import required_string
        return [required_string(payload, "recipient")]

    if not isinstance(recipients, list):
        raise ValidationError("recipients must be an array of strings", field="recipients")

    cleaned = [str(item).strip() for item in recipients if str(item).strip()]
    if not cleaned:
        raise ValidationError("recipients must include at least one recipient", field="recipients")
    return cleaned


def _retry_window_minutes(retry_count):
    if retry_count <= 0:
        return 0
    return min(5 * (2 ** max(retry_count - 1, 0)), 240)


def _mark_schedule_delivery_state(schedule, *, ok, failure_reason=None):
    now = datetime.now(timezone.utc)
    schedule.last_run_at = now if ok else schedule.last_run_at
    schedule.last_attempted_at = now
    if ok:
        schedule.last_failure_reason = None
    elif isinstance(failure_reason, str):
        schedule.last_failure_reason = failure_reason
    elif failure_reason is None:
        schedule.last_failure_reason = "Unknown delivery failure"
    else:
        schedule.last_failure_reason = json.dumps(failure_reason)
    if ok:
        schedule.last_run_status = "success"
        schedule.retry_count = 0
        schedule.next_retry_at = None
        return

    next_retry_count = (schedule.retry_count or 0) + 1
    schedule.retry_count = next_retry_count
    delay_minutes = _retry_window_minutes(next_retry_count)
    schedule.next_retry_at = now + timedelta(minutes=delay_minutes)
    schedule.last_run_status = "retrying" if next_retry_count < 5 else "failed"



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
    now = datetime.now(timezone.utc)
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
    return dashboard_aggregate(filters, group_by=group_by, range_value=range_value)


def _risk_trends(filters):
    return risk_trends(filters)


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


def _json_bytes(payload):
    return json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")


def _pdf_bytes(title, payload):
    lines = [title, "", json.dumps(payload, indent=2, sort_keys=True)]
    text = "\n".join(lines)
    safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 10 Tf 40 780 Td ({safe}) Tj ET"
    content = stream.encode("latin-1", errors="replace")
    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
        b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Courier >> endobj",
        f"5 0 obj << /Length {len(content)} >> stream\n".encode("ascii") + content + b"\nendstream endobj",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(output))
        output.extend(obj + b"\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        output.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    output.extend(f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode("ascii"))
    return bytes(output)


def _report_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=REPORT_EXPORT_TOKEN_SALT)


def _report_dir():
    root = current_app.config.get("REPORT_ARTIFACT_DIR") or os.path.join(current_app.instance_path, "report_artifacts")
    Path(root).mkdir(parents=True, exist_ok=True)
    return root


def _build_export_artifact(*, report_type, export_format, filters, payload, filename_prefix, created_by_user_id=None):
    if export_format == "csv":
        if report_type == "dashboard_summary":
            content_bytes = _csv_content_bytes(["metric", "group", "value"], _summary_rows(payload))
        else:
            content_bytes = _csv_content_bytes(EXPORT_FIELDS, payload)
        content_type = "text/csv"
        extension = "csv"
    elif export_format == "json":
        content_bytes = _json_bytes(payload)
        content_type = "application/json"
        extension = "json"
    else:
        content_bytes = _pdf_bytes(f"UVT {report_type} report", payload)
        content_type = "application/pdf"
        extension = "pdf"

    digest = hashlib.sha256(content_bytes).hexdigest()
    storage_name = f"{filename_prefix}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8]}.{extension}"
    storage_path = os.path.join(_report_dir(), storage_name)
    with open(storage_path, "wb") as handle:
        handle.write(content_bytes)

    artifact = ReportArtifact(
        report_type=report_type,
        format=export_format,
        storage_path=storage_path,
        checksum=digest,
        size=len(content_bytes),
        content_type=content_type,
        filters_json=dict(filters or {}),
        created_by=created_by_user_id or request.user.id,
    )
    db.session.add(artifact)
    db.session.commit()
    return artifact


def _artifact_download_url(artifact):
    token = _report_serializer().dumps({"artifact_id": artifact.id, "user_id": request.user.id})
    return f"/api/reports/artifacts/{artifact.id}/download?token={token}"


def _report_artifact_json(artifact):
    return {
        "id": artifact.id,
        "report_type": artifact.report_type,
        "format": artifact.format,
        "content_type": artifact.content_type,
        "size": artifact.size,
        "checksum": artifact.checksum,
        "created_at": artifact.created_at.isoformat() if artifact.created_at else None,
        "download_url": _artifact_download_url(artifact),
    }


def _csv_content_bytes(fieldnames, rows):
    return _csv_content(fieldnames, rows).encode("utf-8")


def _csv_content(fieldnames, rows):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


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


def _build_export_artifact_async(*, report_type, export_format, filters, user_id):
    """Build a report artifact from a background task (no request context)."""
    if report_type == "dashboard_summary":
        payload = _dashboard_summary(filters)
    else:
        q, _ = build_vulnerability_query(filters or {}, base_query=Vulnerability.query)
        payload = [_vuln_row(v) for v in q.all()]

    return _build_export_artifact(
        report_type=report_type,
        export_format=export_format,
        filters=filters,
        payload=payload,
        filename_prefix="report",
        created_by_user_id=user_id,
    )


def _deliver_report(schedule, content):
    effective = _merged_schedule_settings(schedule)
    recipients = effective["recipients"]
    prefs = effective["delivery_preferences"]
    subject_suffix = prefs.get("subject_suffix")
    subject = f"UVT scheduled report: {schedule.name} ({schedule.frequency})"
    if subject_suffix:
        subject = f"{subject} {subject_suffix}".strip()

    if effective["delivery_channel"] == "email":
        try:
            result = send_email(
                recipient=", ".join(recipients),
                subject=subject,
                body_text=(
                    f"UVT scheduled report generated\n"
                    f"Report: {schedule.name}\n"
                    f"Type: {effective['report_type']}\n"
                    f"Frequency: {schedule.frequency}\n"
                    f"Timezone: {schedule.timezone}\n"
                    f"CSV bytes: {len(content.encode('utf-8'))}\n\n"
                    f"{content}"
                ),
                plugin_id="email",
            )
            result["ok"] = not result.get("error")
            result["recipients"] = recipients
            return result
        except EmailDeliveryError as exc:
            payload = exc.as_dict()
            payload["ok"] = False
            payload["recipients"] = recipients
            return payload

    webhook = recipients[0] if recipients else schedule.recipient
    try:
        client = SlackWebhookClient(webhook)
        response = client.send_message(
            text=(
                f"UVT scheduled report: {schedule.name} ({schedule.frequency})\n"
                f"Report type: {effective['report_type']}\n"
                f"Timezone: {schedule.timezone}\n"
                f"CSV bytes: {len(content.encode('utf-8'))}"
            )
        )
        return {
            "channel": "slack",
            "status": response.status,
            "body": response.body,
            "ok": True,
            "recipients": recipients,
        }
    except SlackWebhookError as exc:
        return {"channel": "slack", "error": str(exc), "ok": False, "recipients": recipients}


# ---------------------------------------------------------------------------
# Route: resolve template helper (used by export routes)
# ---------------------------------------------------------------------------

def _resolve_template_for_user(template_id, *, user, required=False):
    from ..models import ReportTemplate
    from sqlalchemy import or_

    if template_id in (None, ""):
        return None
    try:
        template_id = int(template_id)
    except (TypeError, ValueError):
        raise ValidationError("report_template_id must be an integer", field="report_template_id")

    if user.role == "Admin":
        query = ReportTemplate.query
    else:
        query = ReportTemplate.query.filter(
            or_(
                ReportTemplate.owner_id == user.id,
                ReportTemplate.visibility == "team",
            )
        )

    template = query.filter(ReportTemplate.id == template_id).first()
    if template is None and required:
        raise ValidationError("report template not found", field="report_template_id")
    return template


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bp.get("/reports/vulnerabilities/export")
@login_required
@rate_limit("RATE_LIMIT_VULN_EXPORT_LIMIT", "RATE_LIMIT_VULN_EXPORT_WINDOW_SECONDS", identifier="report_vuln_export")
def export_vulnerabilities():
    """Export vulnerabilities as CSV, JSON, or PDF.
    ---
    get:
      summary: Export vulnerabilities report
      security:
        - BearerAuth: []
      parameters:
        - in: query
          name: format
          schema:
            type: string
            enum: [csv, json, pdf]
            default: csv
        - in: query
          name: report_template_id
          schema:
            type: integer
          description: Optional report template to apply filters and format from
        - in: query
          name: severity
          schema:
            type: string
        - in: query
          name: status
          schema:
            type: string
        - in: query
          name: product_id
          schema:
            type: integer
      responses:
        200:
          description: Export artifact created
          content:
            application/json:
              schema:
                type: object
                properties:
                  artifact:
                    $ref: '#/components/schemas/ReportArtifact'
        400:
          description: Invalid format or filter error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        429:
          description: Rate limit exceeded
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    export_format = (request.args.get("format") or "csv").lower()
    if export_format not in ALLOWED_EXPORT_FORMATS:
        return error_response("format must be one of csv, json, pdf", status_code=400)
    filters = request.args.to_dict(flat=True)
    filters.pop("format", None)
    template = None
    try:
        template = _resolve_template_for_user(request.args.get("report_template_id"), user=request.user)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    if template:
        filters = template.filters_json or filters
        export_format = template.export_format or export_format
    try:
        items, _ = build_vulnerability_query(filters, base_query=Vulnerability.query)
        items = items.all()
    except ValueError as exc:
        return error_response(str(exc), status_code=400)
    rows = [_vuln_row(v) for v in items]
    artifact = _build_export_artifact(
        report_type="vulnerabilities",
        export_format=export_format,
        filters=filters,
        payload=rows,
        filename_prefix="vulnerabilities_export",
    )
    return jsonify({"artifact": _report_artifact_json(artifact)})


@bp.get("/reports/dashboard/export")
@login_required
@rate_limit("RATE_LIMIT_VULN_EXPORT_LIMIT", "RATE_LIMIT_VULN_EXPORT_WINDOW_SECONDS", identifier="report_dashboard_export")
def export_dashboard_summary():
    """Export dashboard summary as CSV, JSON, or PDF.
    ---
    get:
      summary: Export dashboard summary report
      security:
        - BearerAuth: []
      parameters:
        - in: query
          name: format
          schema:
            type: string
            enum: [csv, json, pdf]
            default: csv
        - in: query
          name: report_template_id
          schema:
            type: integer
          description: Optional report template to apply filters and format from
      responses:
        200:
          description: Export artifact created
          content:
            application/json:
              schema:
                type: object
                properties:
                  artifact:
                    $ref: '#/components/schemas/ReportArtifact'
        400:
          description: Invalid format or filter error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        429:
          description: Rate limit exceeded
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    export_format = (request.args.get("format") or "csv").lower()
    if export_format not in ALLOWED_EXPORT_FORMATS:
        return error_response("format must be one of csv, json, pdf", status_code=400)
    filters = request.args.to_dict(flat=True)
    filters.pop("format", None)
    template = None
    try:
        template = _resolve_template_for_user(request.args.get("report_template_id"), user=request.user)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    if template:
        filters = template.filters_json or filters
        export_format = template.export_format or export_format
    try:
        summary = _dashboard_summary(filters)
    except ValueError as exc:
        return error_response(str(exc), status_code=400)
    artifact = _build_export_artifact(
        report_type="dashboard_summary",
        export_format=export_format,
        filters=filters,
        payload=summary,
        filename_prefix="dashboard_summary",
    )
    return jsonify({"artifact": _report_artifact_json(artifact)})




@bp.get("/reports/artifacts/<int:artifact_id>/download")
@login_required
def download_report_artifact(artifact_id):
    """Download a report artifact file.
    ---
    get:
      summary: Download a report artifact
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: artifact_id
          required: true
          schema:
            type: integer
        - in: query
          name: token
          required: true
          schema:
            type: string
          description: Signed download token (valid for 10 minutes)
      responses:
        200:
          description: Artifact file download
          content:
            text/csv:
              schema:
                type: string
                format: binary
            application/json:
              schema:
                type: string
                format: binary
            application/pdf:
              schema:
                type: string
                format: binary
        403:
          description: Missing, invalid, or expired token, or forbidden access
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        404:
          description: Artifact not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    artifact = ReportArtifact.query.filter_by(id=artifact_id).first()
    if not artifact:
        return error_response("Artifact not found", status_code=404)

    token = request.args.get("token")
    if not token:
        return error_response("Missing token", status_code=403)

    try:
        payload = _report_serializer().loads(token, max_age=600)
    except (BadSignature, SignatureExpired):
        return error_response("Invalid token", status_code=403)

    if payload.get("artifact_id") != artifact.id or payload.get("user_id") != request.user.id:
        return error_response("Forbidden", status_code=403)

    if request.user.role != "Admin" and artifact.created_by != request.user.id:
        return error_response("Forbidden", status_code=403)

    filename = f"{artifact.report_type}.{artifact.format}"
    return send_file(
        artifact.storage_path,
        mimetype=artifact.content_type or "application/octet-stream",
        as_attachment=True,
        download_name=filename,
    )

@bp.get("/dashboard/summary")
@login_required
@rate_limit("RATE_LIMIT_VULN_LIST_LIMIT", "RATE_LIMIT_VULN_LIST_WINDOW_SECONDS", identifier="dashboard_summary")
def dashboard_summary():
    """Get aggregated dashboard summary with by_severity, by_status, and total.
    ---
    get:
      summary: Get dashboard summary
      security:
        - BearerAuth: []
      parameters:
        - in: query
          name: group_by
          schema:
            type: string
            default: Severity
        - in: query
          name: range
          schema:
            type: string
            default: Last 14 days
          description: Time range filter (e.g. "Last 14 days", "Month to date", "Quarter to date")
      responses:
        200:
          description: Dashboard summary data
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DashboardSummary'
        400:
          description: Invalid filter parameters
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        429:
          description: Rate limit exceeded
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
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
    """Get risk trend data over time.
    ---
    get:
      summary: Get risk trend data
      security:
        - BearerAuth: []
      responses:
        200:
          description: Risk trend data
          content:
            application/json:
              schema:
                type: object
        400:
          description: Invalid filter parameters
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        429:
          description: Rate limit exceeded
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    try:
        payload = _risk_trends(request.args)
    except ValueError as exc:
        return error_response(str(exc), status_code=400)
    return jsonify(payload)
