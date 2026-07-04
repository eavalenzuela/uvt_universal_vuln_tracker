import csv
import io
import json

from flask import Blueprint, jsonify, request, Response
from sqlalchemy.orm import joinedload

from ..models import AuditLog
from ..auth import role_required
from ..rate_limiter import rate_limit
from .validation import ValidationError, error_response, parse_int

bp = Blueprint("audit_logs_api", __name__, url_prefix="/api")

# Hard cap on CSV export size to keep response times and memory bounded;
# narrow the window with action/table filters for larger histories.
EXPORT_MAX_ROWS = 10000


@bp.get("/audit-logs")
@role_required("Admin")
def list_audit_logs():
    """List audit logs with pagination and filtering.
    ---
    get:
      summary: List audit logs with pagination and filtering
      security:
        - BearerAuth: []
      parameters:
        - in: query
          name: page
          schema:
            type: integer
            minimum: 1
            default: 1
        - in: query
          name: page_size
          schema:
            type: integer
            minimum: 1
            maximum: 500
            default: 100
        - in: query
          name: action
          schema:
            type: string
        - in: query
          name: table
          schema:
            type: string
      responses:
        200:
          description: Paginated list of audit logs
          content:
            application/json:
              schema:
                type: object
                properties:
                  items:
                    type: array
                    items:
                      $ref: '#/components/schemas/AuditLog'
                  total:
                    type: integer
                  page:
                    type: integer
                  page_size:
                    type: integer
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    try:
        page = parse_int(request.args.get("page"), field="page", minimum=1) or 1
        page_size = parse_int(request.args.get("page_size"), field="page_size", minimum=1, maximum=500) or 100
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    action = (request.args.get("action") or "").strip()
    table = (request.args.get("table") or "").strip()

    # Eager-load the related user to avoid an N+1 lazy load per row below.
    query = AuditLog.query.options(joinedload(AuditLog.user))
    if action:
        query = query.filter(AuditLog.action == action)
    if table:
        query = query.filter(AuditLog.table_name == table)

    total = query.count()
    logs = query.order_by(AuditLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()

    def _user_payload(log: AuditLog):
        if not log.user:
            return None
        return {"id": log.user.id, "username": log.user.username, "email": log.user.email}

    return jsonify({
        "items": [
            {
                "id": log.id,
                "action": log.action,
                "table_name": log.table_name,
                "record_id": log.record_id,
                "old_values": log.old_values,
                "new_values": log.new_values,
                "created_at": log.created_at.isoformat() if log.created_at else None,
                "user": _user_payload(log),
            }
            for log in logs
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    })


@bp.get("/audit-logs/export.csv")
@role_required("Admin")
@rate_limit("RATE_LIMIT_VULN_EXPORT_LIMIT", "RATE_LIMIT_VULN_EXPORT_WINDOW_SECONDS", identifier="audit_export")
def export_audit_logs_csv():
    """Export audit logs as a CSV file.
    ---
    get:
      summary: Export audit logs as CSV
      security:
        - BearerAuth: []
      parameters:
        - in: query
          name: action
          schema:
            type: string
          description: Filter by exact action (e.g. UPDATE, IMPERSONATE)
        - in: query
          name: table
          schema:
            type: string
          description: Filter by table name (e.g. vulnerabilities)
      responses:
        200:
          description: CSV file download (most recent 10000 rows matching the filters)
          content:
            text/csv:
              schema:
                type: string
                format: binary
          headers:
            Content-Disposition:
              schema:
                type: string
                example: attachment; filename=audit-logs.csv
        429:
          description: Rate limit exceeded
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    action = (request.args.get("action") or "").strip()
    table = (request.args.get("table") or "").strip()

    query = AuditLog.query.options(joinedload(AuditLog.user))
    if action:
        query = query.filter(AuditLog.action == action)
    if table:
        query = query.filter(AuditLog.table_name == table)

    logs = query.order_by(AuditLog.created_at.desc()).limit(EXPORT_MAX_ROWS).all()

    def _json_cell(value):
        if value in (None, {}):
            return ""
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["id", "created_at", "action", "table_name", "record_id", "username", "user_email", "old_values", "new_values"],
    )
    writer.writeheader()
    for log in logs:
        writer.writerow({
            "id": log.id,
            "created_at": log.created_at.isoformat() if log.created_at else "",
            "action": log.action,
            "table_name": log.table_name,
            "record_id": log.record_id if log.record_id is not None else "",
            "username": log.user.username if log.user else "",
            "user_email": log.user.email if log.user else "",
            "old_values": _json_cell(log.old_values),
            "new_values": _json_cell(log.new_values),
        })

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit-logs.csv"},
    )
