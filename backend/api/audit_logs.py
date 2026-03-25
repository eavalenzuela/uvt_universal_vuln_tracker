from flask import Blueprint, jsonify, request

from ..models import AuditLog
from ..auth import role_required
from .validation import ValidationError, error_response, parse_int

bp = Blueprint("audit_logs_api", __name__, url_prefix="/api")


@bp.get("/audit-logs")
@role_required("Admin")
def list_audit_logs():
    try:
        page = parse_int(request.args.get("page"), field="page", minimum=1) or 1
        page_size = parse_int(request.args.get("page_size"), field="page_size", minimum=1, maximum=500) or 100
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    action = (request.args.get("action") or "").strip()
    table = (request.args.get("table") or "").strip()

    query = AuditLog.query
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
