from __future__ import annotations

from datetime import timedelta

from flask import Blueprint, jsonify, request

from ..auth import role_required
from ..database import db
from ..models import NotificationDeliveryLog
from ..services.audit import record_audit
from ..services.notification_rules import NotificationEvent, trigger_notifications_for_event
from .validation import ValidationError, error_response, parse_int

bp = Blueprint("notification_delivery_api", __name__, url_prefix="/api")


def _status_for(row: NotificationDeliveryLog) -> str:
    return "delivered" if row.success else "failed"


def _retry_count_for(row: NotificationDeliveryLog) -> int:
    if row.success:
        return 0

    previous = NotificationDeliveryLog.query.filter(
        NotificationDeliveryLog.id <= row.id,
        NotificationDeliveryLog.rule_id == row.rule_id,
        NotificationDeliveryLog.vulnerability_id == row.vulnerability_id,
        NotificationDeliveryLog.event_type == row.event_type,
    ).order_by(NotificationDeliveryLog.id.desc()).all()

    count = 0
    for attempt in previous:
        if attempt.success:
            break
        count += 1
    return count


def _next_retry_for(row: NotificationDeliveryLog, retry_count: int):
    if row.success or not row.created_at:
        return None
    delay_seconds = min(60 * (2 ** max(retry_count - 1, 0)), 3600)
    return row.created_at + timedelta(seconds=delay_seconds)


def _attempt_json(row: NotificationDeliveryLog):
    retry_count = _retry_count_for(row)
    next_retry_at = _next_retry_for(row, retry_count)
    return {
        "id": row.id,
        "rule_id": row.rule_id,
        "vulnerability_id": row.vulnerability_id,
        "event_type": row.event_type,
        "status": _status_for(row),
        "channel": row.delivery_adapter,
        "error": row.error_message,
        "retry_count": retry_count,
        "next_retry_at": next_retry_at.isoformat() if next_retry_at else None,
        "response_payload": row.response_payload,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def _audit(action: str, record_id: int, *, old_values=None, new_values=None):
    record_audit(action, "notification_delivery_logs", record_id, old_values=old_values, new_values=new_values)


@bp.get("/notification-delivery-attempts")
@role_required("Admin")
def list_delivery_attempts():
    try:
        limit = parse_int(request.args.get("limit", 100), field="limit", minimum=1, maximum=500, required=True)
        failed_only = str(request.args.get("failed_only", "false")).strip().lower() in {"1", "true", "yes", "on"}
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    query = NotificationDeliveryLog.query.order_by(NotificationDeliveryLog.id.desc())
    if failed_only:
        query = query.filter_by(success=False)
    rows = query.limit(limit).all()
    return jsonify([_attempt_json(row) for row in rows])


def _retry_or_replay(*, log_row: NotificationDeliveryLog, action: str, guard_failures_only: bool) -> dict:
    if guard_failures_only and log_row.success:
        raise ValidationError("Only failed delivery attempts can be retried", field="attempt_id", status_code=409)
    if not log_row.rule_id or not log_row.vulnerability_id:
        raise ValidationError("Cannot replay delivery without rule_id and vulnerability_id", field="attempt_id", status_code=409)

    event = NotificationEvent(
        event_type=log_row.event_type,
        vulnerability_id=log_row.vulnerability_id,
        actor_id=request.user.id,
        new_values={
            "source_attempt_id": log_row.id,
            "operator_action": action,
        },
    )
    logs = trigger_notifications_for_event(event, dry_run_rule_id=log_row.rule_id)
    latest_id = logs[-1].id if logs else None
    return {"ok": True, "attempts": len(logs), "latest_attempt_id": latest_id}


@bp.post("/notification-delivery-attempts/<int:attempt_id>/retry")
@role_required("Admin")
def retry_delivery_attempt(attempt_id: int):
    row = NotificationDeliveryLog.query.get_or_404(attempt_id)
    result = _retry_or_replay(log_row=row, action="retry", guard_failures_only=True)
    _audit(
        "RETRY_NOTIFICATION_DELIVERY",
        row.id,
        old_values={"attempt_id": row.id, "status": _status_for(row)},
        new_values=result,
    )
    db.session.commit()
    return jsonify(result)


@bp.post("/notification-delivery-attempts/<int:attempt_id>/replay")
@role_required("Admin")
def replay_delivery_attempt(attempt_id: int):
    row = NotificationDeliveryLog.query.get_or_404(attempt_id)
    result = _retry_or_replay(log_row=row, action="replay", guard_failures_only=False)
    _audit(
        "REPLAY_NOTIFICATION_DELIVERY",
        row.id,
        old_values={"attempt_id": row.id, "status": _status_for(row)},
        new_values=result,
    )
    db.session.commit()
    return jsonify(result)

