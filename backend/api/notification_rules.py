from __future__ import annotations

from flask import Blueprint, jsonify, request
from sqlalchemy import desc

from ..auth import role_required
from ..rate_limiter import rate_limit
from ..database import db
from ..models import NotificationDeliveryLog, NotificationRule, Vulnerability
from ..services.audit import record_audit as _audit
from ..services.notification_rules import NotificationEvent, trigger_notifications_for_event
from ..serializers.notification_rule_serializers import rule_json as _rule_json
from .validation import ValidationError, enum_value, error_response, paginate_query, parse_bool, parse_int, required_string

bp = Blueprint("notification_rules_api", __name__, url_prefix="/api")

VALID_ADAPTERS = {"slack", "jira", "webhook", "email"}
VALID_SEVERITIES = {"None", "Low", "Medium", "High", "Critical"}


@bp.get("/notification-rules")
@role_required("Admin")
def list_rules():
    query = NotificationRule.query.order_by(NotificationRule.id.desc())
    try:
        rows, meta = paginate_query(query)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    return jsonify({"items": [_rule_json(row) for row in rows], **meta})


@bp.post("/notification-rules")
@role_required("Admin")
def create_rule():
    data = request.get_json(silent=True) or {}
    try:
        name = required_string(data, "name")
        adapter = enum_value(data.get("delivery_adapter", "slack"), field="delivery_adapter", options=VALID_ADAPTERS)
        severity_threshold = enum_value(data.get("severity_threshold", "Medium"), field="severity_threshold", options=VALID_SEVERITIES)
        frequency_days = parse_int(data.get("frequency_days", 3), field="frequency_days", minimum=1, required=True)
        escalation_after_days = parse_int(data.get("escalation_after_days", 7), field="escalation_after_days", minimum=0, required=True)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    rule = NotificationRule(
        name=name,
        is_enabled=bool(data.get("is_enabled", True)),
        delivery_adapter=adapter,
        delivery_config=data.get("delivery_config") or {},
        severity_threshold=severity_threshold,
        notify_on_status_change=bool(data.get("notify_on_status_change", True)),
        notify_on_assignment_change=bool(data.get("notify_on_assignment_change", True)),
        product_scope=data.get("product_scope") or [],
        frequency_days=frequency_days,
        escalation_after_days=escalation_after_days,
        channels=data.get("channels") or [],
        recipients=data.get("recipients") or [],
        created_by=request.user.id,
    )
    db.session.add(rule)
    db.session.flush()

    _audit("CREATE", "notification_rules", rule.id, new_values=_rule_json(rule))
    db.session.commit()
    return jsonify(_rule_json(rule)), 201


@bp.put("/notification-rules/<int:rule_id>")
@role_required("Admin")
def update_rule(rule_id: int):
    rule = NotificationRule.query.get_or_404(rule_id)
    data = request.get_json(silent=True) or {}
    old = _rule_json(rule)

    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            return error_response("name cannot be empty", field="name")
        rule.name = name

    if "delivery_adapter" in data:
        adapter = data.get("delivery_adapter")
        if adapter not in VALID_ADAPTERS:
            return error_response(f"delivery_adapter must be one of {sorted(VALID_ADAPTERS)}", field="delivery_adapter", details={"allowed": sorted(VALID_ADAPTERS)})
        rule.delivery_adapter = adapter

    if "severity_threshold" in data:
        severity_threshold = data.get("severity_threshold")
        if severity_threshold not in VALID_SEVERITIES:
            return error_response(f"severity_threshold must be one of {sorted(VALID_SEVERITIES)}", field="severity_threshold", details={"allowed": sorted(VALID_SEVERITIES)})
        rule.severity_threshold = severity_threshold

    for field in ["is_enabled", "notify_on_status_change", "notify_on_assignment_change"]:
        if field in data:
            setattr(rule, field, bool(data.get(field)))


    if "frequency_days" in data:
        try:
            rule.frequency_days = parse_int(data.get("frequency_days") or 1, field="frequency_days", minimum=1, required=True)
        except ValidationError as exc:
            return error_response(exc.error, field=exc.field, details=exc.details)

    if "escalation_after_days" in data:
        try:
            rule.escalation_after_days = parse_int(data.get("escalation_after_days") or 0, field="escalation_after_days", minimum=0, required=True)
        except ValidationError as exc:
            return error_response(exc.error, field=exc.field, details=exc.details)

    if "channels" in data:
        channels = data.get("channels")
        if channels is None:
            channels = []
        if not isinstance(channels, list):
            return error_response("channels must be an array", field="channels")
        rule.channels = channels

    if "recipients" in data:
        recipients = data.get("recipients")
        if recipients is None:
            recipients = []
        if not isinstance(recipients, list):
            return error_response("recipients must be an array", field="recipients")
        rule.recipients = recipients

    if "delivery_config" in data:
        cfg = data.get("delivery_config")
        if cfg is not None and not isinstance(cfg, dict):
            return error_response("delivery_config must be an object", field="delivery_config")
        rule.delivery_config = cfg or {}

    if "product_scope" in data:
        scope = data.get("product_scope")
        if scope is None:
            scope = []
        if not isinstance(scope, list):
            return error_response("product_scope must be an array of product ids", field="product_scope")
        rule.product_scope = scope

    _audit("UPDATE", "notification_rules", rule.id, old_values=old, new_values=_rule_json(rule))
    db.session.commit()
    return jsonify(_rule_json(rule))


@bp.delete("/notification-rules/<int:rule_id>")
@role_required("Admin")
def delete_rule(rule_id: int):
    rule = NotificationRule.query.get_or_404(rule_id)
    old = _rule_json(rule)
    _audit("DELETE", "notification_rules", rule.id, old_values=old)
    db.session.delete(rule)
    db.session.commit()
    return jsonify({"ok": True})


@bp.post("/notification-rules/<int:rule_id>/test-send")
@role_required("Admin")
@rate_limit("RATE_LIMIT_SENSITIVE_LIMIT", "RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", identifier="notification_test_send")
def test_send(rule_id: int):
    rule = NotificationRule.query.get_or_404(rule_id)
    vuln = Vulnerability.query.order_by(desc(Vulnerability.updated_at)).first()
    if not vuln:
        return error_response("No vulnerabilities found to use for test-send", field="vulnerability_id")

    logs = trigger_notifications_for_event(
        NotificationEvent(
            event_type="test_send",
            vulnerability_id=vuln.id,
            actor_id=request.user.id,
            new_values={"test_send": True},
        ),
        dry_run_rule_id=rule.id,
    )
    db.session.commit()
    return jsonify({"ok": True, "sent": len(logs)})


@bp.get("/notification-delivery-logs")
@role_required("Admin")
def list_delivery_logs():
    try:
        limit = parse_int(request.args.get("limit", 100), field="limit", minimum=1, maximum=500, required=True)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)
    rows = NotificationDeliveryLog.query.order_by(NotificationDeliveryLog.id.desc()).limit(limit).all()
    return jsonify([
        {
            "id": row.id,
            "rule_id": row.rule_id,
            "vulnerability_id": row.vulnerability_id,
            "event_type": row.event_type,
            "delivery_adapter": row.delivery_adapter,
            "success": row.success,
            "response_payload": row.response_payload,
            "error_message": row.error_message,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ])
