from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any
from urllib import request as urllib_request
from urllib import error as urllib_error

from ..database import db
from ..models import (
    NotificationDeliveryCheckpoint,
    NotificationDeliveryLog,
    NotificationRule,
    PluginConfig,
    ProductVersion,
    Notification,
    User,
    UserPreferences,
    Vulnerability,
    VulnerabilityVersion,
    VulnerabilityWatcher,
)
from .jira_sync import JiraApiError, JiraClient
from .slack_alerts import SlackWebhookClient, SlackWebhookError
from .email_delivery import EmailDeliveryError, send_email
from .url_guard import UnsafeOutboundUrlError, safe_urlopen, validate_outbound_url
from ..live_notifications import publish_user_event

SEVERITY_ORDER = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

MENTION_PATTERN = re.compile(r"(?<!\w)@([A-Za-z0-9_.-]{1,100})")


def parse_mentions(text: str | None) -> set[str]:
    if not text:
        return set()
    return {match.group(1) for match in MENTION_PATTERN.finditer(text)}


def trigger_mention_notifications(*, vulnerability_id: int, actor_id: int | None, comment_id: int, comment_text: str) -> list[Notification]:
    mentioned_usernames = parse_mentions(comment_text)
    if not mentioned_usernames:
        return []

    users = User.query.filter(User.username.in_(mentioned_usernames), User.is_active.is_(True)).all()
    notifications: list[Notification] = []
    for user in users:
        if actor_id is not None and user.id == actor_id:
            continue
        row = Notification(
            user_id=user.id,
            vulnerability_id=vulnerability_id,
            message=(
                f"You were mentioned by user #{actor_id} in vulnerability #{vulnerability_id} "
                f"comment #{comment_id}."
            ),
        )
        db.session.add(row)
        db.session.flush()
        notifications.append(row)
        publish_user_event(
            user_id=user.id,
            event_type="mention_notification_created",
            payload={
                "notification": {
                    "id": row.id,
                    "user_id": user.id,
                    "vulnerability_id": vulnerability_id,
                    "message": row.message,
                    "is_read": False,
                    "comment_id": comment_id,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
            },
        )

    return notifications


@dataclass
class NotificationEvent:
    event_type: str
    vulnerability_id: int
    actor_id: int | None
    old_values: dict[str, Any] | None = None
    new_values: dict[str, Any] | None = None
    status_changed: bool = False
    assignment_changed: bool = False


def _severity_value(severity: str | None) -> int:
    if not severity:
        return 0
    return SEVERITY_ORDER.get(severity, 0)


def _plugin_config(plugin_id: str) -> dict[str, Any]:
    row = PluginConfig.query.filter_by(plugin_id=plugin_id).first()
    if not row or not row.config_json:
        return {}
    return dict(row.config_json)


def _merged_delivery_config(adapter: str, config: dict[str, Any] | None) -> dict[str, Any]:
    merged = _plugin_config(adapter)
    merged.update(config or {})
    return merged


def _passes_product_scope(rule: NotificationRule, vulnerability: Vulnerability) -> bool:
    scope = rule.product_scope or []
    if not scope:
        return True
    scoped_ids = {int(pid) for pid in scope}
    match = (
        db.session.query(VulnerabilityVersion.id)
        .join(ProductVersion, VulnerabilityVersion.product_version_id == ProductVersion.id)
        .filter(
            VulnerabilityVersion.vulnerability_id == vulnerability.id,
            ProductVersion.product_id.in_(scoped_ids),
        )
        .first()
    )
    return match is not None


def _event_allowed(rule: NotificationRule, event: NotificationEvent) -> bool:
    if event.event_type == "status_change" and not rule.notify_on_status_change:
        return False
    if event.event_type == "assignment_change" and not rule.notify_on_assignment_change:
        return False
    return True


def _slack_send(config: dict[str, Any], text: str) -> dict[str, Any]:
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        raise SlackWebhookError("Missing webhook_url")
    try:
        validate_outbound_url(webhook_url, purpose="Slack webhook")
    except UnsafeOutboundUrlError as exc:
        raise SlackWebhookError(str(exc)) from exc
    client = SlackWebhookClient(webhook_url)
    response = client.send_message(
        text=text,
        channel=config.get("channel") or config.get("default_channel"),
        username=config.get("username"),
        icon_emoji=config.get("icon_emoji"),
    )
    return {"status": response.status, "body": response.body}


def _jira_send(config: dict[str, Any], vulnerability: Vulnerability, text: str) -> dict[str, Any]:
    base_url = config.get("base_url")
    api_token = config.get("api_token")
    project_key = config.get("project_key")
    if not base_url or not api_token or not project_key:
        raise JiraApiError("Missing Jira configuration (base_url, api_token, project_key)")
    try:
        validate_outbound_url(base_url, purpose="Jira base")
    except UnsafeOutboundUrlError as exc:
        raise JiraApiError(str(exc)) from exc

    client = JiraClient(base_url=base_url, api_token=api_token, user_email=config.get("user_email"))
    issue_key = client.create_issue(fields={
        "project": {"key": project_key},
        "summary": f"[{vulnerability.severity}] {vulnerability.title}",
        "description": text,
        "issuetype": {"name": config.get("issue_type", "Task")},
    })
    return {"issue_key": issue_key}


def _webhook_send(config: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        raise ValueError("Missing webhook_url")
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    req = urllib_request.Request(webhook_url, data=body, method="POST")
    req.add_header("Content-Type", "application/json; charset=utf-8")
    try:
        # safe_urlopen re-validates after DNS resolution and refuses redirects,
        # so neither a rebound hostname nor a 302 can steer this at an
        # internal address.
        with safe_urlopen(req, timeout=10, purpose="notification webhook") as resp:
            return {"status": resp.status}
    except UnsafeOutboundUrlError:
        raise
    except urllib_error.URLError as exc:
        raise ValueError(f"webhook request failed: {exc}") from exc


def _email_send(config: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    text = str(payload.get("text") or "")
    vuln_id = payload.get("vulnerability_id")
    event_type = payload.get("event_type")
    recipients = config.get("recipients")
    if isinstance(recipients, str):
        recipients = [item.strip() for item in recipients.split(",") if item.strip()]
    recipients = recipients or ([config.get("recipient")] if config.get("recipient") else [])
    if not recipients:
        raise EmailDeliveryError("invalid_recipient", "Email delivery requires recipient or recipients in config")

    results = []
    for recipient in recipients:
        subject = f"UVT notification: vulnerability #{vuln_id} ({event_type})"
        body = f"{text}\n\nEvent: {event_type}\nVulnerability ID: {vuln_id}"
        results.append(
            send_email(
                recipient=str(recipient),
                subject=subject,
                body_text=body,
                config_overrides=config,
                plugin_id="email",
            )
        )
    return {"channel": "email", "deliveries": results, "count": len(results)}


def _deliver(rule: NotificationRule, vulnerability: Vulnerability, event: NotificationEvent, dry_run: bool = False) -> tuple[bool, dict[str, Any] | None, str | None]:
    config = _merged_delivery_config(rule.delivery_adapter, rule.delivery_config)
    text = (
        f"UVT notification ({event.event_type}) for vulnerability #{vulnerability.id}: "
        f"{vulnerability.title} | severity={vulnerability.severity} | status={vulnerability.status}"
    )

    if dry_run:
        return True, {"dry_run": True, "message": text, "event_context": event.new_values or {}}, None

    try:
        if rule.delivery_adapter == "slack":
            payload = _slack_send(config, text)
        elif rule.delivery_adapter == "jira":
            payload = _jira_send(config, vulnerability, text)
        elif rule.delivery_adapter == "webhook":
            payload = _webhook_send(config, {"text": text, "vulnerability_id": vulnerability.id, "event_type": event.event_type})
        elif rule.delivery_adapter == "email":
            payload = _email_send(config, {"text": text, "vulnerability_id": vulnerability.id, "event_type": event.event_type})
        else:
            return False, None, f"Unsupported delivery_adapter '{rule.delivery_adapter}'"
        return True, payload, None
    except EmailDeliveryError as exc:
        return False, exc.as_dict(), exc.message
    except (SlackWebhookError, JiraApiError, ValueError, TypeError) as exc:
        return False, None, str(exc)


def _escalation_step(rule: NotificationRule, vulnerability: Vulnerability) -> int:
    if not vulnerability.sla_due_at:
        return 0
    escalation_after_days = max(int(rule.escalation_after_days or 0), 0)
    if escalation_after_days <= 0:
        return 1
    overdue_days = (datetime.now(timezone.utc) - vulnerability.sla_due_at).days
    if overdue_days < escalation_after_days:
        return 0
    return (overdue_days // escalation_after_days) + 1


def _resolve_targets(rule: NotificationRule, step: int) -> tuple[list[str], list[str]]:
    channels = list(rule.channels or [])
    recipients = list(rule.recipients or [])
    if step > 0:
        escalation_cfg = (rule.delivery_config or {}).get("escalation") or {}
        channels = list(escalation_cfg.get("channels") or channels)
        recipients = list(escalation_cfg.get("recipients") or recipients)
    return channels, recipients


def _publish_rule_trigger_event(event: NotificationEvent, vulnerability: Vulnerability) -> None:
    if not (event.status_changed or event.assignment_changed):
        return
    user_ids = {vulnerability.created_by}
    if vulnerability.assigned_to:
        user_ids.add(vulnerability.assigned_to)
    if event.actor_id:
        user_ids.add(event.actor_id)

    payload = {
        "event_type": event.event_type,
        "vulnerability_id": vulnerability.id,
        "title": vulnerability.title,
        "status": vulnerability.status,
        "severity": vulnerability.severity,
        "status_changed": bool(event.status_changed),
        "assignment_changed": bool(event.assignment_changed),
    }
    for user_id in user_ids:
        if user_id is None:
            continue
        publish_user_event(user_id=user_id, event_type="rule_triggered", payload=payload)


_WATCHER_EVENT_TYPES = {"updated", "status_change", "assignment_change", "version_link_change"}


def notify_watchers_for_event(event: NotificationEvent, vulnerability: Vulnerability) -> list[Notification]:
    """Create in-app notifications for watchers of an updated vulnerability.

    Watchers opted out via the ``notify_on_watched_vuln_update`` preference are
    skipped (a missing preferences row means "use defaults" = opted in), as is
    the acting user.
    """
    if event.event_type not in _WATCHER_EVENT_TYPES:
        return []

    rows = (
        db.session.query(VulnerabilityWatcher, User, UserPreferences)
        .join(User, VulnerabilityWatcher.user_id == User.id)
        .outerjoin(UserPreferences, UserPreferences.user_id == User.id)
        .filter(
            VulnerabilityWatcher.vulnerability_id == vulnerability.id,
            User.is_active.is_(True),
        )
        .all()
    )

    notifications: list[Notification] = []
    for _watcher, user, prefs in rows:
        if event.actor_id is not None and user.id == event.actor_id:
            continue
        if prefs is not None and not prefs.notify_on_watched_vuln_update:
            continue

        if event.event_type == "status_change":
            detail = f"status changed to {vulnerability.status}"
        elif event.event_type == "assignment_change":
            detail = "assignment changed"
        else:
            detail = "was updated"
        row = Notification(
            user_id=user.id,
            vulnerability_id=vulnerability.id,
            message=f"Watched vulnerability #{vulnerability.id} ({vulnerability.title}) {detail}.",
        )
        db.session.add(row)
        db.session.flush()
        notifications.append(row)
        publish_user_event(
            user_id=user.id,
            event_type="watched_vulnerability_updated",
            payload={
                "notification": {
                    "id": row.id,
                    "user_id": user.id,
                    "vulnerability_id": vulnerability.id,
                    "message": row.message,
                    "is_read": False,
                    "event_type": event.event_type,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
            },
        )

    return notifications


def trigger_notifications_for_event(event: NotificationEvent, *, dry_run_rule_id: int | None = None) -> list[NotificationDeliveryLog]:
    vulnerability = db.session.get(Vulnerability, event.vulnerability_id)
    if not vulnerability:
        return []

    _publish_rule_trigger_event(event, vulnerability)

    if dry_run_rule_id is None:
        notify_watchers_for_event(event, vulnerability)

    query = NotificationRule.query.filter_by(is_enabled=True)
    if dry_run_rule_id is not None:
        query = NotificationRule.query.filter_by(id=dry_run_rule_id)

    rules = query.all()
    logs: list[NotificationDeliveryLog] = []

    for rule in rules:
        if _severity_value(vulnerability.severity) < _severity_value(rule.severity_threshold):
            continue
        if not _passes_product_scope(rule, vulnerability):
            continue
        if not _event_allowed(rule, event):
            continue

        success, response_payload, error_message = _deliver(
            rule,
            vulnerability,
            event,
            dry_run=dry_run_rule_id is not None,
        )
        log_row = NotificationDeliveryLog(
            rule_id=rule.id,
            vulnerability_id=vulnerability.id,
            event_type=event.event_type,
            delivery_adapter=rule.delivery_adapter,
            success=success,
            response_payload=response_payload,
            error_message=error_message,
        )
        db.session.add(log_row)
        logs.append(log_row)

    return logs


def run_scheduled_notification_scan(now: datetime | None = None, *, dry_run: bool = False) -> list[NotificationDeliveryLog]:
    now = now or datetime.now(timezone.utc)
    rules = NotificationRule.query.filter_by(is_enabled=True).all()
    vulnerabilities = Vulnerability.query.filter(
        Vulnerability.status.in_(["Open", "In Progress"]),
    ).all()

    logs: list[NotificationDeliveryLog] = []

    for rule in rules:
        frequency_days = max(int(rule.frequency_days or 1), 1)
        for vulnerability in vulnerabilities:
            if _severity_value(vulnerability.severity) < _severity_value(rule.severity_threshold):
                continue
            if not _passes_product_scope(rule, vulnerability):
                continue

            overdue = vulnerability.sla_due_at is not None and vulnerability.sla_due_at <= now
            high_risk = _severity_value(vulnerability.severity) >= _severity_value("High")
            if not (overdue or high_risk):
                continue

            checkpoint = NotificationDeliveryCheckpoint.query.filter_by(
                rule_id=rule.id,
                vulnerability_id=vulnerability.id,
            ).first()
            if checkpoint and checkpoint.last_notified_at and (now - checkpoint.last_notified_at) < timedelta(days=frequency_days):
                continue

            step = _escalation_step(rule, vulnerability)
            channels, recipients = _resolve_targets(rule, step)
            event = NotificationEvent(
                event_type="scheduled_scan",
                vulnerability_id=vulnerability.id,
                actor_id=None,
                new_values={
                    "overdue": overdue,
                    "high_risk": high_risk,
                    "escalation_step": step,
                    "channels": channels,
                    "recipients": recipients,
                },
            )
            success, response_payload, error_message = _deliver(rule, vulnerability, event, dry_run=dry_run)
            log_row = NotificationDeliveryLog(
                rule_id=rule.id,
                vulnerability_id=vulnerability.id,
                event_type="scheduled_scan",
                delivery_adapter=rule.delivery_adapter,
                success=success,
                response_payload=response_payload,
                error_message=error_message,
            )
            db.session.add(log_row)
            logs.append(log_row)

            if not success:
                # Delivery failed — do not advance the checkpoint, otherwise this
                # rule+vuln is treated as "already notified" for the whole
                # frequency window and the alert is silently dropped on transient
                # errors. Leaving the checkpoint untouched lets the next scan retry.
                # (In dry-run mode _deliver reports success, so checkpoint
                # bookkeeping is exercised as before.)
                continue

            if step > 0:
                user_ids = {vulnerability.created_by}
                if vulnerability.assigned_to:
                    user_ids.add(vulnerability.assigned_to)
                for user_id in user_ids:
                    if user_id is None:
                        continue
                    publish_user_event(
                        user_id=user_id,
                        event_type="scheduled_scan_escalation_logged",
                        payload={
                            "vulnerability_id": vulnerability.id,
                            "title": vulnerability.title,
                            "severity": vulnerability.severity,
                            "status": vulnerability.status,
                            "escalation_step": step,
                            "rule_id": rule.id,
                        },
                    )

            if checkpoint is None:
                checkpoint = NotificationDeliveryCheckpoint(
                    rule_id=rule.id,
                    vulnerability_id=vulnerability.id,
                )
                db.session.add(checkpoint)
            checkpoint.last_notified_at = now
            checkpoint.last_escalation_step = step
            checkpoint.last_event_type = "scheduled_scan"

    return logs
