from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from ..database import db
from ..models import (
    NotificationDeliveryLog,
    NotificationRule,
    PluginConfig,
    ProductVersion,
    Notification,
    User,
    Vulnerability,
    VulnerabilityVersion,
)
from .jira_sync import JiraApiError, JiraClient
from .slack_alerts import SlackWebhookClient, SlackWebhookError

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
        notifications.append(row)

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
    version_rows = VulnerabilityVersion.query.filter_by(vulnerability_id=vulnerability.id).all()
    if not version_rows:
        return False
    for mapping in version_rows:
        pv = ProductVersion.query.get(mapping.product_version_id)
        if pv and int(pv.product_id) in scoped_ids:
            return True
    return False


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

    client = JiraClient(base_url=base_url, api_token=api_token, user_email=config.get("user_email"))
    issue_key = client.create_issue(fields={
        "project": {"key": project_key},
        "summary": f"[{vulnerability.severity}] {vulnerability.title}",
        "description": text,
        "issuetype": {"name": config.get("issue_type", "Task")},
    })
    return {"issue_key": issue_key}


def _deliver(rule: NotificationRule, vulnerability: Vulnerability, event: NotificationEvent, dry_run: bool = False) -> tuple[bool, dict[str, Any] | None, str | None]:
    config = _merged_delivery_config(rule.delivery_adapter, rule.delivery_config)
    text = (
        f"UVT notification ({event.event_type}) for vulnerability #{vulnerability.id}: "
        f"{vulnerability.title} | severity={vulnerability.severity} | status={vulnerability.status}"
    )

    if dry_run:
        return True, {"dry_run": True, "message": text}, None

    try:
        if rule.delivery_adapter == "slack":
            payload = _slack_send(config, text)
        elif rule.delivery_adapter == "jira":
            payload = _jira_send(config, vulnerability, text)
        else:
            return False, None, f"Unsupported delivery_adapter '{rule.delivery_adapter}'"
        return True, payload, None
    except (SlackWebhookError, JiraApiError, ValueError, TypeError) as exc:
        return False, None, str(exc)


def trigger_notifications_for_event(event: NotificationEvent, *, dry_run_rule_id: int | None = None) -> list[NotificationDeliveryLog]:
    vulnerability = Vulnerability.query.get(event.vulnerability_id)
    if not vulnerability:
        return []

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
