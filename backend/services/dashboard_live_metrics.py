from __future__ import annotations

from typing import Any

from ..live_notifications import publish_user_event
from ..models import User, Vulnerability


RESOLVED_STATUSES = {"Resolved", "Closed"}


def publish_vulnerability_metric_event(*, vulnerability: Vulnerability, action: str, previous: dict[str, Any] | None = None) -> None:
    payload = {
        "action": action,
        "vulnerability_id": vulnerability.id,
        "status": vulnerability.status,
        "severity": vulnerability.severity,
        "updated_at": vulnerability.updated_at.isoformat() if vulnerability.updated_at else None,
        "previous_status": (previous or {}).get("status"),
        "previous_severity": (previous or {}).get("severity"),
    }
    user_ids = [row[0] for row in User.query.with_entities(User.id).filter(User.is_active.is_(True)).all()]
    for user_id in user_ids:
        publish_user_event(user_id=user_id, event_type="dashboard_metric_change", payload=payload)


def classify_vulnerability_metric_action(*, previous_status: str | None, current_status: str | None) -> str:
    if previous_status and previous_status not in RESOLVED_STATUSES and current_status in RESOLVED_STATUSES:
        return "resolved"
    return "updated"
