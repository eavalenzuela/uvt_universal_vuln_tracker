from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
import re
from typing import Any

from sqlalchemy.inspection import inspect

from ..models import AuditLog

_MAX_STRING_LENGTH = 300
_MAX_COLLECTION_ITEMS = 20
_MAX_DEPTH = 4
_SECRET_KEY_RE = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|webhook|credential|private[_-]?key|auth)",
    re.IGNORECASE,
)


def _is_secret_key(key: str | None) -> bool:
    return bool(key and _SECRET_KEY_RE.search(key))


def _compact_scalar(value: Any):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, str):
        if len(value) <= _MAX_STRING_LENGTH:
            return value
        return f"{value[:_MAX_STRING_LENGTH]}…(truncated)"
    return value


def scrub_snapshot(value: Any, *, key: str | None = None, depth: int = 0):
    if _is_secret_key(key):
        return "***"

    if depth >= _MAX_DEPTH:
        return "…"

    if isinstance(value, dict):
        items = list(value.items())[:_MAX_COLLECTION_ITEMS]
        payload = {k: scrub_snapshot(v, key=str(k), depth=depth + 1) for k, v in items}
        if len(value) > _MAX_COLLECTION_ITEMS:
            payload["_truncated"] = len(value) - _MAX_COLLECTION_ITEMS
        return payload

    if isinstance(value, (list, tuple, set)):
        values = list(value)
        payload = [scrub_snapshot(v, depth=depth + 1) for v in values[:_MAX_COLLECTION_ITEMS]]
        if len(values) > _MAX_COLLECTION_ITEMS:
            payload.append(f"…(+{len(values) - _MAX_COLLECTION_ITEMS} more)")
        return payload

    return _compact_scalar(value)


def model_snapshot(instance: Any) -> dict[str, Any]:
    mapper = inspect(instance.__class__)
    return {column.key: scrub_snapshot(getattr(instance, column.key)) for column in mapper.columns}


def build_field_diff(
    old_values: dict[str, Any] | None,
    new_values: dict[str, Any] | None,
    tracked_fields: list[str] | tuple[str, ...],
) -> dict[str, dict[str, Any]]:
    old_values = old_values or {}
    new_values = new_values or {}
    field_diff: dict[str, dict[str, Any]] = {}

    for field in tracked_fields:
        before = old_values.get(field)
        after = new_values.get(field)
        if before == after:
            continue
        field_diff[field] = {
            "before": before,
            "after": after,
        }

    return field_diff


def log_audit_event(
    *,
    actor_id: int | None,
    action: str,
    resource: str,
    record_id: int | None,
    old_values: dict[str, Any] | None = None,
    new_values: dict[str, Any] | None = None,
):
    db_row = AuditLog(
        user_id=actor_id,
        action=action,
        table_name=resource,
        record_id=record_id,
        old_values=scrub_snapshot(old_values) if old_values is not None else None,
        new_values=scrub_snapshot(new_values) if new_values is not None else None,
    )
    return db_row
