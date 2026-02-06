from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Iterable

from flask import jsonify


@dataclass
class ValidationError(Exception):
    error: str
    field: str | None = None
    details: Any = None
    status_code: int = 400


def error_response(error: str, *, field: str | None = None, details: Any = None, status_code: int = 400):
    payload = {"error": error, "details": details, "field": field}
    return jsonify(payload), status_code


def invalid(field: str, error: str, *, details: Any = None) -> ValidationError:
    return ValidationError(error=error, field=field, details=details)


def required_string(data: dict[str, Any], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise invalid(field, f"{field} is required")
    return value.strip()


def optional_string(data: dict[str, Any], field: str) -> str | None:
    value = data.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise invalid(field, f"{field} must be a string")
    return value.strip()


def enum_value(value: Any, *, field: str, options: Iterable[str], required: bool = True) -> str | None:
    opts = set(options)
    if value is None or value == "":
        if required:
            raise invalid(field, f"{field} is required")
        return None
    if not isinstance(value, str):
        raise invalid(field, f"{field} must be one of {sorted(opts)}", details={"allowed": sorted(opts)})
    normalized = value.strip()
    if normalized not in opts:
        raise invalid(field, f"{field} must be one of {sorted(opts)}", details={"allowed": sorted(opts)})
    return normalized


def parse_iso_date(value: Any, *, field: str, required: bool = False) -> date | None:
    if value in (None, ""):
        if required:
            raise invalid(field, f"{field} is required")
        return None
    if not isinstance(value, str):
        raise invalid(field, f"{field} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise invalid(field, f"{field} must be an ISO date") from exc


def parse_int(value: Any, *, field: str, minimum: int | None = None, maximum: int | None = None, required: bool = False) -> int | None:
    if value in (None, ""):
        if required:
            raise invalid(field, f"{field} is required")
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise invalid(field, f"{field} must be an integer") from exc

    if minimum is not None and parsed < minimum:
        raise invalid(field, f"{field} must be >= {minimum}")
    if maximum is not None and parsed > maximum:
        raise invalid(field, f"{field} must be <= {maximum}")
    return parsed


def parse_bool(value: Any, *, field: str, required: bool = False) -> bool | None:
    if value is None:
        if required:
            raise invalid(field, f"{field} is required")
        return None
    if not isinstance(value, bool):
        raise invalid(field, f"{field} must be a boolean")
    return value
