from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import re
from typing import Any, Callable, Iterable

from flask import jsonify, request


_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass
class ValidationError(Exception):
    error: str
    field: str | None = None
    details: Any = None
    status_code: int = 400


def error_response(error: str, *, field: str | None = None, details: Any = None, status_code: int = 400):
    payload = {"error": error, "field": field, "details": details}
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


def normalize_cve_id(value: Any, *, field: str = "cve_id", required: bool = False) -> str | None:
    if value in (None, ""):
        if required:
            raise invalid(field, f"{field} is required")
        return None
    if not isinstance(value, str):
        raise invalid(field, f"{field} must be a string")

    normalized = value.strip().upper()
    if not _CVE_ID_RE.fullmatch(normalized):
        raise invalid(field, f"{field} must match CVE-YYYY-NNNN format")
    return normalized


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


def parse_query_bool(value: Any, *, field: str, required: bool = False) -> bool | None:
    if value in (None, ""):
        if required:
            raise invalid(field, f"{field} is required")
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    raise invalid(field, f"{field} must be a boolean", details={"accepted": ["true", "false"]})


def parse_float(value: Any, *, field: str, minimum: float | None = None, maximum: float | None = None, required: bool = False) -> float | None:
    if value in (None, ""):
        if required:
            raise invalid(field, f"{field} is required")
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise invalid(field, f"{field} must be a number") from exc

    if minimum is not None and parsed < minimum:
        raise invalid(field, f"{field} must be >= {minimum}")
    if maximum is not None and parsed > maximum:
        raise invalid(field, f"{field} must be <= {maximum}")
    return parsed


@dataclass(frozen=True)
class FieldSchema:
    parser: Callable[[Any], Any]
    required: bool = False
    default: Any = None


def schema_field(parser: Callable[[Any], Any], *, required: bool = False, default: Any = None) -> FieldSchema:
    return FieldSchema(parser=parser, required=required, default=default)


def validate_schema(data: dict[str, Any], schema: dict[str, FieldSchema]) -> dict[str, Any]:
    validated: dict[str, Any] = {}
    for field, config in schema.items():
        raw_value = data.get(field)
        if raw_value in (None, ""):
            if config.required:
                raise invalid(field, f"{field} is required")
            validated[field] = config.default
            continue
        validated[field] = config.parser(raw_value)
    return validated


DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def paginate_query(query, *, default_per_page: int = DEFAULT_PAGE_SIZE, max_per_page: int = MAX_PAGE_SIZE):
    """Apply pagination to a SQLAlchemy query using ?page=&per_page= query params.

    Returns (items, meta) where meta is a dict with pagination info.
    """
    page = parse_int(request.args.get("page", 1), field="page", minimum=1, required=True)
    per_page = parse_int(request.args.get("per_page", default_per_page), field="per_page", minimum=1, maximum=max_per_page, required=True)

    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()

    return items, {
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": (total + per_page - 1) // per_page if per_page else 0,
    }
