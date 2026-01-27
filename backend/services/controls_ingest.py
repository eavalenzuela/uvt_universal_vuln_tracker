from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from backend.database import db
from backend.models import Control, ControlSource


@dataclass(frozen=True)
class NormalizedControl:
    framework: str
    control_id: str
    title: str
    description: str | None = None
    version: str | None = None
    source_url: str | None = None
    raw_payload: Mapping[str, Any] | None = None


def upsert_control(
    normalized: NormalizedControl,
    *,
    source: str | None = None,
) -> Control:
    control = _find_existing(normalized, source)

    if control is None:
        control = Control(
            framework=normalized.framework,
            name=_control_name(normalized),
        )
        db.session.add(control)

    _apply_normalized(control, normalized)

    if source:
        _upsert_source(control, source, normalized)

    db.session.commit()
    return control


def upsert_controls(
    normalized_items: list[NormalizedControl],
    *,
    source: str | None = None,
) -> list[Control]:
    results: list[Control] = []
    for normalized in normalized_items:
        results.append(upsert_control(normalized, source=source))
    return results


def _find_existing(normalized: NormalizedControl, source: str | None) -> Control | None:
    if source and normalized.control_id:
        source_match = ControlSource.query.filter_by(
            source=source,
            source_control_id=normalized.control_id,
        ).first()
        if source_match:
            return source_match.control

    query = Control.query.filter_by(framework=normalized.framework)
    if normalized.title:
        return query.filter_by(name=normalized.title).first()
    return None


def _apply_normalized(control: Control, normalized: NormalizedControl) -> None:
    control.framework = normalized.framework or control.framework
    if normalized.title:
        control.name = normalized.title
    elif normalized.control_id:
        control.name = normalized.control_id
    if normalized.description is not None:
        control.description = normalized.description


def _upsert_source(
    control: Control,
    source: str,
    normalized: NormalizedControl,
) -> None:
    query = ControlSource.query.filter_by(
        control_id=control.id,
        source=source,
        source_control_id=normalized.control_id,
        version=normalized.version,
    )
    existing = query.first()
    if existing is None:
        existing = ControlSource(
            control=control,
            source=source,
            source_control_id=normalized.control_id,
            version=normalized.version,
        )
        db.session.add(existing)

    if normalized.source_url is not None:
        existing.source_url = normalized.source_url
    if normalized.raw_payload is not None:
        existing.raw_json = dict(normalized.raw_payload)


def _control_name(normalized: NormalizedControl) -> str:
    if normalized.title:
        return normalized.title
    return normalized.control_id
