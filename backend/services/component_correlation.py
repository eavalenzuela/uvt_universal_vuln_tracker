from __future__ import annotations

from typing import Any, Iterable, Mapping

from backend.database import db
from backend.models import SoftwareComponent, Vulnerability, VulnerabilityComponent


def correlate_vulnerability_to_components(
    vulnerability: Vulnerability,
    *,
    source: str,
    cve_id: str | None,
    raw_payload: Mapping[str, Any] | None = None,
) -> int:
    if not cve_id:
        return 0

    linked = 0
    components = SoftwareComponent.query.all()
    candidate_purls = _extract_candidate_purls(raw_payload)
    candidate_cpes = _extract_candidate_cpes(raw_payload)

    for component in components:
        match_type = None
        dependency_path = None
        depth = 0

        metadata = component.metadata_json or {}
        cves = metadata.get("cves") if isinstance(metadata, Mapping) else None
        if isinstance(cves, list) and cve_id in {str(item) for item in cves}:
            match_type = "sbom_cve"

        if match_type is None and component.purl and component.purl in candidate_purls:
            match_type = "purl"
        if match_type is None and component.cpe and component.cpe in candidate_cpes:
            match_type = "cpe"

        if match_type is None:
            continue

        path = metadata.get("dependency_path") if isinstance(metadata, Mapping) else None
        if isinstance(path, str):
            dependency_path = path
            depth = max(0, path.count(" > "))

        existing = VulnerabilityComponent.query.filter_by(
            vulnerability_id=vulnerability.id,
            component_id=component.id,
            source=source,
        ).first()
        if existing:
            existing.match_type = match_type
            existing.dependency_path = dependency_path
            existing.transitive_depth = depth
            continue

        db.session.add(VulnerabilityComponent(
            vulnerability_id=vulnerability.id,
            component_id=component.id,
            source=source,
            match_type=match_type,
            dependency_path=dependency_path,
            transitive_depth=depth,
        ))
        linked += 1
    return linked


def _extract_candidate_purls(payload: Mapping[str, Any] | None) -> set[str]:
    if not payload:
        return set()
    purls: set[str] = set()
    for item in _walk(payload):
        if isinstance(item, Mapping):
            value = item.get("purl")
            if isinstance(value, str) and value:
                purls.add(value)
    return purls


def _extract_candidate_cpes(payload: Mapping[str, Any] | None) -> set[str]:
    if not payload:
        return set()
    cpes: set[str] = set()
    for item in _walk(payload):
        if isinstance(item, Mapping):
            value = item.get("criteria") or item.get("cpe23Uri") or item.get("cpe")
            if isinstance(value, str) and value:
                cpes.add(value)
    return cpes


def _walk(value: Any) -> Iterable[Any]:
    if isinstance(value, Mapping):
        yield value
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)
