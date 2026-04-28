from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime
from typing import Any, Mapping

from backend.database import db
from backend.api.validation import normalize_cve_id
from backend.models import Vulnerability, VulnerabilitySource
from backend.services.component_correlation import correlate_vulnerability_to_components


@dataclass(frozen=True)
class NormalizedVuln:
    cve_id: str | None
    title: str
    description: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    published_date: date | None = None
    last_modified_date: date | None = None
    raw_payload: Mapping[str, Any] | None = None


def upsert_vulnerability(
    normalized: NormalizedVuln,
    *,
    source: str | None = None,
    source_id: str | None = None,
    team_id: int | None = None,
) -> Vulnerability:
    """Upsert a normalized vuln.

    F15: ``team_id`` is applied ONLY when the vuln row is first created. Once a
    vuln exists in the DB its ``team_id`` is immutable through ingest paths —
    shared-pool vulns (NULL) stay shared even if a later product linkage would
    otherwise suggest promotion. See docs/plans/done/F15-team-acl.md §6.
    """
    vulnerability = _upsert_vulnerability_no_commit(
        normalized,
        source=source,
        source_id=source_id,
        team_id=team_id,
    )

    db.session.commit()
    return vulnerability


def _upsert_vulnerability_no_commit(
    normalized: NormalizedVuln,
    *,
    source: str | None = None,
    source_id: str | None = None,
    team_id: int | None = None,
) -> Vulnerability:
    normalized = replace(
        normalized,
        cve_id=normalize_cve_id(normalized.cve_id, required=False),
    )

    vulnerability = _find_existing(normalized)

    if vulnerability is None:
        vulnerability = Vulnerability(
            cve_id=normalized.cve_id,
            title=normalized.title,
            team_id=team_id,
        )
        db.session.add(vulnerability)

    _apply_normalized(vulnerability, normalized)

    if source:
        _upsert_source(vulnerability, source, source_id, normalized.raw_payload)

    if source and normalized.cve_id:
        correlate_vulnerability_to_components(
            vulnerability,
            source=source,
            cve_id=normalized.cve_id,
            raw_payload=normalized.raw_payload,
        )
    return vulnerability


def upsert_vulnerabilities(
    normalized_items: list[NormalizedVuln],
    *,
    source: str | None = None,
    team_id: int | None = None,
) -> list[Vulnerability]:
    results: list[Vulnerability] = []
    try:
        for normalized in normalized_items:
            results.append(
                _upsert_vulnerability_no_commit(
                    normalized,
                    source=source,
                    source_id=_extract_source_id(normalized),
                    team_id=team_id,
                )
            )

        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    return results


def _find_existing(normalized: NormalizedVuln) -> Vulnerability | None:
    vulnerability = None
    if normalized.cve_id:
        vulnerability = Vulnerability.query.filter_by(cve_id=normalized.cve_id).first()
    if vulnerability is None and normalized.title:
        vulnerability = Vulnerability.query.filter_by(title=normalized.title).first()
    return vulnerability


def _apply_normalized(vulnerability: Vulnerability, normalized: NormalizedVuln) -> None:
    vulnerability.title = normalized.title or vulnerability.title
    if normalized.cve_id:
        vulnerability.cve_id = normalized.cve_id
    if normalized.description is not None:
        vulnerability.description = normalized.description
    if normalized.severity is not None:
        vulnerability.severity = normalized.severity
    if normalized.cvss_score is not None:
        vulnerability.cvss_score = normalized.cvss_score
    if normalized.published_date is not None:
        vulnerability.published_date = normalized.published_date
    if normalized.last_modified_date is not None:
        vulnerability.last_modified_date = normalized.last_modified_date


def _upsert_source(
    vulnerability: Vulnerability,
    source: str,
    source_id: str | None,
    raw_payload: Mapping[str, Any] | None,
) -> None:
    query = VulnerabilitySource.query.filter_by(
        vulnerability_id=vulnerability.id,
        source=source,
        source_id=source_id,
    )
    existing = query.first()
    if existing is None:
        existing = VulnerabilitySource(
            vulnerability=vulnerability,
            source=source,
            source_id=source_id,
        )
        db.session.add(existing)

    if raw_payload is not None:
        existing.raw_json = dict(raw_payload)


def _extract_source_id(normalized: NormalizedVuln) -> str | None:
    if normalized.cve_id:
        return normalized.cve_id
    if normalized.raw_payload:
        for key in ("id", "source_id", "sourceId"):
            value = normalized.raw_payload.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def parse_date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized).date()
        except ValueError:
            return None
    return None
