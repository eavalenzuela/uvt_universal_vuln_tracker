"""Normalize inbound webhook payloads into vulnerability records.

Each source type (generic, GitHub/Dependabot, Trivy, etc.) has its own parser
that yields ``NormalizedVuln`` instances; the shared upsert path in
``vuln_ingest`` handles dedup and persistence.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Iterable, Mapping

from backend.services.vuln_ingest import NormalizedVuln, upsert_vulnerability


class WebhookPayloadError(ValueError):
    pass


_SEVERITY_ALIASES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "info": "None",
    "informational": "None",
    "none": "None",
    "unknown": "Medium",
}


def _normalize_severity(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    return _SEVERITY_ALIASES.get(raw.strip().lower())


def _parse_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _generic_entries(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    vulns = payload.get("vulnerabilities")
    if isinstance(vulns, list):
        return [v for v in vulns if isinstance(v, Mapping)]
    if isinstance(payload.get("cve_id"), str) or isinstance(payload.get("title"), str):
        return [dict(payload)]
    raise WebhookPayloadError("payload must contain a 'vulnerabilities' array or a single vuln object")


def _parse_generic(payload: Mapping[str, Any]) -> Iterable[NormalizedVuln]:
    for entry in _generic_entries(payload):
        title = entry.get("title") or entry.get("summary") or entry.get("cve_id")
        if not isinstance(title, str) or not title.strip():
            continue
        cvss = entry.get("cvss_score")
        yield NormalizedVuln(
            cve_id=entry.get("cve_id") if isinstance(entry.get("cve_id"), str) else None,
            title=title.strip(),
            description=entry.get("description") if isinstance(entry.get("description"), str) else None,
            severity=_normalize_severity(entry.get("severity")),
            cvss_score=float(cvss) if isinstance(cvss, (int, float)) else None,
            published_date=_parse_date(entry.get("published_date") or entry.get("published_at")),
            last_modified_date=_parse_date(entry.get("last_modified_date") or entry.get("modified_at")),
            raw_payload=entry,
        )


def _parse_github(payload: Mapping[str, Any]) -> Iterable[NormalizedVuln]:
    alert = payload.get("alert") if isinstance(payload.get("alert"), Mapping) else payload
    advisory = alert.get("security_advisory") if isinstance(alert.get("security_advisory"), Mapping) else {}
    vuln_meta = alert.get("security_vulnerability") if isinstance(alert.get("security_vulnerability"), Mapping) else {}

    cve_id = None
    for item in advisory.get("identifiers") or []:
        if isinstance(item, Mapping) and item.get("type") == "CVE":
            cve_id = item.get("value")
            break

    title = advisory.get("summary") or advisory.get("ghsa_id") or cve_id
    if not isinstance(title, str) or not title.strip():
        return

    severity = _normalize_severity(vuln_meta.get("severity") or advisory.get("severity"))
    cvss = advisory.get("cvss") if isinstance(advisory.get("cvss"), Mapping) else {}
    cvss_score = cvss.get("score") if isinstance(cvss.get("score"), (int, float)) else None

    yield NormalizedVuln(
        cve_id=cve_id if isinstance(cve_id, str) else None,
        title=title.strip(),
        description=advisory.get("description") if isinstance(advisory.get("description"), str) else None,
        severity=severity,
        cvss_score=float(cvss_score) if cvss_score is not None else None,
        published_date=_parse_date(advisory.get("published_at")),
        last_modified_date=_parse_date(advisory.get("updated_at")),
        raw_payload=payload,
    )


def _parse_trivy(payload: Mapping[str, Any]) -> Iterable[NormalizedVuln]:
    results = payload.get("Results") or payload.get("results")
    if not isinstance(results, list):
        raise WebhookPayloadError("Trivy payload must contain a 'Results' array")
    for result in results:
        if not isinstance(result, Mapping):
            continue
        for v in result.get("Vulnerabilities") or []:
            if not isinstance(v, Mapping):
                continue
            title = v.get("Title") or v.get("VulnerabilityID")
            if not isinstance(title, str) or not title.strip():
                continue
            cvss_obj = v.get("CVSS") if isinstance(v.get("CVSS"), Mapping) else {}
            cvss_score = None
            for vendor in cvss_obj.values():
                if isinstance(vendor, Mapping):
                    score = vendor.get("V3Score") or vendor.get("V2Score")
                    if isinstance(score, (int, float)):
                        cvss_score = float(score)
                        break
            yield NormalizedVuln(
                cve_id=v.get("VulnerabilityID") if isinstance(v.get("VulnerabilityID"), str) else None,
                title=title.strip(),
                description=v.get("Description") if isinstance(v.get("Description"), str) else None,
                severity=_normalize_severity(v.get("Severity")),
                cvss_score=cvss_score,
                published_date=_parse_date(v.get("PublishedDate")),
                last_modified_date=_parse_date(v.get("LastModifiedDate")),
                raw_payload=v,
            )


PARSERS = {
    "generic": _parse_generic,
    "github": _parse_github,
    "dependabot": _parse_github,
    "trivy": _parse_trivy,
}


def ingest_webhook_payload(
    *,
    source_type: str,
    payload: Mapping[str, Any],
    source_label: str,
    team_id: int | None = None,
) -> int:
    """Parse payload by source_type and upsert vulns. Returns count.

    ``team_id`` is the stamp applied to any NEW vulns created — typically the
    owning WebhookEndpoint's team. NULL means shared-pool.
    """
    parser = PARSERS.get(source_type)
    if parser is None:
        raise WebhookPayloadError(f"unsupported source_type: {source_type}")

    ingested = 0
    for normalized in parser(payload):
        upsert_vulnerability(normalized, source=source_label, team_id=team_id)
        ingested += 1
    return ingested
