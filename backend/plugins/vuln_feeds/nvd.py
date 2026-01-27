from __future__ import annotations

from datetime import date, datetime
from typing import Any, Mapping

from backend.services.vuln_ingest import NormalizedVuln, parse_date


def map_nvd_record(payload: Mapping[str, Any]) -> NormalizedVuln:
    cve = payload.get("cve") or {}
    cve_id = _get_first_str(cve, "id") or _get_first_str(payload, "cve_id", "cveId")
    description = _extract_description(cve) or _get_first_str(payload, "description", "summary")
    title = _get_first_str(cve, "title") or cve_id or _get_first_str(payload, "title") or "NVD Vulnerability"
    severity, score = _extract_severity_and_score(payload)
    published = parse_date(payload.get("published") or payload.get("publishedDate"))
    last_modified = parse_date(payload.get("lastModified") or payload.get("lastModifiedDate"))

    return NormalizedVuln(
        cve_id=cve_id,
        title=title,
        description=description,
        severity=severity,
        cvss_score=score,
        published_date=published,
        last_modified_date=last_modified,
        raw_payload=payload,
    )


def _extract_description(cve: Mapping[str, Any]) -> str | None:
    descriptions = cve.get("descriptions")
    if isinstance(descriptions, list):
        for entry in descriptions:
            if isinstance(entry, Mapping) and entry.get("lang") == "en":
                value = entry.get("value")
                if isinstance(value, str):
                    return value
        for entry in descriptions:
            if isinstance(entry, Mapping):
                value = entry.get("value")
                if isinstance(value, str):
                    return value
    return None


def _extract_severity_and_score(payload: Mapping[str, Any]) -> tuple[str | None, float | None]:
    metrics = payload.get("metrics") or {}
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key)
        if isinstance(entries, list) and entries:
            cvss_data = entries[0].get("cvssData") if isinstance(entries[0], Mapping) else None
            if isinstance(cvss_data, Mapping):
                severity = _get_first_str(cvss_data, "baseSeverity")
                score = _get_first_float(cvss_data, "baseScore")
                return severity, score
    return None, None


def _get_first_str(mapping: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _get_first_float(mapping: Mapping[str, Any], *keys: str) -> float | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                continue
    return None
