from __future__ import annotations

from datetime import date, datetime
from typing import Any, Mapping

from backend.services.vuln_ingest import NormalizedVuln, parse_date


def map_nvd_record(payload: Mapping[str, Any]) -> NormalizedVuln:
    cve = payload.get("cve") or {}
    cve_id = _get_first_str(cve, "id") or _get_first_str(payload, "cve_id", "cveId")
    description = _extract_description(cve) or _get_first_str(payload, "description", "summary")
    title = _get_first_str(cve, "title") or cve_id or _get_first_str(payload, "title") or "NVD Vulnerability"
    severity, score, vector, cvss_version = _extract_cvss(payload)
    published = parse_date(payload.get("published") or payload.get("publishedDate"))
    last_modified = parse_date(payload.get("lastModified") or payload.get("lastModifiedDate"))

    return NormalizedVuln(
        cve_id=cve_id,
        title=title,
        description=description,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        cvss_version=cvss_version,
        cwe_id=_extract_cwe(cve),
        references=_extract_references(cve),
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


def _extract_cvss(payload: Mapping[str, Any]) -> tuple[str | None, float | None, str | None, str | None]:
    """Return (severity, score, vector, version) from NVD metrics.

    Metrics live at the payload level in legacy feeds and under ``cve`` in the
    NVD 2.0 API shape; accept both.
    """
    metrics = payload.get("metrics")
    if not isinstance(metrics, Mapping):
        cve = payload.get("cve")
        metrics = cve.get("metrics") if isinstance(cve, Mapping) else None
    if not isinstance(metrics, Mapping):
        return None, None, None, None

    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key)
        if isinstance(entries, list) and entries:
            cvss_data = entries[0].get("cvssData") if isinstance(entries[0], Mapping) else None
            if isinstance(cvss_data, Mapping):
                severity = _get_first_str(cvss_data, "baseSeverity")
                score = _get_first_float(cvss_data, "baseScore")
                vector = _get_first_str(cvss_data, "vectorString")
                version = _get_first_str(cvss_data, "version")
                return severity, score, vector, version
    return None, None, None, None


def _extract_cwe(cve: Mapping[str, Any]) -> str | None:
    weaknesses = cve.get("weaknesses")
    if not isinstance(weaknesses, list):
        return None
    for weakness in weaknesses:
        if not isinstance(weakness, Mapping):
            continue
        descriptions = weakness.get("description")
        if not isinstance(descriptions, list):
            continue
        for entry in descriptions:
            if isinstance(entry, Mapping):
                value = entry.get("value")
                if isinstance(value, str) and value.startswith("CWE-"):
                    return value
    return None


def _extract_references(cve: Mapping[str, Any]) -> tuple[str, ...] | None:
    references = cve.get("references")
    if not isinstance(references, list):
        return None
    urls: list[str] = []
    for entry in references:
        if isinstance(entry, Mapping):
            url = entry.get("url")
            if isinstance(url, str) and url and url not in urls:
                urls.append(url)
    return tuple(urls) or None


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
