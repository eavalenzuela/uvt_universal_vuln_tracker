from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from socket import timeout as SocketTimeout
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .vuln_ingest import parse_date


class CveEnrichmentError(Exception):
    """Base error for CVE enrichment failures."""


class CveNotFoundError(CveEnrichmentError):
    """Raised when the upstream source has no record for a CVE."""


class CveUpstreamTimeoutError(CveEnrichmentError):
    """Raised when the upstream source times out."""


class CveUpstreamRequestError(CveEnrichmentError):
    """Raised when the upstream source fails unexpectedly."""


@dataclass
class CveEnrichmentData:
    cve_id: str | None
    title: str | None
    description: str | None
    severity: str | None
    cvss_score: float | None
    cvss_vector: str | None
    cvss_version: str | None
    cwe_id: str | None
    references_json: list[dict[str, Any]]
    published_date: date | None
    last_modified_date: date | None
    raw_payload: dict[str, Any]


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"


def fetch_cve_enrichment(cve_id: str, *, timeout_seconds: int = 10) -> CveEnrichmentData:
    url = NVD_CVE_API_URL.format(cve_id=quote(cve_id, safe=""))
    request = Request(url, headers={"User-Agent": "uvt-cve-enrichment/1.0", "Accept": "application/json"})

    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            raise CveNotFoundError(f"CVE {cve_id} not found") from exc
        raise CveUpstreamRequestError(f"NVD request failed ({exc.code})") from exc
    except SocketTimeout as exc:
        raise CveUpstreamTimeoutError("NVD request timed out") from exc
    except URLError as exc:
        if isinstance(exc.reason, SocketTimeout):
            raise CveUpstreamTimeoutError("NVD request timed out") from exc
        raise CveUpstreamRequestError("NVD request failed") from exc
    except (ValueError, json.JSONDecodeError) as exc:
        raise CveUpstreamRequestError("Invalid NVD response payload") from exc

    vuln_items = payload.get("vulnerabilities")
    if not isinstance(vuln_items, list) or not vuln_items:
        raise CveNotFoundError(f"CVE {cve_id} not found")

    first_item = vuln_items[0] if isinstance(vuln_items[0], Mapping) else {}
    return map_nvd_cve_enrichment(first_item)


def map_nvd_cve_enrichment(payload: Mapping[str, Any]) -> CveEnrichmentData:
    cve = payload.get("cve") if isinstance(payload.get("cve"), Mapping) else {}

    cve_id = _get_first_str(cve, "id") or _get_first_str(payload, "cve_id", "cveId")
    description = _extract_description(cve) or _get_first_str(payload, "description", "summary")
    title = _get_first_str(cve, "title") or cve_id or _get_first_str(payload, "title")

    severity, score, vector, version = _extract_cvss_fields(payload)
    cwe_id = _extract_cwe_id(cve)
    references_json = _extract_references(cve)
    published = parse_date(payload.get("published") or payload.get("publishedDate"))
    last_modified = parse_date(payload.get("lastModified") or payload.get("lastModifiedDate"))

    return CveEnrichmentData(
        cve_id=cve_id,
        title=title,
        description=description,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        cvss_version=version,
        cwe_id=cwe_id,
        references_json=references_json,
        published_date=published,
        last_modified_date=last_modified,
        raw_payload=dict(payload),
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


def _extract_cvss_fields(payload: Mapping[str, Any]) -> tuple[str | None, float | None, str | None, str | None]:
    metrics = payload.get("metrics") or {}
    metric_order = (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    )
    for metric_key, fallback_version in metric_order:
        entries = metrics.get(metric_key)
        if isinstance(entries, list) and entries:
            first_entry = entries[0] if isinstance(entries[0], Mapping) else {}
            cvss_data = first_entry.get("cvssData") if isinstance(first_entry.get("cvssData"), Mapping) else {}
            severity = _get_first_str(cvss_data, "baseSeverity") or _get_first_str(first_entry, "baseSeverity")
            score = _get_first_float(cvss_data, "baseScore") or _get_first_float(first_entry, "baseScore")
            vector = _get_first_str(cvss_data, "vectorString")
            version = _get_first_str(cvss_data, "version") or fallback_version
            return severity, score, vector, version
    return None, None, None, None


def _extract_cwe_id(cve: Mapping[str, Any]) -> str | None:
    weaknesses = cve.get("weaknesses")
    if not isinstance(weaknesses, list):
        return None

    for weakness in weaknesses:
        if not isinstance(weakness, Mapping):
            continue
        descs = weakness.get("description")
        if not isinstance(descs, list):
            continue
        for entry in descs:
            if not isinstance(entry, Mapping):
                continue
            value = entry.get("value")
            if isinstance(value, str) and value.startswith("CWE-"):
                return value
    return None


def _extract_references(cve: Mapping[str, Any]) -> list[dict[str, Any]]:
    references = cve.get("references")
    if not isinstance(references, list):
        return []

    items: list[dict[str, Any]] = []
    for ref in references:
        if not isinstance(ref, Mapping):
            continue
        url = ref.get("url")
        if not isinstance(url, str) or not url:
            continue
        title = ref.get("name") if isinstance(ref.get("name"), str) else None
        source = ref.get("source") if isinstance(ref.get("source"), str) else None
        tags = ref.get("tags") if isinstance(ref.get("tags"), list) else None
        items.append({"url": url, "title": title, "source": source, "tags": tags})
    return items


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
