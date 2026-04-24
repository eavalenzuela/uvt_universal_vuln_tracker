"""Bulk scanner import adapters (F19).

Accepts scanner output files (Nessus .nessus XML, Qualys CSV, Trivy JSON) and
normalizes each row into a NormalizedVuln fed through the standard upsert
pipeline. Trivy JSON reuses the parser from ``webhook_ingest`` to avoid
divergence.
"""

from __future__ import annotations

import csv
import io
import xml.etree.ElementTree as ET
from datetime import date
from typing import Any, Iterable

from backend.services.vuln_ingest import NormalizedVuln, upsert_vulnerability
from backend.services.webhook_ingest import WebhookPayloadError, _parse_trivy


class ScannerImportError(ValueError):
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
    # Nessus risk_factor numeric string form (0..4)
    "4": "Critical",
    "3": "High",
    "2": "Medium",
    "1": "Low",
    "0": "None",
}


def _normalize_severity(raw: Any) -> str | None:
    if raw is None:
        return None
    text = str(raw).strip().lower()
    return _SEVERITY_ALIASES.get(text)


def _parse_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _float_or_none(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Nessus (.nessus XML)
# ---------------------------------------------------------------------------

def parse_nessus(xml_bytes: bytes) -> Iterable[NormalizedVuln]:
    """Parse a Tenable Nessus .nessus v2 report.

    Each <ReportItem> element describes one finding on one host.
    """
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ScannerImportError(f"invalid Nessus XML: {exc}") from exc

    for report_item in root.iter("ReportItem"):
        plugin_name = report_item.attrib.get("pluginName") or report_item.findtext("plugin_name")
        if not plugin_name:
            continue

        cve_elem = report_item.find("cve")
        cve_id = cve_elem.text.strip() if cve_elem is not None and cve_elem.text else None

        severity = _normalize_severity(
            report_item.attrib.get("severity")
            or report_item.findtext("risk_factor"),
        )

        cvss_score = _float_or_none(
            report_item.findtext("cvss3_base_score")
            or report_item.findtext("cvss_base_score"),
        )

        description = (
            report_item.findtext("description")
            or report_item.findtext("synopsis")
        )

        yield NormalizedVuln(
            cve_id=cve_id,
            title=plugin_name.strip(),
            description=description.strip() if isinstance(description, str) else None,
            severity=severity,
            cvss_score=cvss_score,
            published_date=_parse_date(report_item.findtext("plugin_publication_date")),
            last_modified_date=_parse_date(report_item.findtext("plugin_modification_date")),
            raw_payload={
                "plugin_id": report_item.attrib.get("pluginID"),
                "plugin_family": report_item.attrib.get("pluginFamily"),
                "port": report_item.attrib.get("port"),
            },
        )


# ---------------------------------------------------------------------------
# Qualys CSV
# ---------------------------------------------------------------------------

_QUALYS_ALIASES = {
    "title": ("Title", "VULN TITLE", "QID Title"),
    "qid": ("QID",),
    "cve": ("CVE ID", "CVE"),
    "severity": ("Severity", "Vuln Severity"),
    "cvss": ("CVSS Base", "CVSS3 Base", "CVSS"),
    "description": ("Description", "Threat"),
    "first_seen": ("First Detected", "First Found"),
    "last_seen": ("Last Detected", "Last Found", "Last Updated"),
}


def _pick(row: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        if key in row and row[key]:
            return row[key]
    return None


def parse_qualys_csv(csv_bytes: bytes) -> Iterable[NormalizedVuln]:
    """Parse a Qualys VM detection CSV export.

    Column layout varies by export profile; we probe a handful of known header
    names. Rows without a usable title or QID are skipped.
    """
    try:
        text = csv_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ScannerImportError(f"invalid Qualys CSV encoding: {exc}") from exc

    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise ScannerImportError("Qualys CSV has no header row")

    for row in reader:
        title = _pick(row, _QUALYS_ALIASES["title"])
        qid = _pick(row, _QUALYS_ALIASES["qid"])
        if not title:
            title = f"QID {qid}" if qid else None
        if not title:
            continue

        cve_raw = _pick(row, _QUALYS_ALIASES["cve"])
        # Qualys can list multiple CVEs comma-separated; take the first.
        cve_id = cve_raw.split(",")[0].strip() if cve_raw else None

        yield NormalizedVuln(
            cve_id=cve_id or None,
            title=title.strip(),
            description=_pick(row, _QUALYS_ALIASES["description"]),
            severity=_normalize_severity(_pick(row, _QUALYS_ALIASES["severity"])),
            cvss_score=_float_or_none(_pick(row, _QUALYS_ALIASES["cvss"])),
            published_date=_parse_date(_pick(row, _QUALYS_ALIASES["first_seen"])),
            last_modified_date=_parse_date(_pick(row, _QUALYS_ALIASES["last_seen"])),
            raw_payload={"qid": qid, "qualys_row": row},
        )


# ---------------------------------------------------------------------------
# Trivy JSON (reuses webhook parser so behavior stays identical)
# ---------------------------------------------------------------------------

def parse_trivy_json(json_bytes: bytes) -> Iterable[NormalizedVuln]:
    import json

    try:
        payload = json.loads(json_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ScannerImportError(f"invalid Trivy JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ScannerImportError("Trivy JSON must be a JSON object")
    try:
        yield from _parse_trivy(payload)
    except WebhookPayloadError as exc:
        raise ScannerImportError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

PARSERS = {
    "nessus": parse_nessus,
    "qualys": parse_qualys_csv,
    "trivy": parse_trivy_json,
}


def import_scanner_file(
    *,
    scanner: str,
    file_bytes: bytes,
    source_label: str,
    team_id: int | None = None,
) -> int:
    parser = PARSERS.get(scanner)
    if parser is None:
        raise ScannerImportError(f"unsupported scanner: {scanner}")

    ingested = 0
    for normalized in parser(file_bytes):
        upsert_vulnerability(normalized, source=source_label, team_id=team_id)
        ingested += 1
    return ingested
