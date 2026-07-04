"""CISA Known Exploited Vulnerabilities (KEV) catalog mapper.

Catalog shape (https://www.cisa.gov/known-exploited-vulnerabilities-catalog):

    {
      "title": "CISA Catalog of Known Exploited Vulnerabilities",
      "vulnerabilities": [
        {
          "cveID": "CVE-2021-44228",
          "vendorProject": "Apache",
          "product": "Log4j2",
          "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
          "dateAdded": "2021-12-10",
          "shortDescription": "...",
          "requiredAction": "...",
          "dueDate": "2021-12-24",
          "knownRansomwareCampaignUse": "Known"
        },
        ...
      ]
    }

KEV entries carry no CVSS data, so severity/score are left untouched — the
catalog's value is the ``known_exploited`` flag and ``kev_date_added``.
"""

from __future__ import annotations

from typing import Any, Mapping

from backend.services.vuln_ingest import NormalizedVuln, parse_date


def map_kev_record(payload: Mapping[str, Any]) -> NormalizedVuln:
    cve_id = _first_str(payload, "cveID", "cve_id", "cveId")
    title = _first_str(payload, "vulnerabilityName", "title") or cve_id or "KEV Vulnerability"
    description = _first_str(payload, "shortDescription", "description")
    required_action = _first_str(payload, "requiredAction")
    if description and required_action:
        description = f"{description}\n\nCISA required action: {required_action}"

    return NormalizedVuln(
        cve_id=cve_id,
        title=title,
        description=description,
        known_exploited=True,
        kev_date_added=parse_date(payload.get("dateAdded")),
        raw_payload=payload,
    )


def _first_str(mapping: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value:
            return value
    return None
