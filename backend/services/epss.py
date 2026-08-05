"""EPSS enrichment (FIRST.org Exploit Prediction Scoring System).

KEV flagging tells you a CVE *is* being exploited. EPSS tells you how likely
one is to be exploited in the next 30 days. Together they turn "what do I fix
first" into something better than sorting by CVSS, which correlates poorly with
real-world exploitation — most Critical CVEs are never exploited, and plenty of
Mediums are.

The public API takes up to 100 CVE ids per request and needs no key.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from urllib.parse import urlencode
from urllib.request import Request

from ..database import db
from ..models import Vulnerability
from .url_guard import UnsafeOutboundUrlError, safe_urlopen

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100
REQUEST_TIMEOUT_SECONDS = 20


def fetch_epss_scores(cve_ids: list[str], *, timeout: int = REQUEST_TIMEOUT_SECONDS) -> dict[str, dict]:
    """Return ``{cve_id: {"epss": float, "percentile": float}}``.

    CVEs the service does not know about are simply absent from the result.
    """
    scores: dict[str, dict] = {}
    unique = [c for c in dict.fromkeys(cve_ids) if c]

    for start in range(0, len(unique), BATCH_SIZE):
        batch = unique[start:start + BATCH_SIZE]
        url = f"{EPSS_API_URL}?{urlencode({'cve': ','.join(batch)})}"
        request = Request(url, headers={"Accept": "application/json", "User-Agent": "UVT"})
        try:
            with safe_urlopen(request, timeout=timeout, purpose="EPSS lookup") as response:
                payload = json.loads(response.read().decode("utf-8"))
        except UnsafeOutboundUrlError:
            raise
        except Exception as exc:  # network / decode failures are non-fatal
            logger.warning("EPSS batch lookup failed: %s", exc)
            continue

        for row in payload.get("data") or []:
            cve = row.get("cve")
            if not cve:
                continue
            try:
                scores[cve] = {
                    "epss": float(row.get("epss", 0.0)),
                    "percentile": float(row.get("percentile", 0.0)),
                }
            except (TypeError, ValueError):
                continue

    return scores


def enrich_vulnerabilities_with_epss(vulnerabilities=None, *, commit: bool = True) -> int:
    """Populate EPSS fields for the given vulnerabilities (default: all with a CVE).

    Returns the number of records updated.
    """
    if vulnerabilities is None:
        vulnerabilities = Vulnerability.query.filter(Vulnerability.cve_id.isnot(None)).all()

    by_cve: dict[str, list] = {}
    for vuln in vulnerabilities:
        if vuln.cve_id:
            by_cve.setdefault(vuln.cve_id, []).append(vuln)

    if not by_cve:
        return 0

    scores = fetch_epss_scores(list(by_cve))
    now = datetime.now(timezone.utc)
    updated = 0

    for cve, data in scores.items():
        for vuln in by_cve.get(cve, []):
            vuln.epss_score = data["epss"]
            vuln.epss_percentile = data["percentile"]
            vuln.epss_updated_at = now
            db.session.add(vuln)
            updated += 1

    if commit and updated:
        db.session.commit()
    return updated
