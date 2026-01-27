from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.request import Request, urlopen

from .base import VulnerabilityFeedPlugin
from .vuln_feeds.exploitdb import map_exploitdb_record
from .vuln_feeds.nvd import map_nvd_record
from ..services.vuln_ingest import NormalizedVuln, upsert_vulnerabilities


class NvdVulnerabilityFeedPlugin(VulnerabilityFeedPlugin):
    plugin_id = "vuln-feed-nvd"
    display_name = "NVD Vulnerability Feed"
    version = "1.0.0"
    capabilities = ("vulnerability_feed", "nvd")
    config_schema = {
        "fields": [
            {
                "name": "feed_url",
                "label": "Feed URL",
                "type": "string",
                "required": True,
            },
            {
                "name": "auth_token",
                "label": "Auth token",
                "type": "string",
                "secret": True,
            },
            {
                "name": "timeout_seconds",
                "label": "Request timeout",
                "type": "integer",
                "default": 30,
            },
            {
                "name": "file_path",
                "label": "Fallback file path",
                "type": "string",
            },
        ],
    }

    def run(self) -> dict[str, Any]:
        records = _load_records(self.config)
        normalized = _normalize_vulns(records, map_nvd_record)
        upsert_vulnerabilities(normalized, source=self.plugin_id)
        return {"status": "success", "stats": {"items_processed": len(normalized)}}


class ExploitDbVulnerabilityFeedPlugin(VulnerabilityFeedPlugin):
    plugin_id = "vuln-feed-exploitdb"
    display_name = "ExploitDB Vulnerability Feed"
    version = "1.0.0"
    capabilities = ("vulnerability_feed", "exploitdb")
    config_schema = {
        "fields": [
            {
                "name": "feed_url",
                "label": "Feed URL",
                "type": "string",
                "required": True,
            },
            {
                "name": "auth_token",
                "label": "Auth token",
                "type": "string",
                "secret": True,
            },
            {
                "name": "timeout_seconds",
                "label": "Request timeout",
                "type": "integer",
                "default": 30,
            },
            {
                "name": "file_path",
                "label": "Fallback file path",
                "type": "string",
            },
        ],
    }

    def run(self) -> dict[str, Any]:
        records = _load_records(self.config)
        normalized = _normalize_vulns(records, map_exploitdb_record)
        upsert_vulnerabilities(normalized, source=self.plugin_id)
        return {"status": "success", "stats": {"items_processed": len(normalized)}}


def _normalize_vulns(
    records: Iterable[Mapping[str, Any]],
    mapper,
) -> list[NormalizedVuln]:
    normalized: list[NormalizedVuln] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        normalized.append(mapper(record))
    return normalized


def _load_records(config: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    payload = _load_json_payload(config)
    return _extract_records(payload)


def _load_json_payload(config: Mapping[str, Any]) -> Any:
    feed_url = config.get("feed_url")
    file_path = config.get("file_path")
    timeout_seconds = config.get("timeout_seconds", 30)
    auth_token = config.get("auth_token")

    if feed_url:
        return _load_json_from_url(feed_url, auth_token=auth_token, timeout_seconds=timeout_seconds)
    if file_path:
        return _load_json_from_file(file_path)
    raise ValueError("Missing feed_url or file_path for vulnerability feed plugin.")


def _load_json_from_url(url: str, *, auth_token: str | None, timeout_seconds: int) -> Any:
    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def _load_json_from_file(path: str) -> Any:
    payload = Path(path).read_text(encoding="utf-8")
    return json.loads(payload)


def _extract_records(payload: Any) -> list[Mapping[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Mapping)]
    if not isinstance(payload, Mapping):
        return []

    for key in ("vulnerabilities", "items", "records", "data", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, Mapping)]

    result = payload.get("result")
    if isinstance(result, Mapping):
        cve_items = result.get("CVE_Items")
        if isinstance(cve_items, list):
            return [item for item in cve_items if isinstance(item, Mapping)]

    return [payload]
