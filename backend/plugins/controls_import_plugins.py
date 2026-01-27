from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.request import Request, urlopen

from .base import ControlsImportPlugin
from .controls_import.cis import map_cis_record
from .controls_import.pci_dss import map_pci_dss_record
from .controls_import.stig import map_stig_record
from ..services.controls_ingest import NormalizedControl, upsert_controls


class CisControlsImportPlugin(ControlsImportPlugin):
    plugin_id = "controls-import-cis"
    display_name = "CIS Controls Import"
    version = "1.0.0"
    capabilities = ("controls_import", "cis")
    config_schema = {
        "fields": [
            {
                "name": "file_path",
                "label": "Controls file path",
                "type": "string",
                "required": True,
            },
            {
                "name": "source_url",
                "label": "Source URL",
                "type": "string",
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
        ],
    }

    def run(self) -> dict[str, Any]:
        records = _load_records(self.config)
        normalized = _normalize_controls(records, map_cis_record)
        upsert_controls(normalized, source=self.plugin_id)
        return {"status": "success", "stats": {"items_processed": len(normalized)}}


class PciDssControlsImportPlugin(ControlsImportPlugin):
    plugin_id = "controls-import-pci-dss"
    display_name = "PCI DSS Controls Import"
    version = "1.0.0"
    capabilities = ("controls_import", "pci_dss")
    config_schema = {
        "fields": [
            {
                "name": "file_path",
                "label": "Controls file path",
                "type": "string",
                "required": True,
            },
            {
                "name": "source_url",
                "label": "Source URL",
                "type": "string",
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
        ],
    }

    def run(self) -> dict[str, Any]:
        records = _load_records(self.config)
        normalized = _normalize_controls(records, map_pci_dss_record)
        upsert_controls(normalized, source=self.plugin_id)
        return {"status": "success", "stats": {"items_processed": len(normalized)}}


class StigControlsImportPlugin(ControlsImportPlugin):
    plugin_id = "controls-import-stig"
    display_name = "STIG Controls Import"
    version = "1.0.0"
    capabilities = ("controls_import", "stig")
    config_schema = {
        "fields": [
            {
                "name": "file_path",
                "label": "Controls file path",
                "type": "string",
                "required": True,
            },
            {
                "name": "source_url",
                "label": "Source URL",
                "type": "string",
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
        ],
    }

    def run(self) -> dict[str, Any]:
        records = _load_records(self.config)
        normalized = _normalize_controls(records, map_stig_record)
        upsert_controls(normalized, source=self.plugin_id)
        return {"status": "success", "stats": {"items_processed": len(normalized)}}


def _normalize_controls(
    records: Iterable[Mapping[str, Any]],
    mapper,
) -> list[NormalizedControl]:
    normalized: list[NormalizedControl] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        normalized.append(mapper(record))
    return normalized


def _load_records(config: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    payload = _load_json_payload(config)
    return _extract_records(payload)


def _load_json_payload(config: Mapping[str, Any]) -> Any:
    file_path = config.get("file_path")
    source_url = config.get("source_url")
    timeout_seconds = config.get("timeout_seconds", 30)
    auth_token = config.get("auth_token")

    if file_path:
        return _load_json_from_file(file_path)
    if source_url:
        return _load_json_from_url(source_url, auth_token=auth_token, timeout_seconds=timeout_seconds)
    raise ValueError("Missing file_path or source_url for controls import plugin.")


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

    for key in ("controls", "items", "records", "data", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, Mapping)]

    return [payload]
