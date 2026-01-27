from __future__ import annotations

from typing import Any, Mapping

from backend.services.controls_ingest import NormalizedControl


def map_cis_record(payload: Mapping[str, Any]) -> NormalizedControl:
    control_id = _get_first_str(payload, "control_id", "id", "controlId", "identifier") or "Unknown"
    title = _get_first_str(payload, "title", "name") or control_id
    description = _get_first_str(payload, "description", "summary")
    version = _get_first_str(payload, "version", "benchmark_version", "benchmarkVersion")
    source_url = _get_first_str(payload, "url", "source_url", "sourceUrl", "link")
    framework = _get_first_str(payload, "framework") or "CIS"

    return NormalizedControl(
        framework=framework,
        control_id=control_id,
        title=title,
        description=description,
        version=version,
        source_url=source_url,
        raw_payload=payload,
    )


def _get_first_str(mapping: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value:
            return value
    return None
