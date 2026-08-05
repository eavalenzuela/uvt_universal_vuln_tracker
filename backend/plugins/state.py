from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from ..database import db
from ..models import (
    ExternalSourceState,
    PluginConfig,
    PluginRun,
    PluginRunArtifact,
    PluginRunArtifactLink,
)

logger = logging.getLogger(__name__)


def get_plugin_config(plugin_id: str) -> PluginConfig | None:
    return PluginConfig.query.filter_by(plugin_id=plugin_id).first()


def upsert_plugin_config(
    plugin_id: str,
    config: Mapping[str, Any] | None = None,
    *,
    enabled: bool = True,
    schedule_cron: str | None = None,
    interval_minutes: int | None = None,
) -> PluginConfig:
    config_row = get_plugin_config(plugin_id)
    if not config_row:
        config_row = PluginConfig(
            plugin_id=plugin_id,
            config_json=dict(config or {}),
            enabled=enabled,
            schedule_cron=schedule_cron,
            interval_minutes=interval_minutes,
        )
        db.session.add(config_row)
    else:
        if config is not None:
            config_row.config_json = dict(config)
        config_row.enabled = enabled
        if schedule_cron is not None:
            config_row.schedule_cron = schedule_cron
        if interval_minutes is not None:
            config_row.interval_minutes = interval_minutes
    db.session.commit()
    return config_row


def get_external_source_state(plugin_id: str, source_key: str) -> ExternalSourceState | None:
    return ExternalSourceState.query.filter_by(plugin_id=plugin_id, source_key=source_key).first()


def upsert_external_source_state(
    plugin_id: str,
    source_key: str,
    *,
    last_cursor: str | None = None,
    last_sync_at: datetime | None = None,
) -> ExternalSourceState:
    state = get_external_source_state(plugin_id, source_key)
    if not state:
        state = ExternalSourceState(
            plugin_id=plugin_id,
            source_key=source_key,
            last_cursor=last_cursor,
            last_sync_at=last_sync_at,
        )
        db.session.add(state)
    else:
        state.last_cursor = last_cursor
        state.last_sync_at = last_sync_at
    db.session.commit()
    return state


def create_plugin_run(
    plugin_id: str,
    *,
    status: str,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    error: str | None = None,
    stats: Mapping[str, Any] | None = None,
    team_id: int | None = None,
) -> PluginRun:
    # F15: team_id defaults to the plugin's configured team if not passed.
    if team_id is None:
        config = get_plugin_config(plugin_id)
        if config is not None:
            team_id = getattr(config, "team_id", None)
    run = PluginRun(
        plugin_id=plugin_id,
        status=status,
        started_at=started_at or datetime.now(timezone.utc),
        finished_at=finished_at,
        error=error,
        stats_json=dict(stats or {}) if stats is not None else None,
        team_id=team_id,
    )
    db.session.add(run)
    db.session.commit()
    return run


def update_plugin_run(
    run: PluginRun,
    *,
    status: str | None = None,
    finished_at: datetime | None = None,
    error: str | None = None,
    stats: Mapping[str, Any] | None = None,
) -> PluginRun:
    if status is not None:
        run.status = status
    if finished_at is not None:
        run.finished_at = finished_at
    if error is not None:
        run.error = error
    if stats is not None:
        run.stats_json = dict(stats)
    db.session.commit()
    return run


def save_plugin_run_result(
    run: PluginRun,
    *,
    status: str,
    finished_at: datetime,
    error: str | None = None,
    stats: Mapping[str, Any] | None = None,
    artifact_descriptors: Sequence[Mapping[str, Any]] | None = None,
) -> PluginRun:
    run.status = status
    run.finished_at = finished_at
    run.error = error
    if stats is not None:
        run.stats_json = dict(stats)

    try:
        if artifact_descriptors is not None:
            run.artifacts.clear()
            for descriptor in artifact_descriptors:
                artifact = PluginRunArtifact(
                    plugin_run_id=run.id,
                    artifact_type=str(descriptor.get("artifact_type") or "unknown"),
                    storage_path=str(descriptor.get("storage_path") or ""),
                    checksum=descriptor.get("checksum"),
                    size=descriptor.get("size"),
                    content_type=descriptor.get("content_type"),
                )
                db.session.add(artifact)
                db.session.flush()

                for vuln_id in descriptor.get("vulnerability_ids") or []:
                    db.session.add(
                        PluginRunArtifactLink(
                            artifact_id=artifact.id,
                            vulnerability_id=int(vuln_id),
                        )
                    )
                for version_id in descriptor.get("product_version_ids") or []:
                    db.session.add(
                        PluginRunArtifactLink(
                            artifact_id=artifact.id,
                            product_version_id=int(version_id),
                        )
                    )

        db.session.commit()
    except Exception as exc:
        # Log the real exception. This used to be replaced wholesale with the
        # string "artifact persistence failed", which told an operator nothing
        # and left no trace anywhere of what actually went wrong.
        logger.exception("Persisting artifacts for plugin run %s failed", run.id)
        db.session.rollback()
        run = db.session.get(PluginRun, run.id)
        run.status = "partial_failed"
        run.finished_at = finished_at
        run.error = f"artifact persistence failed: {type(exc).__name__}: {exc}"[:500]
        db.session.commit()
    return run
