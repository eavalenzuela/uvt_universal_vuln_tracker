from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from ..database import db
from ..models import ExternalSourceState, PluginConfig, PluginRun


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
) -> PluginRun:
    run = PluginRun(
        plugin_id=plugin_id,
        status=status,
        started_at=started_at or datetime.utcnow(),
        finished_at=finished_at,
        error=error,
        stats_json=dict(stats or {}) if stats is not None else None,
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
