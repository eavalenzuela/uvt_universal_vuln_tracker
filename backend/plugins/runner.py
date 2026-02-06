from __future__ import annotations

from collections.abc import Sized
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import logging
from typing import Any

from .registry import PluginRegistry
from .state import create_plugin_run, get_plugin_config, save_plugin_run_result
from ..models import PluginRun

logger = logging.getLogger(__name__)

_plugin_run_executor: ThreadPoolExecutor | None = None


def get_plugin_run_executor() -> ThreadPoolExecutor:
    global _plugin_run_executor
    if _plugin_run_executor is None:
        _plugin_run_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="plugin-runner")
    return _plugin_run_executor


def get_plugin_run_by_id(run_id: int) -> PluginRun | None:
    return PluginRun.query.execution_options(populate_existing=True).filter_by(id=run_id).first()


def get_latest_plugin_run(plugin_id: str) -> PluginRun | None:
    return PluginRun.query.filter_by(plugin_id=plugin_id).order_by(PluginRun.started_at.desc()).first()


def is_plugin_due(plugin_id: str, interval_minutes: int | None) -> bool:
    if not interval_minutes:
        return True
    last_run = get_latest_plugin_run(plugin_id)
    if not last_run or not last_run.started_at:
        return True
    next_run_at = last_run.started_at + timedelta(minutes=interval_minutes)
    return datetime.utcnow() >= next_run_at


def run_plugin(
    registry: PluginRegistry,
    plugin_id: str,
    *,
    config: dict[str, Any] | None = None,
) -> PluginRun:
    run = create_plugin_run(plugin_id, status="running")
    try:
        plugin = registry.create(plugin_id, config=config)
        result = plugin.run()
        stats: dict[str, Any] | None = None
        if isinstance(result, dict):
            stats_payload = result.get("stats")
            if isinstance(stats_payload, dict):
                stats = stats_payload
        if stats is None and isinstance(result, Sized) and not isinstance(result, (str, bytes)):
            stats = {"items_processed": len(result)}
        artifacts = []
        if isinstance(result, dict) and isinstance(result.get("artifacts"), list):
            artifacts = result.get("artifacts")
        elif getattr(plugin, "artifact_descriptors", None):
            artifacts = [vars(item) for item in plugin.artifact_descriptors]
        save_plugin_run_result(run, status="success", finished_at=datetime.utcnow(), stats=stats, artifact_descriptors=artifacts)
    except Exception as exc:  # noqa: BLE001 - record plugin errors and continue
        logger.exception("Plugin run failed for %s", plugin_id)
        save_plugin_run_result(
            run,
            status="failed",
            finished_at=datetime.utcnow(),
            error=str(exc),
        )
    return run


def _execute_plugin_run(
    app,
    registry: PluginRegistry,
    *,
    run_id: int,
    plugin_id: str,
    config: dict[str, Any] | None = None,
) -> None:
    with app.app_context():
        run = get_plugin_run_by_id(run_id)
        if not run:
            logger.error("Plugin run %s not found", run_id)
            return

        try:
            plugin = registry.create(plugin_id, config=config)
            result = plugin.run()
            stats: dict[str, Any] | None = None
            if isinstance(result, dict):
                stats_payload = result.get("stats")
                if isinstance(stats_payload, dict):
                    stats = stats_payload
            if stats is None and isinstance(result, Sized) and not isinstance(result, (str, bytes)):
                stats = {"items_processed": len(result)}
            artifacts = []
            if isinstance(result, dict) and isinstance(result.get("artifacts"), list):
                artifacts = result.get("artifacts")
            elif getattr(plugin, "artifact_descriptors", None):
                artifacts = [vars(item) for item in plugin.artifact_descriptors]
            save_plugin_run_result(run, status="success", finished_at=datetime.utcnow(), stats=stats, artifact_descriptors=artifacts)
        except Exception as exc:  # noqa: BLE001 - record plugin errors and continue
            logger.exception("Plugin run failed for %s", plugin_id)
            save_plugin_run_result(
                run,
                status="failed",
                finished_at=datetime.utcnow(),
                error=str(exc),
            )


def enqueue_plugin_run(
    app,
    registry: PluginRegistry,
    plugin_id: str,
    *,
    config: dict[str, Any] | None = None,
) -> PluginRun:
    run = create_plugin_run(plugin_id, status="running")
    get_plugin_run_executor().submit(
        _execute_plugin_run,
        app,
        registry,
        run_id=run.id,
        plugin_id=plugin_id,
        config=config,
    )
    return run


def run_plugins(
    registry: PluginRegistry,
    *,
    plugin_id: str | None = None,
    include_disabled: bool = False,
    only_due: bool = False,
) -> list[PluginRun]:
    runs: list[PluginRun] = []
    for plugin_cls in registry.list_plugins():
        current_id = plugin_cls.plugin_id
        if plugin_id and current_id != plugin_id:
            continue
        config_row = get_plugin_config(current_id)
        if config_row and not config_row.enabled and not include_disabled:
            logger.info("Skipping disabled plugin %s", current_id)
            continue
        if only_due and not is_plugin_due(current_id, getattr(config_row, "interval_minutes", None)):
            logger.info("Skipping plugin %s (not due)", current_id)
            continue
        config_payload = dict(config_row.config_json or {}) if config_row else {}
        runs.append(run_plugin(registry, current_id, config=config_payload))
    return runs
