from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import asc

from ..auth import login_required, role_required
from ..models import PluginConfig
from ..plugins.registry import PluginRegistry
from ..plugins.runner import get_latest_plugin_run, run_plugin
from ..plugins.state import get_plugin_config

bp = Blueprint("plugins_api", __name__, url_prefix="/api")

_SENSITIVE_KEY_MARKERS = (
    "secret",
    "token",
    "password",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_secret",
)


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _SENSITIVE_KEY_MARKERS)


def _sanitize_config(value: Any) -> Any:
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if _is_sensitive_key(str(key)):
                sanitized[key] = "******" if item not in (None, "") else item
            else:
                sanitized[key] = _sanitize_config(item)
        return sanitized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_sanitize_config(item) for item in value]
    return value


def _plugin_run_json(run):
    if not run:
        return None
    return {
        "id": run.id,
        "plugin_id": run.plugin_id,
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "error": run.error,
        "stats": run.stats_json,
    }


def _plugin_config_json(config: PluginConfig | None, *, plugin_id: str | None = None):
    return {
        "plugin_id": plugin_id or (config.plugin_id if config else None),
        "enabled": config.enabled if config else True,
        "schedule_cron": config.schedule_cron if config else None,
        "interval_minutes": config.interval_minutes if config else None,
        "config": _sanitize_config(config.config_json or {}) if config else {},
    }


def _get_registry() -> PluginRegistry:
    registry = current_app.extensions.get("plugin_registry")
    if not registry:
        raise RuntimeError("Plugin registry not initialized")
    return registry


def _get_plugin_class(registry: PluginRegistry, plugin_id: str):
    for plugin_cls in registry.list_plugins():
        if plugin_cls.plugin_id == plugin_id:
            return plugin_cls
    return None


@bp.get("/plugins")
@login_required
def list_plugins():
    registry = _get_registry()
    plugins = []
    for plugin_cls in registry.list_plugins():
        config_row = get_plugin_config(plugin_cls.plugin_id)
        last_run = get_latest_plugin_run(plugin_cls.plugin_id)
        plugins.append(
            {
                "plugin_id": plugin_cls.plugin_id,
                "display_name": plugin_cls.display_name,
                "version": plugin_cls.version,
                "capabilities": list(plugin_cls.capabilities or []),
                "config_schema": plugin_cls.config_schema,
                "config": _sanitize_config(config_row.config_json or {}) if config_row else {},
                "enabled": config_row.enabled if config_row else True,
                "schedule_cron": config_row.schedule_cron if config_row else None,
                "interval_minutes": config_row.interval_minutes if config_row else None,
                "last_run": _plugin_run_json(last_run),
            }
        )
    plugins.sort(key=lambda item: item["plugin_id"])
    return jsonify(plugins)


@bp.get("/plugins/configs")
@login_required
def list_plugin_configs():
    configs = PluginConfig.query.order_by(asc(PluginConfig.plugin_id)).all()
    return jsonify([_plugin_config_json(config) for config in configs])


@bp.get("/plugins/<plugin_id>")
@login_required
def get_plugin(plugin_id: str):
    registry = _get_registry()
    plugin_cls = _get_plugin_class(registry, plugin_id)
    if not plugin_cls:
        return jsonify({"error": "Plugin not found"}), 404
    config_row = get_plugin_config(plugin_id)
    last_run = get_latest_plugin_run(plugin_id)
    payload = {
        "plugin_id": plugin_cls.plugin_id,
        "display_name": plugin_cls.display_name,
        "version": plugin_cls.version,
        "capabilities": list(plugin_cls.capabilities or []),
        "config_schema": plugin_cls.config_schema,
        "config": _sanitize_config(config_row.config_json or {}) if config_row else {},
        "enabled": config_row.enabled if config_row else True,
        "schedule_cron": config_row.schedule_cron if config_row else None,
        "interval_minutes": config_row.interval_minutes if config_row else None,
        "last_run": _plugin_run_json(last_run),
    }
    return jsonify(payload)


@bp.post("/plugins/<plugin_id>/run")
@role_required("Admin", "Analyst")
def run_plugin_now(plugin_id: str):
    registry = _get_registry()
    plugin_cls = _get_plugin_class(registry, plugin_id)
    if not plugin_cls:
        return jsonify({"error": "Plugin not found"}), 404

    payload = request.get_json(silent=True) or {}
    config_override = payload.get("config")
    if config_override is not None and not isinstance(config_override, dict):
        return jsonify({"error": "config must be an object"}), 400

    config_row = get_plugin_config(plugin_id)
    config_payload = dict(config_row.config_json or {}) if config_row else {}
    if config_override:
        config_payload.update(config_override)
    run = run_plugin(registry, plugin_id, config=config_payload)
    return jsonify(_plugin_run_json(run)), 201
