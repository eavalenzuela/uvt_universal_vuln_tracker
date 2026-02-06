from __future__ import annotations

from typing import Any

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import asc

from ..auth import login_required, role_required
from ..database import db
from ..models import PluginConfig
from ..plugins.config import is_masked_value, mask_config
from ..plugins.registry import PluginRegistry
from ..plugins.runner import enqueue_plugin_run, get_latest_plugin_run, get_plugin_run_by_id
from ..plugins.state import get_plugin_config, upsert_plugin_config
from ..services.audit import log_audit_event

bp = Blueprint("plugins_api", __name__, url_prefix="/api")


def _audit(action, resource, record_id, *, old_values=None, new_values=None):
    actor = getattr(request, "user", None)
    db.session.add(log_audit_event(
        actor_id=actor.id if actor else None,
        action=action,
        resource=resource,
        record_id=record_id,
        old_values=old_values,
        new_values=new_values,
    ))


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


def _plugin_config_json(
    config: PluginConfig | None,
    *,
    plugin_id: str | None = None,
    schema: dict[str, Any] | None = None,
):
    return {
        "plugin_id": plugin_id or (config.plugin_id if config else None),
        "enabled": config.enabled if config else True,
        "schedule_cron": config.schedule_cron if config else None,
        "interval_minutes": config.interval_minutes if config else None,
        "config": mask_config(config.config_json or {}, schema) if config else {},
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


def _merge_plugin_config(existing: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    for key, value in updates.items():
        if is_masked_value(value):
            if key in existing:
                merged[key] = existing[key]
            continue
        if isinstance(value, dict):
            prior = existing.get(key)
            if isinstance(prior, dict):
                merged[key] = _merge_plugin_config(prior, value)
            else:
                merged[key] = _merge_plugin_config({}, value)
            continue
        merged[key] = value
    return merged


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
                "config": mask_config(config_row.config_json or {}, plugin_cls.config_schema) if config_row else {},
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
        "config": mask_config(config_row.config_json or {}, plugin_cls.config_schema) if config_row else {},
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
    run = enqueue_plugin_run(current_app._get_current_object(), registry, plugin_id, config=config_payload)
    _audit("RUN", "plugin_runs", run.id, new_values={"plugin_id": plugin_id, "config_override": config_override})
    db.session.commit()
    return jsonify(_plugin_run_json(run)), 202


@bp.get("/plugins/runs/<int:run_id>")
@login_required
def get_plugin_run_status(run_id: int):
    run = get_plugin_run_by_id(run_id)
    if not run:
        return jsonify({"error": "Plugin run not found"}), 404
    return jsonify(_plugin_run_json(run)), 200


@bp.post("/plugins/<plugin_id>/config")
@role_required("Admin", "Analyst")
def update_plugin_config(plugin_id: str):
    registry = _get_registry()
    plugin_cls = _get_plugin_class(registry, plugin_id)
    if not plugin_cls:
        return jsonify({"error": "Plugin not found"}), 404

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "payload must be an object"}), 400

    if "config" in payload and not isinstance(payload.get("config"), dict):
        return jsonify({"error": "config must be an object"}), 400
    if "enabled" in payload and not isinstance(payload.get("enabled"), bool):
        return jsonify({"error": "enabled must be a boolean"}), 400
    if "schedule_cron" in payload and payload.get("schedule_cron") is not None:
        if not isinstance(payload.get("schedule_cron"), str):
            return jsonify({"error": "schedule_cron must be a string"}), 400
    if "interval_minutes" in payload and payload.get("interval_minutes") is not None:
        if not isinstance(payload.get("interval_minutes"), int):
            return jsonify({"error": "interval_minutes must be an integer"}), 400

    config_row = get_plugin_config(plugin_id)
    existing_config = dict(config_row.config_json or {}) if config_row else {}
    incoming_config = payload.get("config")
    merged_config = existing_config
    if incoming_config is not None:
        merged_config = _merge_plugin_config(existing_config, incoming_config)

    enabled = payload.get("enabled", config_row.enabled if config_row else True)
    schedule_cron = (
        payload.get("schedule_cron")
        if "schedule_cron" in payload
        else (config_row.schedule_cron if config_row else None)
    )
    interval_minutes = (
        payload.get("interval_minutes")
        if "interval_minutes" in payload
        else (config_row.interval_minutes if config_row else None)
    )

    old_values = _plugin_config_json(config_row, plugin_id=plugin_id, schema=plugin_cls.config_schema)

    updated = upsert_plugin_config(
        plugin_id,
        merged_config if incoming_config is not None else None,
        enabled=enabled,
        schedule_cron=schedule_cron,
        interval_minutes=interval_minutes,
    )
    _audit(
        "UPDATE",
        "plugin_configs",
        updated.id,
        old_values=old_values,
        new_values=_plugin_config_json(updated, schema=plugin_cls.config_schema),
    )
    db.session.commit()
    return jsonify(_plugin_config_json(updated, schema=plugin_cls.config_schema)), 200
