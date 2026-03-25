from __future__ import annotations

import importlib
import inspect
from typing import Any

from flask import Blueprint, current_app, jsonify, request, send_file
from sqlalchemy import asc

from ..auth import login_required, role_required
from ..rate_limiter import rate_limit
from ..database import db
from ..models import PluginConfig, PluginRunArtifact
from ..plugins.config import is_masked_value, mask_config
from ..plugins.base import BasePlugin, ControlsImportPlugin, VulnerabilityFeedPlugin
from ..plugins.config import prepare_plugin_config, validate_config_schema
from ..plugins.registry import PluginRegistry
from ..plugins.runner import enqueue_plugin_run, get_latest_plugin_run, get_plugin_run_by_id
from ..plugins.state import get_plugin_config, upsert_plugin_config
from ..services.audit import record_audit as _audit
from ..serializers.plugin_serializers import artifact_json, plugin_run_json, redact_storage_path

bp = Blueprint("plugins_api", __name__, url_prefix="/api")


def _plugin_run_json(run):
    return plugin_run_json(run)


def _redact_storage_path(storage_path: str | None) -> str | None:
    return redact_storage_path(storage_path)


def _artifact_json(artifact: PluginRunArtifact):
    return artifact_json(artifact)

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


def _allowed_import_paths() -> list[str]:
    paths = current_app.config.get("PLUGIN_IMPORT_PATHS", [])
    return [path for path in paths if isinstance(path, str) and path.strip()]


def _is_allowed_module_path(module_path: str) -> bool:
    configured_paths = _allowed_import_paths()
    if not configured_paths:
        return False
    return any(module_path == allowed or module_path.startswith(f"{allowed}.") for allowed in configured_paths)


def _infer_capabilities(plugin_cls: type[BasePlugin]) -> list[str]:
    capabilities = list(plugin_cls.capabilities or [])
    if capabilities:
        return capabilities
    if issubclass(plugin_cls, VulnerabilityFeedPlugin):
        return ["vulnerability_feed"]
    if issubclass(plugin_cls, ControlsImportPlugin):
        return ["controls_import"]
    return []


def _load_plugin_class(module_path: str, class_name: str):
    if not _is_allowed_module_path(module_path):
        allowed = ", ".join(_allowed_import_paths()) or "<none configured>"
        raise ValueError(f"module_path must be under configured PLUGIN_IMPORT_PATHS. Allowed: {allowed}")

    module = importlib.import_module(module_path)
    plugin_cls = getattr(module, class_name, None)
    if plugin_cls is None:
        raise ValueError(f"Class '{class_name}' was not found in module '{module_path}'")
    if not inspect.isclass(plugin_cls) or not issubclass(plugin_cls, BasePlugin):
        raise ValueError("Selected class must inherit from BasePlugin")
    if inspect.isabstract(plugin_cls):
        raise ValueError("Selected class is abstract and cannot be registered")

    validate_config_schema(plugin_cls.config_schema or {})
    return plugin_cls


def _plugin_introspection_payload(plugin_cls: type[BasePlugin], *, already_registered: bool):
    return {
        "plugin_id": plugin_cls.plugin_id,
        "display_name": plugin_cls.display_name,
        "version": plugin_cls.version,
        "capabilities": _infer_capabilities(plugin_cls),
        "config_schema": plugin_cls.config_schema,
        "already_registered": already_registered,
    }


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
                "capabilities": _infer_capabilities(plugin_cls),
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
        "capabilities": _infer_capabilities(plugin_cls),
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
@rate_limit("RATE_LIMIT_SENSITIVE_LIMIT", "RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", identifier="plugin_run")
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


@bp.get("/plugins/runs/<int:run_id>/artifacts")
@login_required
def list_plugin_run_artifacts(run_id: int):
    run = get_plugin_run_by_id(run_id)
    if not run:
        return jsonify({"error": "Plugin run not found"}), 404
    artifacts = PluginRunArtifact.query.filter_by(plugin_run_id=run_id).order_by(PluginRunArtifact.created_at.asc()).all()
    return jsonify([_artifact_json(item) for item in artifacts]), 200


@bp.get("/plugins/artifacts/<int:artifact_id>/download")
@login_required
def download_plugin_run_artifact(artifact_id: int):
    artifact = PluginRunArtifact.query.filter_by(id=artifact_id).first()
    if not artifact:
        return jsonify({"error": "Artifact not found"}), 404

    actor = getattr(request, "user", None)
    if not actor or actor.role not in {"Admin", "Analyst"}:
        return jsonify({"error": "Forbidden"}), 403

    return send_file(
        artifact.storage_path,
        mimetype=artifact.content_type or "application/octet-stream",
        as_attachment=True,
        download_name=_redact_storage_path(artifact.storage_path) or f"artifact-{artifact.id}",
    )


@bp.get("/plugins/import/sources")
@role_required("Admin")
def list_plugin_import_sources():
    return jsonify({"paths": _allowed_import_paths()})


@bp.post("/plugins/import/validate")
@role_required("Admin")
def validate_plugin_import():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "payload must be an object"}), 400
    module_path = str(payload.get("module_path") or "").strip()
    class_name = str(payload.get("class_name") or "").strip()
    if not module_path or not class_name:
        return jsonify({"error": "module_path and class_name are required"}), 400

    try:
        plugin_cls = _load_plugin_class(module_path, class_name)
    except (ImportError, ValueError, AttributeError) as exc:
        return jsonify({"error": str(exc)}), 400

    registry = _get_registry()
    already_registered = _get_plugin_class(registry, plugin_cls.plugin_id) is not None
    return jsonify(_plugin_introspection_payload(plugin_cls, already_registered=already_registered)), 200


@bp.post("/plugins/import/register")
@role_required("Admin")
def register_plugin_import():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "payload must be an object"}), 400

    module_path = str(payload.get("module_path") or "").strip()
    class_name = str(payload.get("class_name") or "").strip()
    config_payload = payload.get("config") or {}
    enabled = payload.get("enabled", True)
    if not module_path or not class_name:
        return jsonify({"error": "module_path and class_name are required"}), 400
    if not isinstance(config_payload, dict):
        return jsonify({"error": "config must be an object"}), 400
    if not isinstance(enabled, bool):
        return jsonify({"error": "enabled must be a boolean"}), 400

    try:
        plugin_cls = _load_plugin_class(module_path, class_name)
        prepared = prepare_plugin_config(config_payload, plugin_cls.config_schema)
    except (ImportError, ValueError, AttributeError) as exc:
        return jsonify({"error": str(exc)}), 400

    registry = _get_registry()
    already_registered = _get_plugin_class(registry, plugin_cls.plugin_id) is not None
    if not already_registered:
        try:
            registry.register(plugin_cls)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    updated = upsert_plugin_config(plugin_cls.plugin_id, prepared, enabled=enabled)
    _audit(
        "CREATE" if not already_registered else "UPDATE",
        "plugin_configs",
        updated.id,
        new_values=_plugin_config_json(updated, schema=plugin_cls.config_schema),
    )
    db.session.commit()

    return jsonify({
        "plugin": _plugin_introspection_payload(plugin_cls, already_registered=already_registered),
        "config": _plugin_config_json(updated, schema=plugin_cls.config_schema),
        "message": "Plugin imported successfully" if not already_registered else "Plugin updated successfully",
    }), 201 if not already_registered else 200
