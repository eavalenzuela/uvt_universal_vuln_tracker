"""Celery task definitions for background operations.

Each task runs inside a Flask application context (see celery_app.py).
Tasks are imported automatically when the Celery worker starts.
"""

from __future__ import annotations

import logging
from collections.abc import Sized
from datetime import datetime, timezone
from typing import Any

from .celery_app import celery
from .database import db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Plugin execution
# ---------------------------------------------------------------------------

@celery.task(bind=True, name="uvt.run_plugin", max_retries=0)
def run_plugin_task(self, *, run_id: int, plugin_id: str, config: dict[str, Any] | None = None):
    """Execute a single plugin run in the background."""
    from .plugins.runner import get_plugin_run_by_id
    from .plugins.state import save_plugin_run_result

    run = get_plugin_run_by_id(run_id)
    if not run:
        logger.error("Plugin run %s not found", run_id)
        return {"status": "error", "detail": "Plugin run not found"}

    # Store Celery task ID on the run record for status lookups
    if not run.celery_task_id:
        run.celery_task_id = self.request.id
        db.session.commit()

    from flask import current_app
    registry = current_app.extensions.get("plugin_registry")
    if not registry:
        logger.error("Plugin registry not available")
        save_plugin_run_result(run, status="failed", finished_at=datetime.now(timezone.utc), error="Plugin registry not available")
        return {"status": "failed", "detail": "Plugin registry not available"}

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

        save_plugin_run_result(
            run, status="success",
            finished_at=datetime.now(timezone.utc),
            stats=stats, artifact_descriptors=artifacts,
        )
        return {"status": "success", "run_id": run.id}

    except Exception as exc:
        logger.exception("Plugin run failed for %s", plugin_id)
        save_plugin_run_result(
            run, status="failed",
            finished_at=datetime.now(timezone.utc),
            error=str(exc),
        )
        return {"status": "failed", "run_id": run.id, "error": str(exc)}


# ---------------------------------------------------------------------------
# Notification scan
# ---------------------------------------------------------------------------

@celery.task(bind=True, name="uvt.notification_scan", max_retries=0)
def notification_scan_task(self, *, dry_run: bool = False):
    """Run the scheduled notification scan in the background."""
    from .services.notification_rules import run_scheduled_notification_scan

    logs = run_scheduled_notification_scan(dry_run=dry_run)
    db.session.commit()
    return {"status": "success", "delivery_attempts": len(logs)}


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

@celery.task(bind=True, name="uvt.generate_report", max_retries=0)
def generate_report_task(
    self,
    *,
    report_type: str,
    export_format: str,
    filters: dict | None = None,
    user_id: int | None = None,
):
    """Generate a report artifact in the background."""
    from .api.report_exports import _build_export_artifact_async

    try:
        artifact = _build_export_artifact_async(
            report_type=report_type,
            export_format=export_format,
            filters=filters,
            user_id=user_id,
        )
        return {"status": "success", "artifact_id": artifact.id}
    except Exception as exc:
        logger.exception("Report generation failed")
        return {"status": "failed", "error": str(exc)}
