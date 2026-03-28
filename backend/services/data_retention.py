"""Data retention — purge old records based on configured retention policies."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

from flask import current_app

from ..database import db
from ..models import AuditLog, NotificationDeliveryLog, PluginRun, ReportArtifact

logger = logging.getLogger(__name__)


def purge_old_records(*, dry_run: bool = False) -> dict[str, int]:
    """Delete records older than the configured retention periods.

    Returns a dict mapping table names to the number of rows deleted (or
    that would be deleted in dry_run mode).
    """
    results: dict[str, int] = {}
    now = datetime.now(timezone.utc)

    # Audit logs
    days = current_app.config.get("RETENTION_AUDIT_LOG_DAYS", 365)
    if days > 0:
        cutoff = now - timedelta(days=days)
        count = _purge_table(AuditLog, AuditLog.created_at, cutoff, dry_run=dry_run)
        results["audit_logs"] = count

    # Notification delivery logs
    days = current_app.config.get("RETENTION_NOTIFICATION_LOG_DAYS", 90)
    if days > 0:
        cutoff = now - timedelta(days=days)
        count = _purge_table(NotificationDeliveryLog, NotificationDeliveryLog.created_at, cutoff, dry_run=dry_run)
        results["notification_delivery_logs"] = count

    # Plugin runs (cascades to artifacts)
    days = current_app.config.get("RETENTION_PLUGIN_RUN_DAYS", 90)
    if days > 0:
        cutoff = now - timedelta(days=days)
        count = _purge_table(PluginRun, PluginRun.started_at, cutoff, dry_run=dry_run)
        results["plugin_runs"] = count

    # Report artifacts (also delete files on disk)
    days = current_app.config.get("RETENTION_REPORT_ARTIFACT_DAYS", 180)
    if days > 0:
        cutoff = now - timedelta(days=days)
        count = _purge_report_artifacts(cutoff, dry_run=dry_run)
        results["report_artifacts"] = count

    if not dry_run:
        db.session.commit()

    return results


def _purge_table(model, date_column, cutoff, *, dry_run: bool) -> int:
    """Delete rows from a model where date_column < cutoff."""
    query = model.query.filter(date_column < cutoff)
    count = query.count()
    if count and not dry_run:
        query.delete(synchronize_session=False)
        logger.info("Purged %d rows from %s (cutoff: %s)", count, model.__tablename__, cutoff.isoformat())
    return count


def _purge_report_artifacts(cutoff, *, dry_run: bool) -> int:
    """Delete old report artifacts and their files on disk."""
    artifacts = ReportArtifact.query.filter(ReportArtifact.created_at < cutoff).all()
    count = len(artifacts)
    if not count:
        return 0
    if dry_run:
        return count
    for artifact in artifacts:
        if artifact.storage_path and os.path.isfile(artifact.storage_path):
            try:
                os.remove(artifact.storage_path)
            except OSError:
                logger.warning("Could not delete artifact file: %s", artifact.storage_path)
        db.session.delete(artifact)
    logger.info("Purged %d report artifacts (cutoff: %s)", count, cutoff.isoformat())
    return count
