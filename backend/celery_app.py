"""Celery application factory.

Creates a Celery instance tied to the Flask app so that tasks run inside
an application context with access to the database and config.

Do **not** point the worker at this module. It defines the Celery instance but
not the Flask app, so tasks would run without an application context. Use
``backend.celery_worker`` instead::

    celery -A backend.celery_worker:celery worker --loglevel=info
    celery -A backend.celery_worker:celery beat --loglevel=info
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

# ``include`` is what makes the worker import backend.tasks.
#
# Without it the worker started with an empty task registry: the web process
# imports the task functions lazily at dispatch time
# (``from ..tasks import run_plugin_task``), so *sending* worked, but
# `celery -A backend.celery_app:celery worker` only ever imported this module.
# Every message was answered with "Received unregistered task of type
# 'uvt.run_plugin'. The message has been ignored and discarded." — so with
# CELERY_ENABLED=true (the compose default) plugin runs, async PDF rendering,
# notification scans and the retention purge were all dropped on the floor,
# leaving their rows stuck in "running"/"pending" forever.
celery = Celery("uvt", include=["backend.tasks"])

# Sensible defaults — overridden by init_celery() when the Flask app boots.
celery.config_from_object({
    "broker_url": "redis://localhost:6379/1",
    "result_backend": "redis://localhost:6379/2",
    "task_serializer": "json",
    "result_serializer": "json",
    "accept_content": ["json"],
    "task_track_started": True,
    "result_expires": 86400,
    "task_acks_late": True,
    "worker_prefetch_multiplier": 1,
})

# Recurring work. celery-beat previously ran with no schedule at all, so the
# service was a no-op: nothing was ever scheduled, and the documented
# "scheduled execution" of the retention purge and notification scan never
# happened. Times are UTC.
BEAT_SCHEDULE = {
    "notification-scan": {
        "task": "uvt.notification_scan",
        # Every 15 minutes: SLA breaches and watched-vulnerability updates
        # should surface within a working session, not once a day.
        "schedule": crontab(minute="*/15"),
    },
    "run-due-plugins": {
        "task": "uvt.run_due_plugins",
        # Hourly; each plugin's own interval_minutes/schedule_cron decides
        # whether it is actually due.
        "schedule": crontab(minute=5),
    },
    "purge-old-data": {
        "task": "uvt.purge_old_data",
        # Nightly, off-peak. Retention windows are measured in days, so more
        # frequent runs buy nothing and just hold locks.
        "schedule": crontab(hour=3, minute=30),
    },
}
celery.conf.beat_schedule = BEAT_SCHEDULE


def init_celery(app) -> Celery:
    """Bind Celery to a Flask app so tasks execute inside app context.

    Stores the active Flask app on ``celery._uvt_flask_app`` so ContextTask
    looks it up at call time rather than capturing whichever app was current
    when the task class was first defined. Otherwise tests that create
    multiple Flask apps (per-test fixtures) all dispatch into the first
    app's app_context and miss the per-test in-memory SQLite DB.
    """
    celery.conf.update(
        broker_url=app.config["CELERY_BROKER_URL"],
        result_backend=app.config["CELERY_RESULT_BACKEND"],
        task_time_limit=app.config["CELERY_TASK_TIMEOUT"],
        task_soft_time_limit=app.config["CELERY_TASK_SOFT_TIMEOUT"],
        # Recycle each worker child after N tasks. Necessary because
        # WeasyPrint+Matplotlib accumulate memory across PDF renders.
        worker_max_tasks_per_child=app.config.get("CELERY_WORKER_MAX_TASKS_PER_CHILD", 100),
    )
    celery._uvt_flask_app = app  # type: ignore[attr-defined]

    class ContextTask(celery.Task):
        """Wraps task execution in the currently-bound Flask app context."""

        def __call__(self, *args, **kwargs):
            active_app = getattr(celery, "_uvt_flask_app", app)
            with active_app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    app.extensions["celery"] = celery
    return celery
