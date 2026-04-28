"""Celery application factory.

Creates a Celery instance tied to the Flask app so that tasks run inside
an application context with access to the database and config.

Usage (worker)::

    celery -A backend.celery_app:celery worker --loglevel=info

Usage (beat scheduler)::

    celery -A backend.celery_app:celery beat --loglevel=info
"""

from __future__ import annotations

from celery import Celery

celery = Celery("uvt")

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
