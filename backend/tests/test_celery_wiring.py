"""The background-job pipeline was completely non-functional in Docker.

With CELERY_ENABLED=true (the compose default) every task was dropped:

1. `celery -A backend.celery_app:celery worker` imported only the module that
   defines the Celery instance. `backend.tasks` was never imported in the
   worker process, so its registry was empty and every message was answered
   with "Received unregistered task ... ignored and discarded".
2. The worker never called `create_app()`, so `ContextTask` was never
   installed and tasks that got past (1) died with "Working outside of
   application context" on their first database access.
3. celery-beat ran with no `beat_schedule` at all, so nothing recurring ever
   fired despite the UI exposing per-plugin schedules.

Plugin runs, async PDF rendering, notification scans and the retention purge
were all affected. These tests pin the wiring.
"""

from __future__ import annotations

import backend.tasks  # noqa: F401  (registers the tasks)
from backend.celery_app import BEAT_SCHEDULE, celery

EXPECTED_TASKS = {
    "uvt.run_plugin",
    "uvt.run_due_plugins",
    "uvt.notification_scan",
    "uvt.generate_report",
    "uvt.purge_old_data",
}


def test_all_tasks_are_registered():
    """Every task the app dispatches must be in the Celery registry."""
    missing = EXPECTED_TASKS - set(celery.tasks)
    assert not missing, f"tasks not registered with Celery: {sorted(missing)}"


def test_celery_app_includes_the_task_module():
    """`include` is what makes the *worker* process import backend.tasks.

    The web process imports task functions lazily at dispatch time, so
    dispatching worked while nothing consumed the messages.
    """
    assert "backend.tasks" in (celery.conf.include or []), (
        "backend.tasks must be in Celery's include list, or a worker started "
        "from this module has an empty task registry"
    )


def test_beat_schedule_is_populated():
    """celery-beat with no schedule is a no-op container."""
    assert BEAT_SCHEDULE, "celery-beat has nothing scheduled"
    for name, entry in BEAT_SCHEDULE.items():
        assert entry["task"] in EXPECTED_TASKS, f"{name} schedules unknown task {entry['task']}"
        assert entry.get("schedule") is not None, f"{name} has no schedule"


def test_worker_entrypoint_builds_the_flask_app(monkeypatch):
    """The module the worker loads must create the app and install ContextTask.

    Pointing the worker at backend.celery_app skips create_app(), so tasks run
    with no application context and every database access raises.
    """
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

    import importlib

    entry = importlib.import_module("backend.celery_worker")
    entry = importlib.reload(entry)

    assert hasattr(entry, "celery"), "worker entrypoint must expose `celery`"
    assert hasattr(entry, "flask_app"), "worker entrypoint must build the Flask app"
    # create_app() ran, so ContextTask is installed and bound to that app.
    assert entry.celery.Task.__name__ == "ContextTask"
    assert getattr(entry.celery, "_uvt_flask_app", None) is entry.flask_app


def test_context_task_is_installed_after_init(app):
    """Tasks must execute inside an application context."""
    assert getattr(celery, "_uvt_flask_app", None) is not None
    assert celery.Task.__name__ == "ContextTask"
