"""Celery entrypoint for the worker and beat processes.

    celery -A backend.celery_worker:celery worker
    celery -A backend.celery_worker:celery beat

Importing ``backend.celery_app`` directly is not enough. That module only
defines the Celery instance; the Flask application — and with it the database
binding, the plugin registry, and the ``ContextTask`` base class that wraps
each task in an app context — is created by ``create_app()``, which the worker
process otherwise never calls.

Pointing the worker at ``backend.celery_app:celery`` therefore produced tasks
that ran with no application context at all, and every one of them died on its
first database access with::

    RuntimeError: Working outside of application context.

Building the app here, in the module Celery loads, fixes that. It also gives
the worker the same config validation and schema guard the web process gets,
so a misconfigured worker fails loudly at startup instead of at task time.

This lives in its own module rather than in ``celery_app`` because
``create_app()`` imports ``init_celery`` from there — importing it the other
way round at module scope would be circular.
"""

from __future__ import annotations

from .uvt_app import create_app

flask_app = create_app()

# init_celery() ran inside create_app(): it bound the broker URLs, installed
# ContextTask, and stored the app on celery._uvt_flask_app.
celery = flask_app.extensions["celery"]

__all__ = ["celery", "flask_app"]
