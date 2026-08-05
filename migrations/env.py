"""Alembic environment for UVT.

Wired to the Flask app factory via Flask-Migrate, so ``flask db upgrade`` and
``flask db revision --autogenerate`` both see the same metadata the running app
uses.

Autogenerate is configured with ``compare_type`` and ``compare_server_default``
so column type changes are caught too — ``backend/tests/test_migrations.py``
asserts that models and migrations never diverge, and those flags are what make
that assertion meaningful.
"""

from __future__ import annotations

import logging
from logging.config import fileConfig

from alembic import context
from flask import current_app

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)
logger = logging.getLogger("alembic.env")


def get_engine():
    return current_app.extensions["migrate"].db.engine


def get_engine_url() -> str:
    # Escape % so ConfigParser interpolation doesn't choke on URL-encoded creds.
    return get_engine().url.render_as_string(hide_password=False).replace("%", "%%")


config.set_main_option("sqlalchemy.url", get_engine_url())
target_metadata = current_app.extensions["migrate"].db.metadata


def _render_item(type_, obj, autogen_context):
    """Emit ``backend.database.TZDateTime`` by name in generated revisions."""
    if type_ == "type" and obj.__class__.__name__ == "TZDateTime":
        autogen_context.imports.add("import backend.database")
        return "backend.database.TZDateTime()"
    return False


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        compare_server_default=True,
        render_item=_render_item,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = get_engine()

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            render_item=_render_item,
            # SQLite cannot ALTER most things in place; batch mode rewrites the
            # table instead, so the same revision runs on SQLite and PostgreSQL.
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
