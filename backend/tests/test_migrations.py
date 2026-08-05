"""The guard that keeps schema drift from ever shipping again.

UVT used to build its schema with ``db.create_all()``, which creates missing
tables but never adds a column to an existing one. Every release that added a
column therefore left upgraded deployments running against a schema the ORM no
longer matched — the app booted, reported healthy, and 500'd on the first page
that selected the new column. The test suite could not catch it, because tests
ran ``create_all()`` against a fresh in-memory database every time.

These tests close that gap:

``test_migrations_match_models`` is the important one. It runs the real
revision history against an empty database and asserts Alembic finds nothing
left to generate. Change a model without writing a migration and this fails.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from flask_migrate import downgrade, upgrade
from sqlalchemy import inspect

from backend.database import db
from backend.uvt_app import create_app


@pytest.fixture()
def migrated_app(monkeypatch):
    """An app whose database was built by running the migrations."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{path}")
    monkeypatch.setenv("FLASK_ENV", "testing")
    # Let the schema guard apply the migrations itself — that is the code path
    # a real first boot takes.
    monkeypatch.setenv("DB_AUTO_UPGRADE_FRESH", "true")
    app = create_app()
    app.config.update(TESTING=True)
    try:
        yield app
    finally:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
        os.unlink(path)


def _diff_against_models(app) -> list:
    with app.app_context():
        with db.engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={"compare_type": True, "compare_server_default": True},
            )
            return compare_metadata(context, db.metadata)


def test_migrations_match_models(migrated_app):
    """Running every migration must reproduce the models exactly.

    A failure here means a model changed without a matching revision. Fix it
    with::

        flask db revision --autogenerate -m "describe the change"
    """
    diff = _diff_against_models(migrated_app)
    assert diff == [], (
        "Database schema built from migrations does not match the models.\n"
        "Generate a revision with:\n"
        "  flask db revision --autogenerate -m \"<describe the change>\"\n\n"
        f"Differences: {diff}"
    )


def test_schema_guard_reports_ok_after_migrating(migrated_app):
    status = migrated_app.config["SCHEMA_STATUS"]
    assert status.ok, f"schema guard rejected a freshly migrated database: {status.detail}"
    assert status.state == "ok"


def test_migrated_schema_has_expected_tables(migrated_app):
    """Spot-check that the baseline actually created the domain tables."""
    with migrated_app.app_context():
        tables = set(inspect(db.engine).get_table_names())

    for expected in ("users", "vulnerabilities", "products", "teams",
                     "webhook_endpoints", "alembic_version"):
        assert expected in tables, f"migrations did not create {expected!r}"


def test_columns_added_in_v2_23_are_present(migrated_app):
    """Regression test for the exact drift this work was about.

    These four columns existed in the models but not in upgraded PostgreSQL
    databases, which is what made /api/vulnerabilities return 500.
    """
    with migrated_app.app_context():
        insp = inspect(db.engine)
        vuln_cols = {c["name"] for c in insp.get_columns("vulnerabilities")}

    for column in ("known_exploited", "kev_date_added", "resolved_at"):
        assert column in vuln_cols, f"vulnerabilities.{column} missing after migration"


def test_migrations_downgrade_cleanly(migrated_app):
    """The history must be reversible, so a bad deploy can be rolled back."""
    with migrated_app.app_context():
        downgrade(revision="base")
        remaining = set(inspect(db.engine).get_table_names()) - {"alembic_version"}
        assert remaining == set(), f"downgrade left tables behind: {sorted(remaining)}"
        # Leave the database usable for teardown.
        upgrade()
