from datetime import timezone
from pathlib import Path

from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

import sqlalchemy.types as sa_types


class TZDateTime(sa_types.TypeDecorator):
    """A DateTime type that ensures UTC timezone-aware datetimes.

    On write, naive datetimes are assumed UTC and stored as-is.
    On read, naive datetimes (e.g. from SQLite) are tagged as UTC.
    """

    impl = sa_types.DateTime
    cache_ok = True

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value


db = SQLAlchemy()
migrate = Migrate()

MIGRATIONS_DIR = str(Path(__file__).resolve().parent.parent / "migrations")


def init_database(app):
    """Bind SQLAlchemy and Alembic to the app.

    Schema creation is *not* performed here — that belongs to Alembic, and
    ``backend.schema_guard`` verifies the result at boot.

    The hand-rolled column backfill that used to live in this module is gone.
    It only ever ran for SQLite, which is precisely why PostgreSQL deployments
    drifted silently while the test suite stayed green.
    """
    db.init_app(app)
    migrate.init_app(app, db, directory=MIGRATIONS_DIR, render_as_batch=True)


def create_all_for_tests(app):
    """Build the schema from model metadata, then stamp it at head.

    Test databases are in-memory and rebuilt for every test, so replaying the
    full revision history each time would dominate the suite's runtime.
    Stamping afterwards keeps the schema guard satisfied.

    ``backend/tests/test_migrations.py`` separately runs the real migrations
    and asserts they produce this same schema, so the shortcut cannot hide
    drift.
    """
    from flask_migrate import stamp

    with app.app_context():
        db.create_all()
        try:
            stamp()
        except Exception:  # pragma: no cover - best-effort in tests
            pass
