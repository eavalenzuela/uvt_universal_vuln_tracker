"""Startup schema verification.

Historically UVT called ``db.create_all()`` at boot and nothing else.
``create_all()`` creates *missing tables* but never adds a column to a table
that already exists, so any release that added a column left existing
deployments running against a schema the ORM no longer matched. The app booted
happily, reported healthy, and then returned 500 the moment a user opened a
page that selected the new column.

This module makes that state impossible to reach silently:

* **Fresh database** — no tables at all — is migrated to head automatically.
* **Un-versioned database** — tables present, no ``alembic_version`` row —
  is refused, because we cannot know which revisions it already has.
* **Behind head** — refused, naming the pending revisions.
* **Model/migration drift** — refused, naming the offending tables. This
  catches a model change that shipped without a revision.

A refused schema does not crash the process: the app starts, ``/api/health``
reports ``degraded`` with the reason, and every other API route returns 503.
That keeps the container inspectable instead of crash-looping, and makes the
failure legible to an operator instead of surfacing as a random 500.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from flask import jsonify, request
from sqlalchemy import inspect

logger = logging.getLogger(__name__)

MIGRATIONS_HEALTH_PATHS = frozenset({"/api/health", "/metrics"})


@dataclass
class SchemaStatus:
    ok: bool = True
    state: str = "ok"          # ok | fresh | unversioned | behind | drifted | error
    detail: str = ""
    pending: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        data = {"state": self.state, "ok": self.ok}
        if self.detail:
            data["detail"] = self.detail
        if self.pending:
            data["pending_revisions"] = self.pending
        return data


def _script_directory():
    from flask import current_app
    from flask_migrate import Migrate  # noqa: F401  (ensures extension import)
    from alembic.script import ScriptDirectory

    migrate = current_app.extensions["migrate"]
    return ScriptDirectory.from_config(migrate.migrate.get_config())


def _current_revision(connection) -> str | None:
    from alembic.runtime.migration import MigrationContext

    return MigrationContext.configure(connection).get_current_revision()


def _metadata_drift(connection) -> list[str]:
    """Return human-readable descriptions of model/database differences.

    Uses Alembic's own comparison so the check matches what
    ``flask db revision --autogenerate`` would produce.
    """
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext

    from .database import db

    context = MigrationContext.configure(
        connection,
        opts={"compare_type": True, "compare_server_default": True},
    )
    diffs = compare_metadata(context, db.metadata)

    described: list[str] = []
    for diff in diffs:
        # Entries are either a tuple or a list of tuples (for multi-part changes).
        for entry in (diff if isinstance(diff, list) else [diff]):
            if not isinstance(entry, tuple) or not entry:
                continue
            kind = entry[0]
            if kind in ("add_column", "remove_column"):
                described.append(f"{kind}: {entry[2]}.{entry[3].name}")
            elif kind in ("add_table", "remove_table"):
                described.append(f"{kind}: {entry[1].name}")
            elif kind in ("modify_type", "modify_nullable", "modify_default"):
                described.append(f"{kind}: {entry[2]}.{entry[3]}")
            else:
                described.append(str(kind))
    return described


def verify_schema(app, *, auto_upgrade_fresh: bool = True) -> SchemaStatus:
    """Inspect the database and return its migration status."""
    from flask_migrate import upgrade as alembic_upgrade

    from .database import db

    with app.app_context():
        try:
            script = _script_directory()
            head = script.get_current_head()

            # No revisions on disk at all. Only reachable while authoring the
            # first migration; treat it as "nothing to verify" rather than
            # blocking, so `flask db revision --autogenerate` can run.
            if head is None:
                return SchemaStatus(
                    ok=False, state="fresh",
                    detail="No migrations found. Generate one with 'flask db revision --autogenerate'.",
                )

            with db.engine.connect() as connection:
                tables = set(inspect(connection).get_table_names())
                app_tables = tables - {"alembic_version"}
                current = _current_revision(connection)

            # --- fresh database -------------------------------------------------
            if not app_tables:
                if not auto_upgrade_fresh:
                    return SchemaStatus(
                        ok=False, state="fresh",
                        detail="Database is empty. Run 'flask db upgrade' to create the schema.",
                    )
                logger.info("Empty database detected — applying migrations to %s", head)
                alembic_upgrade()
                return SchemaStatus(state="ok", detail=f"initialized at {head}")

            # --- tables but no alembic_version ---------------------------------
            if current is None:
                return SchemaStatus(
                    ok=False, state="unversioned",
                    detail=(
                        "Database has tables but no Alembic revision, so its schema version is "
                        "unknown. If it matches the current models, run "
                        f"'flask db stamp {head}'. Otherwise migrate or recreate it."
                    ),
                )

            # --- behind head ----------------------------------------------------
            if current != head:
                pending = [
                    rev.revision
                    for rev in script.iterate_revisions(head, current)
                    if rev.revision != current
                ]
                return SchemaStatus(
                    ok=False, state="behind", pending=pending,
                    detail=(
                        f"Database is at revision {current}, models expect {head}. "
                        "Run 'flask db upgrade'."
                    ),
                )

            # --- version matches; verify the actual columns ---------------------
            with db.engine.connect() as connection:
                drift = _metadata_drift(connection)
            if drift:
                return SchemaStatus(
                    ok=False, state="drifted", pending=drift,
                    detail=(
                        "Database is at the expected revision but does not match the models. "
                        "A model change probably shipped without a migration."
                    ),
                )

            return SchemaStatus(state="ok", detail=head or "")

        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Schema verification failed")
            return SchemaStatus(ok=False, state="error", detail=str(exc))


def install_schema_guard(app, status: SchemaStatus) -> None:
    """Store the status and, when unhealthy, fail API requests loudly."""
    app.config["SCHEMA_STATUS"] = status

    if status.ok:
        logger.info("Schema check passed (%s)", status.detail or "head")
        return

    logger.error("SCHEMA CHECK FAILED [%s]: %s", status.state, status.detail)
    for item in status.pending:
        logger.error("  pending: %s", item)

    @app.before_request
    def _block_on_bad_schema():
        if request.path in MIGRATIONS_HEALTH_PATHS or request.method == "OPTIONS":
            return None
        if not request.path.startswith("/api/"):
            return None
        response = jsonify({
            "error": "Database schema is out of date",
            "detail": status.detail,
            "state": status.state,
        })
        response.status_code = 503
        response.headers["Retry-After"] = "30"
        return response
