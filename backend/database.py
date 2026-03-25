from flask_sqlalchemy import SQLAlchemy

from sqlalchemy import inspect, text

db = SQLAlchemy()

# Column additions for SQLite databases that were created before these columns
# existed.  The keys are validated against a strict allowlist so the f-string
# interpolation in the ALTER TABLE below is safe.
_SQLITE_VULN_COLUMN_BACKFILL = {
    "attack_complexity": "VARCHAR(20) NOT NULL DEFAULT 'Not Defined'",
    "confidentiality_impact": "VARCHAR(20) NOT NULL DEFAULT 'Not Defined'",
    "integrity_impact": "VARCHAR(20) NOT NULL DEFAULT 'Not Defined'",
    "availability_impact": "VARCHAR(20) NOT NULL DEFAULT 'Not Defined'",
}

_ALLOWED_BACKFILL_COLUMNS = frozenset(_SQLITE_VULN_COLUMN_BACKFILL.keys())


def init_database(app):
    db.init_app(app)
    _ensure_sqlite_schema(app)


def _ensure_sqlite_schema(app):
    """Auto-create tables and backfill columns for SQLite dev databases.

    For PostgreSQL the schema should be managed externally (e.g. via a
    migration tool or ``db.create_all()`` in a one-off script).
    """
    with app.app_context():
        if not db.engine.url.drivername.startswith("sqlite"):
            return

        insp = inspect(db.engine)
        existing_tables = set(insp.get_table_names())

        if not existing_tables:
            db.create_all()
            return  # fresh database — nothing to backfill

        # Create any tables defined in models but missing from the DB.
        db.create_all()
        insp = inspect(db.engine)

        # Backfill columns that were added after initial schema.
        if "vulnerabilities" in insp.get_table_names():
            existing_cols = {c["name"] for c in insp.get_columns("vulnerabilities")}
            added = False
            for column, ddl in _SQLITE_VULN_COLUMN_BACKFILL.items():
                assert column in _ALLOWED_BACKFILL_COLUMNS, f"unexpected column: {column}"
                if column not in existing_cols:
                    db.session.execute(text(
                        f"ALTER TABLE vulnerabilities ADD COLUMN {column} {ddl}"
                    ))
                    added = True
            if added:
                db.session.commit()
