from datetime import timezone

from flask_sqlalchemy import SQLAlchemy

from sqlalchemy import inspect, text
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

# Columns to backfill on SQLite databases created before these existed.
# Each tuple: (column_name, sql_type, default_value)
_SQLITE_VULN_COLUMN_BACKFILL = [
    ("attack_complexity", "VARCHAR(20) NOT NULL DEFAULT 'Not Defined'"),
    ("confidentiality_impact", "VARCHAR(20) NOT NULL DEFAULT 'Not Defined'"),
    ("integrity_impact", "VARCHAR(20) NOT NULL DEFAULT 'Not Defined'"),
    ("availability_impact", "VARCHAR(20) NOT NULL DEFAULT 'Not Defined'"),
    # v2.23.0: CISA KEV flag + remediation timestamp.
    ("known_exploited", "BOOLEAN NOT NULL DEFAULT 0"),
    ("kev_date_added", "DATE"),
    ("resolved_at", "DATETIME"),
]

# F17 Slice 2: report artifact lifecycle columns.
_SQLITE_REPORT_ARTIFACT_BACKFILL = [
    ("status", "VARCHAR(16) NOT NULL DEFAULT 'ready'"),
    ("error", "TEXT"),
    ("celery_task_id", "VARCHAR(64)"),
]

# F3: email verification. Existing users predate the feature and are treated as
# already verified (DEFAULT 1) so backfilling never locks anyone out.
_SQLITE_USER_COLUMN_BACKFILL = [
    ("email_verified", "BOOLEAN NOT NULL DEFAULT 1"),
]

# v2.23.0: raw webhook signing secret. NULL for pre-existing endpoints, which
# keep legacy hash-keyed HMAC verification until their secret is rotated.
_SQLITE_WEBHOOK_ENDPOINT_BACKFILL = [
    ("secret", "VARCHAR(128)"),
]


def init_database(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()
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
        added = False
        if "vulnerabilities" in insp.get_table_names():
            existing_cols = {c["name"] for c in insp.get_columns("vulnerabilities")}
            for col_name, col_def in _SQLITE_VULN_COLUMN_BACKFILL:
                if col_name not in existing_cols:
                    db.session.execute(
                        text(f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_def}")
                    )
                    added = True

        if "users" in insp.get_table_names():
            existing_cols = {c["name"] for c in insp.get_columns("users")}
            for col_name, col_def in _SQLITE_USER_COLUMN_BACKFILL:
                if col_name not in existing_cols:
                    db.session.execute(
                        text(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
                    )
                    added = True

        if "report_artifacts" in insp.get_table_names():
            existing_cols = {c["name"] for c in insp.get_columns("report_artifacts")}
            for col_name, col_def in _SQLITE_REPORT_ARTIFACT_BACKFILL:
                if col_name not in existing_cols:
                    db.session.execute(
                        text(f"ALTER TABLE report_artifacts ADD COLUMN {col_name} {col_def}")
                    )
                    added = True
            # storage_path was NOT NULL pre-Slice-2; SQLite ALTER cannot drop NOT NULL,
            # but new artifacts use INSERT-then-UPDATE so existing rows remain valid.

        if "webhook_endpoints" in insp.get_table_names():
            existing_cols = {c["name"] for c in insp.get_columns("webhook_endpoints")}
            for col_name, col_def in _SQLITE_WEBHOOK_ENDPOINT_BACKFILL:
                if col_name not in existing_cols:
                    db.session.execute(
                        text(f"ALTER TABLE webhook_endpoints ADD COLUMN {col_name} {col_def}")
                    )
                    added = True

        if added:
            db.session.commit()
