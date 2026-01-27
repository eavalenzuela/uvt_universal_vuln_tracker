from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import inspect, text

db = SQLAlchemy()
migrate = Migrate()

def init_database(app):
    db.init_app(app)
    migrate.init_app(app, db)
    ensure_sqlite_schema(app)

def ensure_sqlite_schema(app):
    with app.app_context():
        if not db.engine.url.drivername.startswith("sqlite"):
            return

        inspector = inspect(db.engine)
        if not inspector.get_table_names():
            db.create_all()
            inspector = inspect(db.engine)

        if "vulnerabilities" not in inspector.get_table_names():
            db.create_all()
            inspector = inspect(db.engine)

        if "vulnerabilities" in inspector.get_table_names():
            existing_columns = {col["name"] for col in inspector.get_columns("vulnerabilities")}
            column_definitions = {
                "attack_complexity": "VARCHAR(20) NOT NULL DEFAULT 'Not Defined'",
                "confidentiality_impact": "VARCHAR(20) NOT NULL DEFAULT 'Not Defined'",
                "integrity_impact": "VARCHAR(20) NOT NULL DEFAULT 'Not Defined'",
                "availability_impact": "VARCHAR(20) NOT NULL DEFAULT 'Not Defined'",
            }

            for column, ddl in column_definitions.items():
                if column not in existing_columns:
                    db.session.execute(text(
                        f"ALTER TABLE vulnerabilities ADD COLUMN {column} {ddl}"
                    ))

            if any(column not in existing_columns for column in column_definitions):
                db.session.commit()
