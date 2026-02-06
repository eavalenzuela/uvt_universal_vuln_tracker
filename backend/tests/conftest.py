import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.uvt_app import create_app
from backend.database import db
from backend.rate_limiter import clear_rate_limit_state


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("ALLOW_PUBLIC_REGISTRATION", "true")
    app = create_app()
    app.config.update(TESTING=True)

    with app.app_context():
        db.create_all()
        clear_rate_limit_state(app)
        yield app
        db.session.remove()
        clear_rate_limit_state(app)
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()
