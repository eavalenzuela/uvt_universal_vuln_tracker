import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.auth import create_user, generate_token, hash_password
from backend.database import db
from backend.models import Product, ProductVersion, User, Vulnerability
from backend.rate_limiter import clear_rate_limit_state
from backend.uvt_app import create_app


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("ALLOW_PUBLIC_REGISTRATION", "true")
    monkeypatch.setenv("FLASK_ENV", "testing")
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


@pytest.fixture()
def user_factory(app):
    created = {"count": 0}

    def _create(*, role="Analyst", is_active=True, username=None, email=None, password="pass123"):
        created["count"] += 1
        suffix = created["count"]
        final_username = username or f"user_{role.lower()}_{suffix}"
        final_email = email or f"{final_username}@example.com"
        with app.app_context():
            user = User(
                username=final_username,
                email=final_email,
                password_hash=hash_password(password),
                role=role,
                is_active=is_active,
            )
            db.session.add(user)
            db.session.commit()
            db.session.refresh(user)
            db.session.expunge(user)
            return user

    return _create


@pytest.fixture()
def admin_user(app):
    with app.app_context():
        user = create_user("admin", "admin@example.com", "secret-pass-12", role="Admin")
        db.session.refresh(user)
        db.session.expunge(user)
        return user


@pytest.fixture()
def auth_header():
    def _for(user):
        token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
        return {"Authorization": f"Bearer {token}"}

    return _for


@pytest.fixture()
def sample_product_version(app, admin_user):
    with app.app_context():
        product = Product(name="Widget", description="Representative test product", created_by=admin_user.id)
        db.session.add(product)
        db.session.flush()

        version = ProductVersion(product_id=product.id, version="1.0.0")
        db.session.add(version)
        db.session.commit()
        db.session.refresh(product)
        db.session.refresh(version)
        db.session.expunge(product)
        db.session.expunge(version)
        return product, version


@pytest.fixture()
def sample_vulnerabilities(app, admin_user):
    now = datetime.now(timezone.utc)
    with app.app_context():
        vulns = [
            Vulnerability(
                cve_id="CVE-2026-3001",
                title="Critical Open Vulnerability",
                severity="Critical",
                status="Open",
                assigned_to=admin_user.id,
                created_by=admin_user.id,
                updated_at=now - timedelta(days=1),
            ),
            Vulnerability(
                cve_id="CVE-2026-3002",
                title="High In Progress Vulnerability",
                severity="High",
                status="In Progress",
                created_by=admin_user.id,
                updated_at=now - timedelta(days=2),
            ),
            Vulnerability(
                cve_id="CVE-2026-3003",
                title="Medium Resolved Vulnerability",
                severity="Medium",
                status="Resolved",
                created_by=admin_user.id,
                updated_at=now - timedelta(days=20),
            ),
        ]
        db.session.add_all(vulns)
        db.session.commit()
        for vuln in vulns:
            db.session.refresh(vuln)
            db.session.expunge(vuln)
        return vulns
