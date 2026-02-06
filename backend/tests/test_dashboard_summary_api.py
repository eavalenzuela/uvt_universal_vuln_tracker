from datetime import datetime, timedelta

from backend.auth import create_user, generate_token
from backend.database import db
from backend.models import Vulnerability


def _auth_header(user):
    token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    return {"Authorization": f"Bearer {token}"}


def _create_admin(app):
    with app.app_context():
        user = create_user("dash_admin", "dash_admin@example.com", "secret", role="Admin")
        db.session.refresh(user)
        db.session.expunge(user)
        return user


def _seed_vulnerabilities(app, user_id):
    now = datetime.utcnow()
    with app.app_context():
        db.session.add_all([
            Vulnerability(
                title="Critical open",
                severity="Critical",
                status="Open",
                created_by=user_id,
                updated_at=now - timedelta(days=1),
            ),
            Vulnerability(
                title="High in progress",
                severity="High",
                status="In Progress",
                created_by=user_id,
                updated_at=now - timedelta(days=2),
            ),
            Vulnerability(
                title="Medium resolved",
                severity="Medium",
                status="Resolved",
                created_by=user_id,
                updated_at=now - timedelta(days=20),
            ),
        ])
        db.session.commit()


def test_dashboard_summary_aggregates_and_trends(app, client):
    admin = _create_admin(app)
    _seed_vulnerabilities(app, admin.id)

    resp = client.get(
        "/api/dashboard/summary?status=Open,In Progress&group_by=Status&range=Last 7 days",
        headers=_auth_header(admin),
    )

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["total"] == 2
    assert payload["by_severity"]["Critical"] == 1
    assert payload["by_severity"]["High"] == 1
    assert payload["group_by"] == "Status"
    assert payload["group_totals"]["Open"] == 1
    assert payload["group_totals"]["In Progress"] == 1
    assert len(payload["trend"]["buckets"]) >= 7
    assert sum(bucket["count"] for bucket in payload["trend"]["buckets"]) == 2


def test_list_vulnerabilities_supports_multi_value_filters(app, client):
    admin = _create_admin(app)
    _seed_vulnerabilities(app, admin.id)

    resp = client.get(
        "/api/vulnerabilities?status=Open,In Progress&severity=Critical,High&page_size=50",
        headers=_auth_header(admin),
    )

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["total"] == 2
    returned = {(item["severity"], item["status"]) for item in payload["items"]}
    assert returned == {("Critical", "Open"), ("High", "In Progress")}
