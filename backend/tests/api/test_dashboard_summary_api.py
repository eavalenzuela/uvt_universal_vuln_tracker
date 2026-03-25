from datetime import datetime, timedelta

from backend.auth import create_user, generate_token
from backend.database import db
from backend.models import Product, ProductVersion, Vulnerability, VulnerabilityVersion


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




def test_list_vulnerabilities_supports_severity_in_alias(app, client):
    admin = _create_admin(app)
    _seed_vulnerabilities(app, admin.id)

    resp = client.get(
        "/api/vulnerabilities?status=Open,In Progress&severity_in=Critical,High&page_size=50",
        headers=_auth_header(admin),
    )

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["total"] == 2
    returned = {(item["severity"], item["status"]) for item in payload["items"]}
    assert returned == {("Critical", "Open"), ("High", "In Progress")}


def test_list_vulnerabilities_multi_severity_pagination_has_consistent_items_and_total(app, client):
    admin = _create_admin(app)
    now = datetime.utcnow()

    with app.app_context():
        db.session.add_all(
            [
                Vulnerability(
                    title="Critical newest",
                    severity="Critical",
                    status="Open",
                    created_by=admin.id,
                    updated_at=now - timedelta(minutes=1),
                ),
                Vulnerability(
                    title="High newer",
                    severity="High",
                    status="Open",
                    created_by=admin.id,
                    updated_at=now - timedelta(minutes=2),
                ),
                Vulnerability(
                    title="Critical older",
                    severity="Critical",
                    status="Open",
                    created_by=admin.id,
                    updated_at=now - timedelta(minutes=3),
                ),
                Vulnerability(
                    title="High oldest",
                    severity="High",
                    status="Open",
                    created_by=admin.id,
                    updated_at=now - timedelta(minutes=4),
                ),
                Vulnerability(
                    title="Medium ignored",
                    severity="Medium",
                    status="Open",
                    created_by=admin.id,
                    updated_at=now - timedelta(minutes=5),
                ),
            ]
        )
        db.session.commit()

    page_1 = client.get(
        "/api/vulnerabilities?status=Open&severity_in=Critical,High&page=1&page_size=2&sort=updated_at&order=desc",
        headers=_auth_header(admin),
    )
    page_2 = client.get(
        "/api/vulnerabilities?status=Open&severity_in=Critical,High&page=2&page_size=2&sort=updated_at&order=desc",
        headers=_auth_header(admin),
    )

    assert page_1.status_code == 200
    assert page_2.status_code == 200

    payload_1 = page_1.get_json()
    payload_2 = page_2.get_json()

    assert payload_1["total"] == 4
    assert payload_2["total"] == 4
    assert [item["title"] for item in payload_1["items"]] == ["Critical newest", "High newer"]
    assert [item["title"] for item in payload_2["items"]] == ["Critical older", "High oldest"]

def test_risk_trends_groups_by_product_version_and_bucket(app, client):
    admin = _create_admin(app)
    now = datetime.utcnow()

    product_id = None
    with app.app_context():
        product = Product(name="Payments", created_by=admin.id)
        db.session.add(product)
        db.session.flush()
        product_id = product.id

        pv = ProductVersion(product_id=product.id, version="1.0")
        db.session.add(pv)
        db.session.flush()

        vulns = [
            Vulnerability(
                title="Critical open overdue",
                severity="Critical",
                status="Open",
                sla_due_at=now - timedelta(days=1),
                created_by=admin.id,
                updated_at=now - timedelta(days=1),
            ),
            Vulnerability(
                title="High in progress",
                severity="High",
                status="In Progress",
                created_by=admin.id,
                updated_at=now - timedelta(days=1),
            ),
            Vulnerability(
                title="Low closed",
                severity="Low",
                status="Closed",
                created_by=admin.id,
                updated_at=now - timedelta(days=1),
            ),
        ]
        db.session.add_all(vulns)
        db.session.flush()

        for vuln in vulns:
            db.session.add(VulnerabilityVersion(vulnerability_id=vuln.id, product_version_id=pv.id, affected=True))
        db.session.commit()

    resp = client.get(
        f"/api/reports/risk-trends?bucket=day&range=Last 7 days&product_ids={product_id}",
        headers=_auth_header(admin),
    )

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["bucket"] == "day"
    assert len(payload["items"]) >= 1
    item = payload["items"][0]
    assert item["product_name"] == "Payments"
    assert item["product_version"] == "1.0"
    assert item["open_critical_count"] == 1
    assert item["overdue_sla_count"] == 1
    assert item["weighted_risk_score"] == 17
    assert payload["top_risk_products"][0]["weighted_risk_score"] == 17
