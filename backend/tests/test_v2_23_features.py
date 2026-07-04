"""Tests for the v2.23.0 pass: SSRF guard, plugin path confinement, short-lived
impersonation tokens, password policy, feed-ingest fidelity, CISA KEV,
watcher notifications, audit CSV export, remediation metrics, and
component search."""

import json
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest

from backend.auth import PasswordTooWeakError, validate_password
from backend.database import db
from backend.models import Notification, UserPreferences, Vulnerability, VulnerabilityWatcher
from backend.models.products import SoftwareComponent
from backend.plugins.base import resolve_plugin_file_path
from backend.plugins.vuln_feed_plugins import KevVulnerabilityFeedPlugin
from backend.plugins.vuln_feeds.kev import map_kev_record
from backend.plugins.vuln_feeds.nvd import map_nvd_record
from backend.services import notification_rules
from backend.services.notification_rules import NotificationEvent, notify_watchers_for_event
from backend.services.url_guard import UnsafeOutboundUrlError, validate_outbound_url
from backend.services.vuln_ingest import NormalizedVuln, upsert_vulnerability


# ---------------------------------------------------------------------------
# URL guard (SSRF)
# ---------------------------------------------------------------------------

def test_url_guard_allows_public_hostnames(app):
    with app.app_context():
        assert validate_outbound_url("https://hooks.slack.com/services/x") == "https://hooks.slack.com/services/x"
        assert validate_outbound_url("http://example.invalid/hook") == "http://example.invalid/hook"


@pytest.mark.parametrize("url", [
    "https://127.0.0.1/hook",
    "https://10.0.0.5/hook",
    "https://192.168.1.1:8080/hook",
    "https://169.254.169.254/latest/meta-data/",
    "https://[::1]/hook",
    "https://localhost/hook",
    "https://foo.localhost/hook",
    "https://intranet/hook",
    "https://svc.internal/hook",
])
def test_url_guard_blocks_private_targets(app, url):
    with app.app_context():
        with pytest.raises(UnsafeOutboundUrlError):
            validate_outbound_url(url)


@pytest.mark.parametrize("url", ["ftp://example.com/x", "file:///etc/passwd", "not a url", ""])
def test_url_guard_blocks_bad_schemes(app, url):
    with app.app_context():
        with pytest.raises(UnsafeOutboundUrlError):
            validate_outbound_url(url)


def test_url_guard_allow_private_opt_out(app):
    with app.app_context():
        app.config["OUTBOUND_ALLOW_PRIVATE_URLS"] = True
        assert validate_outbound_url("https://192.168.1.1/hook") == "https://192.168.1.1/hook"


def test_webhook_send_refuses_private_url(app):
    with app.app_context():
        with pytest.raises(UnsafeOutboundUrlError):
            notification_rules._webhook_send({"webhook_url": "https://127.0.0.1/hook"}, {"a": 1})


# ---------------------------------------------------------------------------
# Plugin file_path confinement
# ---------------------------------------------------------------------------

def test_plugin_file_path_unrestricted_when_unset(app, tmp_path):
    payload = tmp_path / "feed.json"
    payload.write_text("[]", encoding="utf-8")
    with app.app_context():
        app.config["PLUGIN_DATA_DIR"] = ""
        assert resolve_plugin_file_path(str(payload)) == payload.resolve()


def test_plugin_file_path_confined_when_set(app, tmp_path):
    allowed = tmp_path / "plugin_data"
    allowed.mkdir()
    inside = allowed / "feed.json"
    inside.write_text("[]", encoding="utf-8")
    outside = tmp_path / "secret.json"
    outside.write_text("{}", encoding="utf-8")

    with app.app_context():
        app.config["PLUGIN_DATA_DIR"] = str(allowed)
        assert resolve_plugin_file_path(str(inside)) == inside.resolve()
        with pytest.raises(ValueError):
            resolve_plugin_file_path(str(outside))
        # Traversal out of the allowed root is caught after resolution.
        with pytest.raises(ValueError):
            resolve_plugin_file_path(str(allowed / ".." / "secret.json"))


# ---------------------------------------------------------------------------
# Impersonation tokens
# ---------------------------------------------------------------------------

def test_impersonation_token_is_short_lived_and_marked(app, client, admin_user, user_factory, auth_header):
    analyst = user_factory(role="Analyst")
    resp = client.post(
        f"/api/users/{analyst.id}/impersonate",
        json={"reason": "support ticket 42"},
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body["expires_in_minutes"] == 15

    with app.app_context():
        claims = pyjwt.decode(body["token"], app.config["JWT_SECRET"], algorithms=["HS256"])
    assert claims["impersonation"] is True
    assert claims["impersonated_by"] == admin_user.id
    assert claims["sub"] == str(analyst.id)
    # Lifetime is minutes, not the default 12 hours.
    assert claims["exp"] - claims["iat"] == 15 * 60

    # The token authenticates as the target user.
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {body['token']}"})
    assert me.status_code == 200
    assert me.get_json()["username"] == analyst.username


# ---------------------------------------------------------------------------
# Password policy
# ---------------------------------------------------------------------------

def test_password_policy_rejects_identity_and_common_passwords():
    with pytest.raises(PasswordTooWeakError):
        validate_password("short")
    with pytest.raises(PasswordTooWeakError):
        validate_password("password123456")
    with pytest.raises(PasswordTooWeakError):
        validate_password("xX-jdoe4ever-Xx", username="jdoe4ever")
    with pytest.raises(PasswordTooWeakError):
        validate_password("j.doe@corp!!!!", email="j.doe@example.com")
    # Acceptable passwords pass with identity context supplied.
    validate_password("correct-horse-battery", username="jdoe", email="j.doe@example.com")


def test_register_rejects_password_containing_username(client):
    resp = client.post("/api/auth/register", json={
        "username": "brandnewuser",
        "email": "brandnewuser@example.com",
        "password": "brandnewuser-99!",
    })
    assert resp.status_code == 400
    assert "username" in resp.get_json()["error"].lower()


# ---------------------------------------------------------------------------
# Feed ingest fidelity (NVD mapper + upsert)
# ---------------------------------------------------------------------------

NVD_RECORD = {
    "cve": {
        "id": "CVE-2026-4242",
        "descriptions": [{"lang": "en", "value": "Buffer overflow in libwidget."}],
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-787"}]},
        ],
        "references": [
            {"url": "https://example.com/advisory"},
            {"url": "https://example.com/advisory"},
            {"url": "https://example.com/patch"},
        ],
    },
    "metrics": {
        "cvssMetricV31": [{
            "cvssData": {
                "baseSeverity": "High",
                "baseScore": 8.1,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "version": "3.1",
            },
        }],
    },
    "published": "2026-01-05T00:00:00Z",
}


def test_nvd_mapper_extracts_vector_cwe_references():
    normalized = map_nvd_record(NVD_RECORD)
    assert normalized.cve_id == "CVE-2026-4242"
    assert normalized.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    assert normalized.cvss_version == "3.1"
    assert normalized.cwe_id == "CWE-787"
    assert normalized.references == ("https://example.com/advisory", "https://example.com/patch")


def test_ingest_applies_vector_cwe_references(app):
    with app.app_context():
        vuln = upsert_vulnerability(map_nvd_record(NVD_RECORD), source="vuln-feed-nvd")
        assert vuln.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        assert vuln.cvss_version == "3.1"
        assert vuln.cwe_id == "CWE-787"
        assert vuln.references_json == ["https://example.com/advisory", "https://example.com/patch"]

        # Re-ingest must not duplicate references.
        vuln = upsert_vulnerability(map_nvd_record(NVD_RECORD), source="vuln-feed-nvd")
        assert vuln.references_json == ["https://example.com/advisory", "https://example.com/patch"]


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

KEV_CATALOG = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-3001",
            "vulnerabilityName": "Widget RCE",
            "shortDescription": "Remote code execution.",
            "requiredAction": "Apply vendor patch.",
            "dateAdded": "2026-06-01",
        },
        {
            "cveID": "CVE-2026-9999",
            "vulnerabilityName": "Unrelated KEV entry",
            "dateAdded": "2026-06-02",
        },
    ],
}


def test_kev_mapper():
    normalized = map_kev_record(KEV_CATALOG["vulnerabilities"][0])
    assert normalized.cve_id == "CVE-2026-3001"
    assert normalized.known_exploited is True
    assert normalized.kev_date_added.isoformat() == "2026-06-01"
    assert "CISA required action" in normalized.description


def test_kev_plugin_flags_only_existing_by_default(app, sample_vulnerabilities, tmp_path):
    feed = tmp_path / "kev.json"
    feed.write_text(json.dumps(KEV_CATALOG), encoding="utf-8")

    with app.app_context():
        plugin = KevVulnerabilityFeedPlugin(config={"file_path": str(feed)})
        result = plugin.run()
        assert result["status"] == "success"
        assert result["stats"] == {"items_processed": 1, "items_skipped": 1}

        flagged = Vulnerability.query.filter_by(cve_id="CVE-2026-3001").first()
        assert flagged.known_exploited is True
        assert flagged.kev_date_added.isoformat() == "2026-06-01"
        # The catalog-only CVE was not created.
        assert Vulnerability.query.filter_by(cve_id="CVE-2026-9999").first() is None


def test_kev_plugin_can_create_new_vulns_when_configured(app, tmp_path):
    feed = tmp_path / "kev.json"
    feed.write_text(json.dumps(KEV_CATALOG), encoding="utf-8")

    with app.app_context():
        plugin = KevVulnerabilityFeedPlugin(config={"file_path": str(feed), "only_flag_existing": False})
        result = plugin.run()
        assert result["stats"]["items_processed"] == 2
        assert Vulnerability.query.filter_by(cve_id="CVE-2026-9999").first() is not None


def test_known_exploited_filter(app, client, admin_user, auth_header, sample_vulnerabilities):
    with app.app_context():
        vuln = Vulnerability.query.filter_by(cve_id="CVE-2026-3001").first()
        vuln.known_exploited = True
        db.session.commit()

    resp = client.get("/api/vulnerabilities?known_exploited=true", headers=auth_header(admin_user))
    assert resp.status_code == 200
    items = resp.get_json()["items"]
    assert [item["cve_id"] for item in items] == ["CVE-2026-3001"]
    assert items[0]["known_exploited"] is True

    resp = client.get("/api/vulnerabilities?known_exploited=false", headers=auth_header(admin_user))
    assert all(not item["known_exploited"] for item in resp.get_json()["items"])

    resp = client.get("/api/vulnerabilities?known_exploited=banana", headers=auth_header(admin_user))
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Watcher notifications
# ---------------------------------------------------------------------------

def _watch(app, vuln_id, user_id):
    with app.app_context():
        db.session.add(VulnerabilityWatcher(vulnerability_id=vuln_id, user_id=user_id, added_by=user_id))
        db.session.commit()


def test_watchers_notified_on_status_change(app, client, admin_user, user_factory, auth_header, sample_vulnerabilities):
    watcher = user_factory(role="Viewer")
    vuln = sample_vulnerabilities[0]
    _watch(app, vuln.id, watcher.id)

    resp = client.put(
        f"/api/vulnerabilities/{vuln.id}",
        json={"status": "In Progress"},
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 200

    with app.app_context():
        rows = Notification.query.filter_by(user_id=watcher.id, vulnerability_id=vuln.id).all()
        assert len(rows) == 1
        assert "status changed to In Progress" in rows[0].message
        # The acting admin gets no self-notification.
        assert Notification.query.filter_by(user_id=admin_user.id, vulnerability_id=vuln.id).count() == 0


def test_watcher_preference_opt_out(app, user_factory, sample_vulnerabilities):
    watcher = user_factory(role="Viewer")
    vuln = sample_vulnerabilities[0]
    _watch(app, vuln.id, watcher.id)

    with app.app_context():
        db.session.add(UserPreferences(user_id=watcher.id, notify_on_watched_vuln_update=False))
        db.session.commit()

        vulnerability = db.session.get(Vulnerability, vuln.id)
        created = notify_watchers_for_event(
            NotificationEvent(event_type="status_change", vulnerability_id=vuln.id, actor_id=None),
            vulnerability,
        )
        assert created == []
        assert Notification.query.filter_by(user_id=watcher.id).count() == 0


def test_watchers_not_notified_for_scheduled_scan_events(app, user_factory, sample_vulnerabilities):
    watcher = user_factory(role="Viewer")
    vuln = sample_vulnerabilities[0]
    _watch(app, vuln.id, watcher.id)

    with app.app_context():
        vulnerability = db.session.get(Vulnerability, vuln.id)
        created = notify_watchers_for_event(
            NotificationEvent(event_type="scheduled_scan", vulnerability_id=vuln.id, actor_id=None),
            vulnerability,
        )
        assert created == []


# ---------------------------------------------------------------------------
# Audit log CSV export
# ---------------------------------------------------------------------------

def test_audit_csv_export(client, admin_user, user_factory, auth_header, sample_vulnerabilities):
    vuln = sample_vulnerabilities[0]
    resp = client.put(
        f"/api/vulnerabilities/{vuln.id}",
        json={"severity": "High"},
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 200

    resp = client.get("/api/audit-logs/export.csv", headers=auth_header(admin_user))
    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    assert "attachment; filename=audit-logs.csv" in resp.headers["Content-Disposition"]
    body = resp.get_data(as_text=True)
    lines = [line for line in body.splitlines() if line.strip()]
    assert lines[0].startswith("id,created_at,action,table_name,record_id,username")
    assert any("UPDATE" in line and "vulnerabilities" in line for line in lines[1:])

    # Filtering by a non-matching action yields only the header.
    filtered = client.get("/api/audit-logs/export.csv?action=NOPE", headers=auth_header(admin_user))
    assert len([line for line in filtered.get_data(as_text=True).splitlines() if line.strip()]) == 1

    # Non-admins are rejected.
    viewer = user_factory(role="Viewer")
    assert client.get("/api/audit-logs/export.csv", headers=auth_header(viewer)).status_code == 403


# ---------------------------------------------------------------------------
# Remediation metrics (resolved_at + endpoint)
# ---------------------------------------------------------------------------

def test_resolved_at_stamped_and_cleared(app, client, admin_user, auth_header, sample_vulnerabilities):
    vuln = sample_vulnerabilities[0]

    resp = client.put(f"/api/vulnerabilities/{vuln.id}", json={"status": "Resolved"}, headers=auth_header(admin_user))
    assert resp.status_code == 200
    with app.app_context():
        row = db.session.get(Vulnerability, vuln.id)
        assert row.resolved_at is not None
        stamped = row.resolved_at

    # Idempotent: staying in the resolved family keeps the original stamp.
    client.put(f"/api/vulnerabilities/{vuln.id}", json={"status": "Closed"}, headers=auth_header(admin_user))
    with app.app_context():
        row = db.session.get(Vulnerability, vuln.id)
        assert row.resolved_at == stamped

    # Reopening clears it.
    client.put(f"/api/vulnerabilities/{vuln.id}", json={"status": "Open"}, headers=auth_header(admin_user))
    with app.app_context():
        row = db.session.get(Vulnerability, vuln.id)
        assert row.resolved_at is None


def test_remediation_metrics_endpoint(app, client, admin_user, auth_header, sample_vulnerabilities):
    now = datetime.now(timezone.utc)
    with app.app_context():
        resolved = Vulnerability.query.filter_by(cve_id="CVE-2026-3003").first()
        resolved.created_at = now - timedelta(days=10)
        resolved.resolved_at = now - timedelta(days=2)
        db.session.commit()

    resp = client.get("/api/reports/remediation-metrics?range=Last 30 days", headers=auth_header(admin_user))
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["resolved"]["count"] == 1
    assert payload["resolved"]["mttr_days_avg"] == 8.0
    assert payload["resolved"]["by_severity"]["Medium"]["count"] == 1
    # Two open vulns from the fixture, created just now.
    assert payload["open"]["count"] == 2
    assert payload["open"]["age_buckets"]["0-7"] == 2


# ---------------------------------------------------------------------------
# Component search
# ---------------------------------------------------------------------------

def test_global_search_includes_components(app, client, admin_user, auth_header, sample_product_version):
    product, version = sample_product_version
    with app.app_context():
        db.session.add(SoftwareComponent(
            product_version_id=version.id,
            name="log4j-core",
            version="2.14.1",
            ecosystem="maven",
        ))
        db.session.commit()

    resp = client.get("/api/search?q=log4j", headers=auth_header(admin_user))
    assert resp.status_code == 200
    payload = resp.get_json()
    assert len(payload["components"]) == 1
    hit = payload["components"][0]
    assert hit["name"] == "log4j-core"
    assert hit["ecosystem"] == "maven"
    assert hit["product_id"] == product.id
    assert hit["product_name"] == "Widget"
