"""Regression tests for the v2.22.0 analysis-and-fix pass.

Covers correctness/security fixes that previously had no coverage or that only
manifested on PostgreSQL (the suite runs on SQLite). See docs/CHANGELOG.md.
"""

import types
from datetime import datetime, timedelta, timezone

from backend.database import db
from backend.models import (
    NotificationDeliveryCheckpoint,
    NotificationRule,
    Product,
    ProductVersion,
    SoftwareComponent,
    Vulnerability,
    VulnerabilityComponent,
)
from backend.api.validation import escape_like
from backend.services.reporting_service import range_start
from backend.services.sla import compute_sla_state
from backend.live_notifications import hub


# ── pure helpers ──────────────────────────────────────────────────────────

def test_escape_like_escapes_sql_wildcards():
    assert escape_like("a_b") == r"a\_b"
    assert escape_like("100%") == r"100\%"
    assert escape_like(r"a\b") == r"a\\b"
    assert escape_like("plain") == "plain"


def test_range_start_is_timezone_aware_for_all_ranges():
    now = datetime.now(timezone.utc)
    for value in ("Month to date", "Quarter to date", "Last 7 days", "", "junk"):
        start = range_start(value)
        assert start.tzinfo is not None, f"{value!r} returned a naive datetime"
        # Comparing with an aware datetime must not raise TypeError.
        assert start <= now


def test_compute_sla_state_met_for_resolved_or_closed():
    past = datetime.now(timezone.utc) - timedelta(days=5)
    for status in ("Resolved", "Closed"):
        vuln = types.SimpleNamespace(status=status, sla_due_at=past)
        assert compute_sla_state(vuln, policy={}) == "met"
    # An open, overdue vulnerability is still breached.
    open_overdue = types.SimpleNamespace(status="Open", sla_due_at=past)
    assert compute_sla_state(open_overdue, policy={}) == "breached"


def test_live_notification_sent_at_is_valid_iso():
    queue = hub.subscribe(424242)
    try:
        hub.publish(424242, {"type": "x", "payload": {}})
        payload = queue.get(timeout=1)
    finally:
        hub.unsubscribe(424242, queue)
    sent_at = payload["sent_at"]
    assert "+00:00Z" not in sent_at  # the old malformed double designator
    # Round-trips through fromisoformat after normalizing the trailing Z.
    datetime.fromisoformat(sent_at.replace("Z", "+00:00"))


# ── component filter (DISTINCT-on-json regression) ────────────────────────

def _make_component_vuln(app, admin_user):
    with app.app_context():
        product = Product(name="CompProduct", created_by=admin_user.id)
        db.session.add(product)
        db.session.flush()
        pv = ProductVersion(product_id=product.id, version="1.0")
        db.session.add(pv)
        db.session.flush()
        vuln = Vulnerability(
            cve_id="CVE-2026-9001", title="Component vuln", severity="High",
            status="Open", created_by=admin_user.id,
        )
        db.session.add(vuln)
        db.session.flush()
        # Link the same vuln to two npm components so a naive join would emit
        # duplicate rows; the IN-subquery must collapse them to one.
        for idx, ver in enumerate(("1.0", "2.0")):
            comp = SoftwareComponent(product_version_id=pv.id, name="leftpad", version=ver, ecosystem="npm")
            db.session.add(comp)
            db.session.flush()
            db.session.add(VulnerabilityComponent(
                vulnerability_id=vuln.id, component_id=comp.id,
                source=f"src{idx}", match_type="purl",
            ))
        db.session.commit()
        return vuln.id


def test_component_filter_returns_vuln_once(app, client, admin_user, auth_header):
    vid = _make_component_vuln(app, admin_user)

    resp = client.get("/api/vulnerabilities?component_ecosystem=npm", headers=auth_header(admin_user))
    assert resp.status_code == 200
    matching = [i for i in resp.get_json()["items"] if i["id"] == vid]
    assert len(matching) == 1  # matches two components but appears once

    resp2 = client.get("/api/vulnerabilities?component_name=leftpad", headers=auth_header(admin_user))
    assert resp2.status_code == 200
    assert any(i["id"] == vid for i in resp2.get_json()["items"])


# ── global search route + LIKE escaping ───────────────────────────────────

def test_global_search_route_and_wildcard_escaping(app, client, admin_user, auth_header, sample_vulnerabilities):
    # The route resolves at /api/search (not the old doubled /api/api/search).
    resp = client.get("/api/search?q=Critical", headers=auth_header(admin_user))
    assert resp.status_code == 200
    cves = {v["cve_id"] for v in resp.get_json()["vulnerabilities"]}
    assert "CVE-2026-3001" in cves

    # A bare "__" must be matched literally, not as two single-char wildcards
    # (which previously matched every row).
    resp2 = client.get("/api/search?q=__", headers=auth_header(admin_user))
    assert resp2.status_code == 200
    assert resp2.get_json()["vulnerabilities"] == []


# ── last-admin lockout guard ──────────────────────────────────────────────

def test_cannot_demote_or_deactivate_last_admin(app, client, admin_user, auth_header):
    headers = auth_header(admin_user)
    assert client.patch(f"/api/users/{admin_user.id}", headers=headers, json={"role": "Viewer"}).status_code == 409
    assert client.patch(f"/api/users/{admin_user.id}", headers=headers, json={"is_active": False}).status_code == 409
    assert client.post(f"/api/users/{admin_user.id}/toggle-active", headers=headers).status_code == 409


def test_can_demote_admin_when_another_admin_exists(app, client, admin_user, auth_header, user_factory):
    other = user_factory(role="Admin")
    resp = client.patch(f"/api/users/{other.id}", headers=auth_header(admin_user), json={"role": "Viewer"})
    assert resp.status_code == 200
    assert resp.get_json()["role"] == "Viewer"


# ── scheduled scan retries after a failed delivery ────────────────────────

def test_failed_delivery_does_not_advance_checkpoint(app, admin_user, monkeypatch):
    from backend.services import notification_rules as nr

    with app.app_context():
        rule = NotificationRule(
            name="retry-rule", delivery_adapter="slack", severity_threshold="Low",
            created_by=admin_user.id, frequency_days=3,
        )
        db.session.add(rule)
        vuln = Vulnerability(
            title="needs alert", severity="High", status="Open", created_by=admin_user.id,
            sla_due_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        db.session.add(vuln)
        db.session.commit()

        monkeypatch.setattr(nr, "_deliver", lambda *a, **k: (False, None, "boom"))

        logs = nr.run_scheduled_notification_scan(now=datetime.now(timezone.utc))
        db.session.commit()
        assert len(logs) == 1 and logs[0].success is False
        # Failed delivery must not create/advance a checkpoint, so it is retried.
        assert NotificationDeliveryCheckpoint.query.filter_by(
            rule_id=rule.id, vulnerability_id=vuln.id,
        ).first() is None

        logs2 = nr.run_scheduled_notification_scan(now=datetime.now(timezone.utc))
        assert len(logs2) == 1  # retried rather than suppressed
