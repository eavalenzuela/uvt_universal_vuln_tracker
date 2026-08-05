"""Regression tests for the v2.24.0 review fixes.

Each test names the behaviour that was broken, so a future change that
reintroduces it fails here rather than in production.
"""

from __future__ import annotations

import pytest

from backend.auth import LOCKOUT_MINUTES, MAX_FAILED_LOGINS, create_api_token
from backend.database import db
from backend.permissions import (
    SCOPE_UNMAPPED,
    audit_route_scopes,
    role_has_scope,
    scope_for_request,
    token_has_scope,
)


# ---------------------------------------------------------------------------
# SEC-4 — API token scopes were unenforced on roughly half the API
# ---------------------------------------------------------------------------

def test_unmapped_routes_fail_closed():
    """An endpoint with no scope mapping must be denied, not waved through.

    scope_for_request used to return None for any path outside a ten-entry
    prefix list, and None meant "no scope required".
    """
    scope = scope_for_request("/api/some-future-endpoint", "GET")
    assert scope == SCOPE_UNMAPPED
    assert role_has_scope("Admin", scope) is False
    assert token_has_scope(["products:read"], scope) is False


def test_every_registered_route_has_a_scope(app):
    """No route may ship without an explicit scope mapping."""
    with app.app_context():
        unmapped = audit_route_scopes(app)
    assert unmapped == [], (
        "These routes have no entry in ROUTE_SCOPES and will be denied:\n  "
        + "\n  ".join(unmapped)
    )


@pytest.mark.parametrize("path", [
    "/api/teams",
    "/api/webhooks",
    "/api/audit-logs",
    "/api/notification-rules",
    "/api/imports",
    "/api/search",
    "/api/dashboard/summary",
])
def test_previously_unscoped_areas_now_require_a_scope(path):
    scope = scope_for_request(path, "GET")
    assert scope not in (None, SCOPE_UNMAPPED), f"{path} resolved to {scope!r}"


def test_narrow_token_cannot_reach_other_feature_areas(app, client, admin_user, auth_header):
    """A products:read token must not create teams or webhooks.

    It could do both: those routes are @admin_required, so the token inherited
    its owner's Admin role while its own scope list was never consulted.
    """
    with app.app_context():
        plaintext, _record = create_api_token(admin_user, "narrow", ["products:read"])
        db.session.commit()

    headers = {"Authorization": f"Bearer {plaintext}"}

    assert client.get("/api/products", headers=headers).status_code == 200

    for method, path, payload in [
        ("get", "/api/teams", None),
        ("get", "/api/audit-logs", None),
        ("get", "/api/webhooks", None),
        ("get", "/api/notification-rules", None),
        ("post", "/api/teams", {"name": "should-not-exist"}),
        ("post", "/api/webhooks", {"name": "should-not-exist"}),
    ]:
        call = getattr(client, method)
        response = call(path, headers=headers, json=payload) if payload else call(path, headers=headers)
        assert response.status_code == 403, (
            f"{method.upper()} {path} returned {response.status_code} for a products:read token"
        )


def test_token_may_use_self_scope_without_declaring_it(app, client, admin_user):
    """A token always acts as its owner, so its own profile stays reachable."""
    with app.app_context():
        plaintext, _ = create_api_token(admin_user, "narrow", ["products:read"])
        db.session.commit()
    response = client.get("/api/me/preferences", headers={"Authorization": f"Bearer {plaintext}"})
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# FN-13 — self-service routes were behind an Admin-only scope
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role", ["Analyst", "Viewer"])
def test_non_admins_can_manage_their_own_api_tokens(client, user_factory, auth_header, role):
    user = user_factory(role=role)
    assert client.get("/api/users/me/api-tokens", headers=auth_header(user)).status_code == 200


@pytest.mark.parametrize("role", ["Analyst", "Viewer"])
def test_non_admins_can_look_up_assignees(client, user_factory, auth_header, role):
    """The directory backs assignee pickers and dashboard owner names."""
    user = user_factory(role=role)
    response = client.get("/api/users/active", headers=auth_header(user))
    assert response.status_code == 200
    assert "items" in response.get_json()


# ---------------------------------------------------------------------------
# SEC-7 — login throttling was per-IP only
# ---------------------------------------------------------------------------

def test_account_locks_after_repeated_failures(app, client, admin_user):
    app.config["RATE_LIMIT_ENABLED"] = False  # isolate the lockout from the throttle

    for _ in range(MAX_FAILED_LOGINS):
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})

    response = client.post("/api/auth/login", json={"username": "admin", "password": "secret-pass-12"})
    assert response.status_code == 401
    # Non-enumerable: identical body to a wrong password, with a hint of when
    # to retry.
    assert response.get_json()["error"] == "Invalid credentials"
    assert int(response.headers["Retry-After"]) <= LOCKOUT_MINUTES * 60

    with app.app_context():
        from backend.models import User
        user = db.session.get(User, admin_user.id)
        assert user.failed_login_count >= MAX_FAILED_LOGINS
        assert user.locked_until is not None


def test_successful_login_clears_the_failure_counter(app, client, admin_user):
    app.config["RATE_LIMIT_ENABLED"] = False

    for _ in range(MAX_FAILED_LOGINS - 1):
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})

    assert client.post(
        "/api/auth/login", json={"username": "admin", "password": "secret-pass-12"}
    ).status_code == 200

    with app.app_context():
        from backend.models import User
        user = db.session.get(User, admin_user.id)
        assert user.failed_login_count == 0
        assert user.locked_until is None


def test_login_throttle_is_keyed_per_account(app, client, admin_user, user_factory):
    """One account's failures must not throttle a different account.

    Keying on IP alone meant everyone behind one NAT gateway shared a single
    five-per-minute budget.
    """
    other = user_factory(role="Analyst", username="colleague", password="another-pass-12")

    for _ in range(6):
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})

    response = client.post(
        "/api/auth/login", json={"username": other.username, "password": "another-pass-12"}
    )
    assert response.status_code != 429, "a colleague's typos throttled an unrelated account"


# ---------------------------------------------------------------------------
# SEC-6 — seed-admin bypassed the password policy
# ---------------------------------------------------------------------------

def test_seed_admin_rejects_a_weak_password(app):
    from click.testing import CliRunner

    from backend.cli import seed_admin

    runner = CliRunner()
    with app.app_context():
        result = runner.invoke(
            seed_admin,
            ["--username", "weakadmin", "--email", "weak@example.com", "--password", "changeme"],
            obj=None,
        )
    assert result.exit_code != 0
    assert "at least 12 characters" in result.output

    with app.app_context():
        from backend.models import User
        assert User.query.filter_by(username="weakadmin").first() is None


# ---------------------------------------------------------------------------
# SEC-5 — CSP was only ever applied to JSON responses
# ---------------------------------------------------------------------------

def test_api_responses_carry_a_strict_csp(client):
    headers = client.get("/api/health").headers
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"


# ---------------------------------------------------------------------------
# FN-15 — the range parameter was accepted but inert
# ---------------------------------------------------------------------------

def test_dashboard_rejects_an_unknown_range(client, admin_user, auth_header):
    """'All time' used to be accepted silently and treated as 14 days."""
    response = client.get("/api/dashboard/summary?range=All%20time", headers=auth_header(admin_user))
    assert response.status_code == 400
    assert "range" in response.get_json()["error"].lower()


def test_dashboard_summary_states_its_scope(client, admin_user, auth_header):
    """The response must say what `total` counts, so the UI can label it."""
    response = client.get("/api/dashboard/summary?status=Open", headers=auth_header(admin_user))
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["scope"]["status"] == "Open"
    assert payload["scope"]["time_scoped"] is False


# ---------------------------------------------------------------------------
# FN-17 — severity and CVSS were never reconciled
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,expected", [
    (0.0, "None"), (3.9, "Low"), (4.0, "Medium"),
    (6.9, "Medium"), (7.0, "High"), (8.9, "High"),
    (9.0, "Critical"), (10.0, "Critical"),
])
def test_cvss_maps_to_its_qualitative_rating(score, expected):
    from backend.services.severity_consistency import severity_for_cvss
    assert severity_for_cvss(score) == expected


def test_contradictory_severity_and_cvss_are_reported():
    from backend.services.severity_consistency import check_severity_consistency

    assert check_severity_consistency("Critical", 5.5) is not None
    assert check_severity_consistency("Medium", 5.5) is None
    assert check_severity_consistency("High", None) is None

    result = check_severity_consistency("Critical", 5.5)
    assert result["derived_severity"] == "Medium"
    assert result["levels_apart"] == 2


# ---------------------------------------------------------------------------
# FN-17 — risk acceptance had no expiry, approver, or reason
# ---------------------------------------------------------------------------

def test_risk_acceptance_requires_an_expiry(client, admin_user, auth_header, sample_vulnerabilities):
    vuln = sample_vulnerabilities[0]
    response = client.post(
        f"/api/vulnerabilities/{vuln.id}/risk-acceptance",
        json={"reason": "Compensating control in place at the edge proxy."},
        headers=auth_header(admin_user),
    )
    assert response.status_code == 400
    assert "expiry" in response.get_json()["error"].lower()


def test_risk_acceptance_requires_a_substantive_reason(client, admin_user, auth_header, sample_vulnerabilities):
    vuln = sample_vulnerabilities[0]
    response = client.post(
        f"/api/vulnerabilities/{vuln.id}/risk-acceptance",
        json={"reason": "wontfix", "until": "2027-01-01T00:00:00Z"},
        headers=auth_header(admin_user),
    )
    assert response.status_code == 400


def test_risk_acceptance_records_who_why_and_until(app, client, admin_user, auth_header, sample_vulnerabilities):
    vuln_id = sample_vulnerabilities[0].id
    response = client.post(
        f"/api/vulnerabilities/{vuln_id}/risk-acceptance",
        json={
            "reason": "Mitigated by the WAF rule shipped in change CHG-4471.",
            "until": "2026-12-01T00:00:00Z",
        },
        headers=auth_header(admin_user),
    )
    assert response.status_code == 200, response.get_json()

    with app.app_context():
        from backend.models import Vulnerability
        stored = db.session.get(Vulnerability, vuln_id)
        assert stored.risk_accepted is True
        assert stored.risk_accepted_by == admin_user.id
        assert stored.risk_accepted_until is not None
        assert "CHG-4471" in stored.risk_acceptance_reason


def test_risk_acceptance_can_be_revoked(client, admin_user, auth_header, sample_vulnerabilities):
    vuln_id = sample_vulnerabilities[0].id
    client.post(
        f"/api/vulnerabilities/{vuln_id}/risk-acceptance",
        json={"reason": "Accepted pending vendor patch in Q4.", "until": "2026-12-01T00:00:00Z"},
        headers=auth_header(admin_user),
    )
    response = client.delete(
        f"/api/vulnerabilities/{vuln_id}/risk-acceptance", headers=auth_header(admin_user)
    )
    assert response.status_code == 200
    assert response.get_json()["risk_accepted"] is False


# ---------------------------------------------------------------------------
# FN-17 — evidence attachments
# ---------------------------------------------------------------------------

def test_attachment_rejects_a_disallowed_type(client, admin_user, auth_header, sample_vulnerabilities):
    """HTML and SVG must not be storable: they execute in our origin."""
    import io

    vuln_id = sample_vulnerabilities[0].id
    response = client.post(
        f"/api/vulnerabilities/{vuln_id}/attachments",
        data={"file": (io.BytesIO(b"<script>alert(1)</script>"), "evil.html")},
        headers=auth_header(admin_user),
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "not an accepted attachment type" in response.get_json()["error"]


def test_attachment_round_trip(client, admin_user, auth_header, sample_vulnerabilities):
    import hashlib
    import io

    vuln_id = sample_vulnerabilities[0].id
    payload = b"nmap scan output\nport 443 open\n"

    upload = client.post(
        f"/api/vulnerabilities/{vuln_id}/attachments",
        data={"file": (io.BytesIO(payload), "scan.log"), "description": "Initial scan"},
        headers=auth_header(admin_user),
        content_type="multipart/form-data",
    )
    assert upload.status_code == 201, upload.get_json()
    body = upload.get_json()
    assert body["sha256"] == hashlib.sha256(payload).hexdigest()
    assert body["size_bytes"] == len(payload)

    listing = client.get(
        f"/api/vulnerabilities/{vuln_id}/attachments", headers=auth_header(admin_user)
    ).get_json()
    assert len(listing["items"]) == 1

    download = client.get(body["download_url"], headers=auth_header(admin_user))
    assert download.status_code == 200
    assert download.data == payload
    # Never served as its own content type — an uploaded file must not render
    # in this origin.
    assert download.headers["Content-Type"].startswith("application/octet-stream")


# ---------------------------------------------------------------------------
# FN-17 — MFA
# ---------------------------------------------------------------------------

def test_mfa_enrollment_requires_a_valid_code_before_activating(app, client, admin_user, auth_header):
    """A bad code must not enable MFA, or a user could lock themselves out."""
    start = client.post("/api/auth/mfa/enroll", headers=auth_header(admin_user))
    assert start.status_code == 200
    assert start.get_json()["otpauth_uri"].startswith("otpauth://totp/")

    bad = client.post(
        "/api/auth/mfa/confirm", json={"code": "000000"}, headers=auth_header(admin_user)
    )
    assert bad.status_code == 400

    with app.app_context():
        from backend.models import User
        assert db.session.get(User, admin_user.id).mfa_enabled is False


def test_mfa_login_requires_the_second_factor(app, client, admin_user, auth_header):
    import pyotp

    start = client.post("/api/auth/mfa/enroll", headers=auth_header(admin_user)).get_json()
    secret = start["secret"]

    confirm = client.post(
        "/api/auth/mfa/confirm",
        json={"code": pyotp.TOTP(secret).now()},
        headers=auth_header(admin_user),
    )
    assert confirm.status_code == 200, confirm.get_json()
    recovery_codes = confirm.get_json()["recovery_codes"]
    assert len(recovery_codes) == 10

    # Password alone is now a challenge, not a session.
    login = client.post("/api/auth/login", json={"username": "admin", "password": "secret-pass-12"})
    assert login.status_code == 200
    payload = login.get_json()
    assert payload["mfa_required"] is True
    assert "token" not in payload

    wrong = client.post(
        "/api/auth/mfa/verify", json={"mfa_token": payload["mfa_token"], "code": "000000"}
    )
    assert wrong.status_code == 401

    ok = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": payload["mfa_token"], "code": pyotp.TOTP(secret).now()},
    )
    assert ok.status_code == 200
    assert ok.get_json()["token"]


def test_mfa_recovery_codes_are_single_use(app, client, admin_user, auth_header):
    import pyotp

    secret = client.post("/api/auth/mfa/enroll", headers=auth_header(admin_user)).get_json()["secret"]
    codes = client.post(
        "/api/auth/mfa/confirm",
        json={"code": pyotp.TOTP(secret).now()},
        headers=auth_header(admin_user),
    ).get_json()["recovery_codes"]

    def challenge():
        return client.post(
            "/api/auth/login", json={"username": "admin", "password": "secret-pass-12"}
        ).get_json()["mfa_token"]

    first = client.post("/api/auth/mfa/verify", json={"mfa_token": challenge(), "recovery_code": codes[0]})
    assert first.status_code == 200

    reuse = client.post("/api/auth/mfa/verify", json={"mfa_token": challenge(), "recovery_code": codes[0]})
    assert reuse.status_code == 401


def test_disabling_mfa_requires_the_password(app, client, admin_user, auth_header):
    import pyotp

    secret = client.post("/api/auth/mfa/enroll", headers=auth_header(admin_user)).get_json()["secret"]
    client.post(
        "/api/auth/mfa/confirm",
        json={"code": pyotp.TOTP(secret).now()},
        headers=auth_header(admin_user),
    )

    assert client.post(
        "/api/auth/mfa/disable", json={"password": "nope"}, headers=auth_header(admin_user)
    ).status_code == 403

    assert client.post(
        "/api/auth/mfa/disable", json={"password": "secret-pass-12"}, headers=auth_header(admin_user)
    ).status_code == 200


# ---------------------------------------------------------------------------
# SEC-9 — no request body size limit
# ---------------------------------------------------------------------------

def test_request_body_size_is_bounded(app):
    assert app.config["MAX_CONTENT_LENGTH"] > 0
    # Generous enough for real scanner exports, which are tens of megabytes.
    assert app.config["MAX_CONTENT_LENGTH"] >= 32 * 1024 * 1024


# ---------------------------------------------------------------------------
# Plugin config types were never enforced
# ---------------------------------------------------------------------------

def test_plugin_config_values_are_coerced_to_their_declared_types():
    """An HTML form yields strings; the schema says integer.

    Nothing coerced, so `timeout_seconds` was stored as "30" and the KEV feed
    died on urlopen(timeout="30") with "'str' object cannot be interpreted as
    an integer" — surfaced to the operator only as "artifact persistence
    failed".
    """
    from backend.plugins.config import prepare_plugin_config

    schema = {
        "fields": [
            {"name": "timeout_seconds", "type": "integer", "default": 30},
            {"name": "ratio", "type": "number"},
            {"name": "only_flag_existing", "type": "boolean"},
            {"name": "feed_url", "type": "string"},
        ]
    }
    prepared = prepare_plugin_config(
        {"timeout_seconds": "45", "ratio": "0.5", "only_flag_existing": "false",
         "feed_url": "https://example.com/f.json"},
        schema,
    )
    assert prepared["timeout_seconds"] == 45 and isinstance(prepared["timeout_seconds"], int)
    assert prepared["ratio"] == 0.5 and isinstance(prepared["ratio"], float)
    assert prepared["only_flag_existing"] is False
    assert prepared["feed_url"] == "https://example.com/f.json"


def test_plugin_config_defaults_keep_their_declared_type():
    from backend.plugins.config import prepare_plugin_config

    prepared = prepare_plugin_config(
        {}, {"fields": [{"name": "timeout_seconds", "type": "integer", "default": 30}]}
    )
    assert isinstance(prepared["timeout_seconds"], int)


def test_uncoercible_plugin_config_value_is_reported_by_field():
    """A bad value should be a named validation error, not a runtime crash."""
    import pytest

    from backend.plugins.config import prepare_plugin_config

    with pytest.raises(ValueError, match="timeout_seconds"):
        prepare_plugin_config(
            {"timeout_seconds": "half a minute"},
            {"fields": [{"name": "timeout_seconds", "type": "integer"}]},
        )


def test_empty_optional_numeric_config_is_left_alone():
    """A blank optional field must not become 0 or raise."""
    from backend.plugins.config import prepare_plugin_config

    prepared = prepare_plugin_config(
        {"timeout_seconds": ""},
        {"fields": [{"name": "timeout_seconds", "type": "integer"}]},
    )
    assert prepared["timeout_seconds"] == ""
