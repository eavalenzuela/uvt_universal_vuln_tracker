import hashlib
import hmac
import json
import time

from backend.database import db
from backend.models import Vulnerability, WebhookDeliveryLog, WebhookEndpoint


def _sign(secret: str, body: bytes, timestamp: str | None = None) -> tuple[str, str]:
    """Sign the way an external sender does.

    The sender holds the raw secret, derives the HMAC key as sha256(secret),
    and signs "{timestamp}.{body}". Keying on the digest rather than the raw
    value is what lets the server store only the digest.
    """
    ts = timestamp or str(int(time.time()))
    key = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    signed = ts.encode("utf-8") + b"." + body
    return ts, hmac.new(key.encode("utf-8"), signed, hashlib.sha256).hexdigest()


def _signed_headers(secret: str, body: bytes, timestamp: str | None = None) -> dict:
    ts, signature = _sign(secret, body, timestamp)
    return {
        "Content-Type": "application/json",
        "X-UVT-Timestamp": ts,
        "X-UVT-Signature": signature,
    }


def _create_endpoint(client, auth_header, admin_user, *, source_type="generic"):
    response = client.post(
        "/api/webhooks",
        json={"name": f"pytest-{source_type}", "source_type": source_type},
        headers=auth_header(admin_user),
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def test_create_webhook_returns_secret_once(client, admin_user, auth_header):
    body = _create_endpoint(client, auth_header, admin_user)
    assert body["secret"].startswith("uvtwh_")
    assert body["ingest_url"] == f"/api/webhooks/ingest/{body['id']}"

    # Subsequent reads must not include the secret.
    listing = client.get("/api/webhooks", headers=auth_header(admin_user)).get_json()
    assert not any("secret" in item for item in listing["items"])


def test_non_admin_cannot_manage_webhooks(client, user_factory, auth_header):
    viewer = user_factory(role="Viewer")
    analyst = user_factory(role="Analyst")
    for user in (viewer, analyst):
        assert client.get("/api/webhooks", headers=auth_header(user)).status_code == 403
        assert client.post(
            "/api/webhooks",
            json={"name": "x"},
            headers=auth_header(user),
        ).status_code == 403


def test_ingest_rejects_missing_signature(app, client, admin_user, auth_header):
    created = _create_endpoint(client, auth_header, admin_user)
    response = client.post(
        f"/api/webhooks/ingest/{created['id']}",
        json={"vulnerabilities": []},
    )
    assert response.status_code == 401
    with app.app_context():
        assert WebhookDeliveryLog.query.filter_by(status="rejected").count() == 1


def test_ingest_rejects_bad_signature(client, admin_user, auth_header):
    created = _create_endpoint(client, auth_header, admin_user)
    body = json.dumps({"vulnerabilities": []}).encode("utf-8")
    response = client.post(
        f"/api/webhooks/ingest/{created['id']}",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-UVT-Timestamp": str(int(time.time())),
            "X-UVT-Signature": "deadbeef",
        },
    )
    assert response.status_code == 401


def test_ingest_generic_creates_vulnerabilities(app, client, admin_user, auth_header):
    created = _create_endpoint(client, auth_header, admin_user)

    payload = {
        "vulnerabilities": [
            {
                "cve_id": "CVE-2026-9001",
                "title": "Fake vuln 1",
                "severity": "High",
                "cvss_score": 8.1,
            },
            {
                "cve_id": "CVE-2026-9002",
                "title": "Fake vuln 2",
                "severity": "critical",
            },
        ]
    }
    body = json.dumps(payload).encode("utf-8")
    response = client.post(
        f"/api/webhooks/ingest/{created['id']}",
        data=body,
        headers=_signed_headers(created["secret"], body),
    )
    assert response.status_code == 202, response.get_json()
    assert response.get_json()["vulnerabilities_ingested"] == 2

    with app.app_context():
        assert Vulnerability.query.filter_by(cve_id="CVE-2026-9001").first() is not None
        assert Vulnerability.query.filter_by(cve_id="CVE-2026-9002").first() is not None
        endpoint = db.session.get(WebhookEndpoint, created["id"])
        assert endpoint.delivery_count == 1
        assert endpoint.failure_count == 0


def test_raw_secret_is_never_persisted(app, client, admin_user, auth_header):
    """Only the digest is stored, so a database dump leaks no signing keys."""
    created = _create_endpoint(client, auth_header, admin_user)
    with app.app_context():
        endpoint = db.session.get(WebhookEndpoint, created["id"])
        columns = {c.name for c in endpoint.__table__.columns}
        assert "secret" not in columns, "raw webhook secret must not have a column"
        assert endpoint.secret_hash == hashlib.sha256(
            created["secret"].encode("utf-8")
        ).hexdigest()


def test_ingest_requires_timestamp_header(client, admin_user, auth_header):
    created = _create_endpoint(client, auth_header, admin_user)
    body = json.dumps({"vulnerabilities": []}).encode("utf-8")
    _ts, signature = _sign(created["secret"], body)
    response = client.post(
        f"/api/webhooks/ingest/{created['id']}",
        data=body,
        headers={"Content-Type": "application/json", "X-UVT-Signature": signature},
    )
    assert response.status_code == 401
    assert "X-UVT-Timestamp" in response.get_json()["error"]


def test_ingest_rejects_replayed_stale_timestamp(client, admin_user, auth_header):
    """A captured request stops verifying once it falls outside the window."""
    created = _create_endpoint(client, auth_header, admin_user)
    body = json.dumps({"vulnerabilities": []}).encode("utf-8")
    stale = str(int(time.time()) - 3600)
    response = client.post(
        f"/api/webhooks/ingest/{created['id']}",
        data=body,
        headers=_signed_headers(created["secret"], body, timestamp=stale),
    )
    assert response.status_code == 401
    assert "Timestamp" in response.get_json()["error"]


def test_signature_is_bound_to_the_timestamp(client, admin_user, auth_header):
    """Swapping in a fresh timestamp must invalidate a captured signature."""
    created = _create_endpoint(client, auth_header, admin_user)
    body = json.dumps({"vulnerabilities": []}).encode("utf-8")
    _old_ts, signature = _sign(created["secret"], body, timestamp=str(int(time.time()) - 3600))
    response = client.post(
        f"/api/webhooks/ingest/{created['id']}",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-UVT-Timestamp": str(int(time.time())),
            "X-UVT-Signature": signature,
        },
    )
    assert response.status_code == 401


def test_ingest_trivy_format(app, client, admin_user, auth_header):
    created = _create_endpoint(client, auth_header, admin_user, source_type="trivy")

    payload = {
        "Results": [
            {
                "Target": "nodeapp (alpine 3.18)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-7777",
                        "Title": "libcrypto buffer overflow",
                        "Severity": "HIGH",
                        "CVSS": {"nvd": {"V3Score": 7.5}},
                    }
                ],
            }
        ]
    }
    body = json.dumps(payload).encode("utf-8")
    response = client.post(
        f"/api/webhooks/ingest/{created['id']}",
        data=body,
        headers=_signed_headers(created["secret"], body),
    )
    assert response.status_code == 202
    with app.app_context():
        assert Vulnerability.query.filter_by(cve_id="CVE-2026-7777").first() is not None


def test_rotate_secret_invalidates_old_signature(app, client, admin_user, auth_header):
    created = _create_endpoint(client, auth_header, admin_user)

    response = client.post(
        f"/api/webhooks/{created['id']}/rotate-secret",
        headers=auth_header(admin_user),
    )
    assert response.status_code == 200
    rotated = response.get_json()
    assert rotated["secret"].startswith("uvtwh_")
    assert rotated["secret"] != created["secret"]

    body = json.dumps({"vulnerabilities": []}).encode("utf-8")

    # Signing with the old secret should now fail...
    response = client.post(
        f"/api/webhooks/ingest/{created['id']}",
        data=body,
        headers=_signed_headers(created["secret"], body),
    )
    assert response.status_code == 401

    # ...while the rotated secret verifies.
    response = client.post(
        f"/api/webhooks/ingest/{created['id']}",
        data=body,
        headers=_signed_headers(rotated["secret"], body),
    )
    assert response.status_code == 202


def test_disabled_endpoint_rejects_ingest(app, client, admin_user, auth_header):
    created = _create_endpoint(client, auth_header, admin_user)
    client.patch(
        f"/api/webhooks/{created['id']}",
        json={"is_enabled": False},
        headers=auth_header(admin_user),
    )

    body = json.dumps({"vulnerabilities": []}).encode("utf-8")
    response = client.post(
        f"/api/webhooks/ingest/{created['id']}",
        data=body,
        headers=_signed_headers(created["secret"], body),
    )
    assert response.status_code == 404
