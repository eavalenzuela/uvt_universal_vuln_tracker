"""F17 Slice 2 — async PDF + executive_summary layout export tests."""

import pytest


def test_pdf_executive_summary_layout(client, auth_header, admin_user, sample_vulnerabilities):
    resp = client.get(
        "/api/reports/vulnerabilities/export?format=pdf&pdf_layout=executive_summary",
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 200
    artifact = resp.get_json()["artifact"]
    assert artifact["status"] == "ready"
    assert artifact["download_url"]

    download = client.get(artifact["download_url"], headers=auth_header(admin_user))
    assert download.status_code == 200
    assert download.headers["Content-Type"].startswith("application/pdf")
    body = download.get_data()
    assert body.startswith(b"%PDF-")
    assert len(body) > 5000  # exec layout is meaningfully larger than parity layout


def test_pdf_layout_param_validates(client, auth_header, admin_user):
    resp = client.get(
        "/api/reports/vulnerabilities/export?format=pdf&pdf_layout=does_not_exist",
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 400
    assert "pdf_layout" in resp.get_json()["error"]


def test_artifact_status_endpoint(client, auth_header, admin_user, sample_vulnerabilities):
    resp = client.get(
        "/api/reports/vulnerabilities/export?format=pdf",
        headers=auth_header(admin_user),
    )
    artifact_id = resp.get_json()["artifact"]["id"]
    status_resp = client.get(f"/api/reports/artifacts/{artifact_id}", headers=auth_header(admin_user))
    assert status_resp.status_code == 200
    payload = status_resp.get_json()["artifact"]
    assert payload["id"] == artifact_id
    assert payload["status"] == "ready"
    assert payload["download_url"]


def test_async_pdf_returns_202_then_polls_to_ready(client, auth_header, admin_user, sample_vulnerabilities, app):
    """When CELERY_ENABLED, the export route should create a pending artifact,
    return 202, and the status endpoint should reflect ready state after the
    eager-mode worker finishes."""
    # Run celery tasks inline so .delay() executes synchronously.
    from backend.celery_app import celery
    celery.conf.update(task_always_eager=True, task_eager_propagates=True)
    app.config["CELERY_ENABLED"] = True
    try:
        resp = client.get(
            "/api/reports/vulnerabilities/export?format=pdf&pdf_layout=executive_summary",
            headers=auth_header(admin_user),
        )
        assert resp.status_code == 202
        artifact = resp.get_json()["artifact"]
        artifact_id = artifact["id"]
        # Eager mode: by the time .delay() returns, the task has run.
        status_resp = client.get(
            f"/api/reports/artifacts/{artifact_id}", headers=auth_header(admin_user)
        )
        assert status_resp.status_code == 200
        final = status_resp.get_json()["artifact"]
        assert final["status"] == "ready", f"expected ready, got {final}"
        assert final["download_url"]

        download = client.get(final["download_url"], headers=auth_header(admin_user))
        assert download.status_code == 200
        assert download.get_data().startswith(b"%PDF-")
    finally:
        celery.conf.update(task_always_eager=False, task_eager_propagates=False)
        app.config["CELERY_ENABLED"] = False


def test_download_returns_409_when_artifact_not_ready(client, auth_header, admin_user, sample_vulnerabilities, app):
    """A pending artifact must not return its file."""
    from backend.database import db
    from backend.models import ReportArtifact
    with app.app_context():
        artifact = ReportArtifact(
            report_type="vulnerabilities",
            format="pdf",
            storage_path=None,
            content_type="application/pdf",
            filters_json={},
            created_by=admin_user.id,
            status="pending",
        )
        db.session.add(artifact)
        db.session.commit()
        artifact_id = artifact.id

    # Need a signed token to even reach the status check; mint one via the export route.
    # Since pending artifacts have download_url=None, sign one manually using the same serializer.
    from itsdangerous import URLSafeTimedSerializer
    from backend.api.report_exports import REPORT_EXPORT_TOKEN_SALT
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt=REPORT_EXPORT_TOKEN_SALT)
    token = serializer.dumps({"artifact_id": artifact_id, "user_id": admin_user.id})
    resp = client.get(
        f"/api/reports/artifacts/{artifact_id}/download?token={token}",
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 409
    assert "not ready" in resp.get_json()["error"]
