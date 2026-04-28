"""F17 Slice 3 — branding admin endpoints + PDF injection tests."""

import io


PNG_1x1 = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xcf"
    b"\xc0\x00\x00\x00\x03\x00\x01\x82\x14\x9d\xb9\x00\x00\x00\x00IEND\xaeB`\x82"
)


def test_get_branding_returns_defaults_for_any_user(client, auth_header, user_factory):
    viewer = user_factory(role="Viewer")
    resp = client.get("/api/admin/branding", headers=auth_header(viewer))
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["primary_color"] == "#2563eb"
    assert payload["footer_text"] == ""
    assert payload["has_logo"] is False


def test_update_branding_admin_only(client, auth_header, admin_user, user_factory):
    analyst = user_factory(role="Analyst")
    resp = client.put(
        "/api/admin/branding",
        headers={**auth_header(analyst), "Content-Type": "application/json"},
        json={"primary_color": "#ff0000"},
    )
    assert resp.status_code == 403

    resp = client.put(
        "/api/admin/branding",
        headers={**auth_header(admin_user), "Content-Type": "application/json"},
        json={"primary_color": "#FF8800", "footer_text": "Acme · Confidential"},
    )
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["primary_color"] == "#ff8800"
    assert payload["footer_text"] == "Acme · Confidential"


def test_update_branding_rejects_bad_color(client, auth_header, admin_user):
    resp = client.put(
        "/api/admin/branding",
        headers={**auth_header(admin_user), "Content-Type": "application/json"},
        json={"primary_color": "red"},
    )
    assert resp.status_code == 400
    assert "primary_color" in resp.get_json()["error"]


def test_update_branding_rejects_long_footer(client, auth_header, admin_user):
    resp = client.put(
        "/api/admin/branding",
        headers={**auth_header(admin_user), "Content-Type": "application/json"},
        json={"footer_text": "x" * 300},
    )
    assert resp.status_code == 400


def test_logo_upload_and_delete(client, auth_header, admin_user, tmp_path, app):
    app.config["BRANDING_DIR"] = str(tmp_path)
    resp = client.post(
        "/api/admin/branding/logo",
        headers=auth_header(admin_user),
        data={"logo": (io.BytesIO(PNG_1x1), "logo.png", "image/png")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()["has_logo"] is True
    assert (tmp_path / "logo.png").exists()

    resp = client.delete("/api/admin/branding/logo", headers=auth_header(admin_user))
    assert resp.status_code == 200
    assert resp.get_json()["has_logo"] is False
    assert not (tmp_path / "logo.png").exists()


def test_logo_upload_rejects_oversize(client, auth_header, admin_user, tmp_path, app):
    app.config["BRANDING_DIR"] = str(tmp_path)
    huge = b"\x89PNG\r\n\x1a\n" + b"\x00" * (1024 * 1024 + 1)
    resp = client.post(
        "/api/admin/branding/logo",
        headers=auth_header(admin_user),
        data={"logo": (io.BytesIO(huge), "logo.png", "image/png")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_logo_upload_rejects_unknown_extension(client, auth_header, admin_user, tmp_path, app):
    app.config["BRANDING_DIR"] = str(tmp_path)
    resp = client.post(
        "/api/admin/branding/logo",
        headers=auth_header(admin_user),
        data={"logo": (io.BytesIO(b"\x00\x01"), "logo.gif", "image/gif")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_branding_injected_into_rendered_pdf(client, auth_header, admin_user, sample_vulnerabilities, app):
    """The renderer should pick up the configured branding row when no
    explicit branding is passed in the context."""
    client.put(
        "/api/admin/branding",
        headers={**auth_header(admin_user), "Content-Type": "application/json"},
        json={"primary_color": "#abcdef", "footer_text": "Acme Inc"},
    )

    # Render a PDF and confirm it's a PDF — the renderer pulls branding from DB.
    resp = client.get(
        "/api/reports/vulnerabilities/export?format=pdf&pdf_layout=executive_summary",
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 200
    artifact = resp.get_json()["artifact"]
    download = client.get(artifact["download_url"], headers=auth_header(admin_user))
    assert download.status_code == 200
    body = download.get_data()
    assert body.startswith(b"%PDF-")

    # Direct renderer test: the loaded branding should reach the template.
    with app.app_context():
        from backend.services.pdf_renderer import _load_branding
        b = _load_branding()
        assert b["primary_color"] == "#abcdef"
        assert b["footer_text"] == "Acme Inc"
