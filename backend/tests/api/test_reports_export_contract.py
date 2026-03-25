import csv
import io


def _parse_csv_rows(content: str):
    return list(csv.DictReader(io.StringIO(content)))


def _create_export(client, auth_header, user, endpoint):
    resp = client.get(endpoint, headers=auth_header(user))
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["artifact"]["id"]
    assert payload["artifact"]["download_url"]
    return payload["artifact"]


def test_vulnerability_export_supports_all_formats(client, auth_header, admin_user, sample_vulnerabilities):
    for export_format, expected_type in (("csv", "text/csv"), ("json", "application/json"), ("pdf", "application/pdf")):
        artifact = _create_export(
            client,
            auth_header,
            admin_user,
            f"/api/reports/vulnerabilities/export?severity=Critical,High&status=Open,In Progress&format={export_format}",
        )

        assert artifact["format"] == export_format
        download = client.get(artifact["download_url"], headers=auth_header(admin_user))
        assert download.status_code == 200
        assert download.headers["Content-Type"].startswith(expected_type)

        if export_format == "csv":
            rows = _parse_csv_rows(download.get_data(as_text=True))
            assert {row["cve_id"] for row in rows} == {"CVE-2026-3001", "CVE-2026-3002"}


def test_dashboard_export_supports_all_formats(client, auth_header, admin_user, sample_vulnerabilities):
    for export_format, expected_type in (("csv", "text/csv"), ("json", "application/json"), ("pdf", "application/pdf")):
        artifact = _create_export(
            client,
            auth_header,
            admin_user,
            f"/api/reports/dashboard/export?severity=Critical&format={export_format}",
        )
        download = client.get(artifact["download_url"], headers=auth_header(admin_user))
        assert download.status_code == 200
        assert download.headers["Content-Type"].startswith(expected_type)


def test_report_artifact_download_enforces_token_and_owner(client, auth_header, admin_user, user_factory, sample_vulnerabilities):
    viewer = user_factory(role="Viewer")
    analyst = user_factory(role="Analyst")
    artifact = _create_export(
        client,
        auth_header,
        analyst,
        "/api/reports/vulnerabilities/export?severity=Critical&format=csv",
    )

    route = artifact["download_url"].split("?", 1)[0]
    missing_token = client.get(route, headers=auth_header(analyst))
    assert missing_token.status_code == 403

    forbidden_user = client.get(artifact["download_url"], headers=auth_header(viewer))
    assert forbidden_user.status_code == 403

    forbidden_other_analyst = client.get(artifact["download_url"], headers=auth_header(admin_user))
    assert forbidden_other_analyst.status_code == 403


def test_vulnerability_export_rejects_invalid_assignee_filter(client, auth_header, admin_user, sample_vulnerabilities):
    resp = client.get(
        "/api/reports/vulnerabilities/export?assigned_to=not-an-int",
        headers=auth_header(admin_user),
    )

    assert resp.status_code == 400
    payload = resp.get_json()
    assert payload["error"] == "assigned_to must be a user id or 'unassigned'"


def test_dashboard_summary_export_rejects_invalid_sort_field(client, auth_header, admin_user, sample_vulnerabilities):
    resp = client.get(
        "/api/reports/dashboard/export?sort=not_a_field",
        headers=auth_header(admin_user),
    )

    assert resp.status_code == 400
    payload = resp.get_json()
    assert payload["error"].startswith("sort must be one of")
