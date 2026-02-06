import csv
import io


def _parse_csv_rows(content: str):
    return list(csv.DictReader(io.StringIO(content)))


def test_vulnerability_export_applies_multi_filters(client, auth_header, admin_user, sample_vulnerabilities):
    resp = client.get(
        "/api/reports/vulnerabilities/export?severity=Critical,High&status=Open,In Progress",
        headers=auth_header(admin_user),
    )

    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/csv")

    rows = _parse_csv_rows(resp.get_data(as_text=True))
    assert {row["cve_id"] for row in rows} == {"CVE-2026-3001", "CVE-2026-3002"}


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
