from backend.services.pdf_renderer import render_pdf


def test_render_pdf_default_vulnerabilities_layout():
    rows = [
        {
            "cve_id": "CVE-2026-9001",
            "title": "Critical RCE in libfoo",
            "severity": "Critical",
            "cvss_score": 9.8,
            "status": "Open",
            "assigned_to": "alice",
            "published_date": "2026-04-01T00:00:00",
        }
    ]
    pdf = render_pdf(
        "default",
        {"title": "UVT Vulnerabilities Report", "report_type": "vulnerabilities", "rows": rows},
    )
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


def test_render_pdf_default_dashboard_layout():
    summary = {
        "total": 7,
        "by_severity": {"Critical": 2, "High": 3, "Medium": 1, "Low": 1},
        "by_status": {"Open": 5, "In Progress": 2},
    }
    pdf = render_pdf(
        "default",
        {"title": "UVT Dashboard Summary", "report_type": "dashboard_summary", "summary": summary},
    )
    assert pdf.startswith(b"%PDF-")


def test_render_pdf_handles_empty_rows():
    pdf = render_pdf(
        "default",
        {"title": "UVT Vulnerabilities Report", "report_type": "vulnerabilities", "rows": []},
    )
    assert pdf.startswith(b"%PDF-")
