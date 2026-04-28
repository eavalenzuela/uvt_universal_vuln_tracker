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


def test_render_pdf_executive_summary_layout():
    from backend.services.pdf_charts import severity_donut, sla_bar

    pdf = render_pdf(
        "executive_summary",
        {
            "title": "UVT Executive Summary",
            "report_type": "vulnerabilities",
            "kpi": {"total_open": 5, "critical_open": 2, "sla_compliance_pct": 80.0, "new_in_period": 1},
            "period_days": 14,
            "severity_chart": severity_donut({"Critical": 2, "High": 3}),
            "sla_chart": sla_bar({"on_track": 4, "at_risk": 1, "breached": 0}),
            "rows": [
                {
                    "cve_id": "CVE-2026-9001",
                    "title": "demo",
                    "severity": "High",
                    "cvss_score": 7.4,
                    "status": "Open",
                    "assigned_to": "alice",
                    "published_date": "2026-04-01T00:00:00",
                }
            ],
            "branding": {"primary_color": "#2563eb", "footer_text": "UVT", "logo_data_uri": None},
        },
    )
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 5000


def test_render_pdf_executive_summary_includes_top_components():
    pdf = render_pdf(
        "executive_summary",
        {
            "title": "UVT Executive Summary",
            "report_type": "vulnerabilities",
            "kpi": {"total_open": 3, "critical_open": 1, "sla_compliance_pct": 100.0, "new_in_period": 0},
            "period_days": 14,
            "severity_chart": None,
            "sla_chart": None,
            "trend_chart": None,
            "top_components": [
                {"name": "lodash", "ecosystem": "npm", "open_count": 4},
                {"name": "django", "ecosystem": "pypi", "open_count": 2},
            ],
            "rows": [],
            "branding": {"primary_color": "#2563eb", "footer_text": "", "logo_data_uri": None},
        },
    )
    assert pdf.startswith(b"%PDF-")


def test_render_pdf_executive_summary_handles_no_charts():
    pdf = render_pdf(
        "executive_summary",
        {
            "title": "UVT Executive Summary",
            "report_type": "vulnerabilities",
            "kpi": {"total_open": 0, "critical_open": 0, "sla_compliance_pct": None, "new_in_period": 0},
            "period_days": 14,
            "severity_chart": None,
            "sla_chart": None,
            "rows": [],
            "branding": {"primary_color": "#2563eb", "footer_text": "", "logo_data_uri": None},
        },
    )
    assert pdf.startswith(b"%PDF-")
