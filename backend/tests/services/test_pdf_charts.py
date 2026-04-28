from backend.services.pdf_charts import severity_donut, sla_bar


def test_severity_donut_returns_data_uri():
    out = severity_donut({"Critical": 2, "High": 5, "Medium": 1})
    assert out is not None
    assert out.startswith("data:image/png;base64,")
    assert len(out) > 200


def test_severity_donut_returns_none_when_empty():
    assert severity_donut({}) is None
    assert severity_donut({"Critical": 0, "High": 0}) is None


def test_sla_bar_returns_data_uri():
    out = sla_bar({"on_track": 10, "at_risk": 3, "breached": 1})
    assert out is not None
    assert out.startswith("data:image/png;base64,")


def test_sla_bar_returns_none_when_empty():
    assert sla_bar({"on_track": 0, "at_risk": 0, "breached": 0}) is None
    assert sla_bar({}) is None


def test_trend_line_returns_data_uri():
    from backend.services.pdf_charts import trend_line
    buckets = [
        {"date": "2026-04-14", "count": 2},
        {"date": "2026-04-15", "count": 5},
        {"date": "2026-04-16", "count": 3},
        {"date": "2026-04-17", "count": 7},
    ]
    out = trend_line(buckets)
    assert out is not None
    assert out.startswith("data:image/png;base64,")


def test_trend_line_returns_none_when_empty():
    from backend.services.pdf_charts import trend_line
    assert trend_line([]) is None
    assert trend_line([{"date": "2026-04-14", "count": 0}]) is None
