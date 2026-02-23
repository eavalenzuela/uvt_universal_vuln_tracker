from backend.services.reporting_service import parse_csv_ints, parse_iso_datetime


def test_parse_csv_ints_parses_values():
    assert parse_csv_ints("1, 2,3") == [1, 2, 3]


def test_parse_csv_ints_rejects_bad_values():
    try:
        parse_csv_ints("1,two")
    except ValueError as exc:
        assert "integer ids" in str(exc)
    else:
        raise AssertionError("ValueError expected")


def test_parse_iso_datetime_rejects_bad_value():
    try:
        parse_iso_datetime("bad", field="start_date")
    except ValueError as exc:
        assert "start_date" in str(exc)
    else:
        raise AssertionError("ValueError expected")
