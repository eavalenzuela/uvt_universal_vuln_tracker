from __future__ import annotations

import pytest

from backend.api.validation import ValidationError
from backend.database import db
from backend.models import Vulnerability
from backend.services import vuln_ingest
from backend.services.vuln_ingest import NormalizedVuln


def test_upsert_vulnerability_commits_once(app, monkeypatch):
    with app.app_context():
        commit_calls = 0
        original_commit = db.session.commit

        def tracked_commit():
            nonlocal commit_calls
            commit_calls += 1
            return original_commit()

        monkeypatch.setattr(db.session, "commit", tracked_commit)

        vuln_ingest.upsert_vulnerability(
            NormalizedVuln(cve_id="CVE-2026-0001", title="Single ingest vuln"),
            source="unit-test",
            source_id="single-1",
        )

        assert commit_calls == 1
        assert Vulnerability.query.filter_by(cve_id="CVE-2026-0001").count() == 1


def test_upsert_vulnerabilities_commits_once_per_batch(app, monkeypatch):
    with app.app_context():
        commit_calls = 0
        original_commit = db.session.commit

        def tracked_commit():
            nonlocal commit_calls
            commit_calls += 1
            return original_commit()

        monkeypatch.setattr(db.session, "commit", tracked_commit)

        result = vuln_ingest.upsert_vulnerabilities(
            [
                NormalizedVuln(cve_id="CVE-2026-1001", title="Batch vuln 1"),
                NormalizedVuln(cve_id="CVE-2026-1002", title="Batch vuln 2"),
            ],
            source="unit-test",
        )

        assert len(result) == 2
        assert commit_calls == 1
        assert Vulnerability.query.filter(Vulnerability.cve_id.in_(["CVE-2026-1001", "CVE-2026-1002"])).count() == 2


def test_upsert_vulnerabilities_rolls_back_on_error(app, monkeypatch):
    with app.app_context():
        original_upsert = vuln_ingest._upsert_vulnerability_no_commit
        rollback_calls = 0
        original_rollback = db.session.rollback

        def tracked_rollback():
            nonlocal rollback_calls
            rollback_calls += 1
            return original_rollback()

        state = {"calls": 0}

        def fail_on_second(*args, **kwargs):
            state["calls"] += 1
            if state["calls"] == 2:
                raise RuntimeError("boom")
            return original_upsert(*args, **kwargs)

        monkeypatch.setattr(vuln_ingest, "_upsert_vulnerability_no_commit", fail_on_second)
        monkeypatch.setattr(db.session, "rollback", tracked_rollback)

        with pytest.raises(RuntimeError, match="boom"):
            vuln_ingest.upsert_vulnerabilities(
                [
                    NormalizedVuln(cve_id="CVE-2026-2001", title="Will rollback 1"),
                    NormalizedVuln(cve_id="CVE-2026-2002", title="Will rollback 2"),
                ],
                source="unit-test",
            )

        assert rollback_calls == 1
        assert Vulnerability.query.filter(Vulnerability.cve_id.in_(["CVE-2026-2001", "CVE-2026-2002"])).count() == 0


def test_upsert_vulnerabilities_invalid_cve_rolls_back_and_raises(app):
    with app.app_context():
        with pytest.raises(ValidationError) as exc_info:
            vuln_ingest.upsert_vulnerabilities(
                [
                    NormalizedVuln(cve_id="CVE-2026-3001", title="Valid first"),
                    NormalizedVuln(cve_id="invalid-cve", title="Invalid second"),
                ],
                source="unit-test",
            )

        assert exc_info.value.field == "cve_id"
        assert exc_info.value.error == "cve_id must match CVE-YYYY-NNNN format"
        assert Vulnerability.query.filter_by(cve_id="CVE-2026-3001").count() == 0
        assert Vulnerability.query.filter_by(title="Invalid second").count() == 0
