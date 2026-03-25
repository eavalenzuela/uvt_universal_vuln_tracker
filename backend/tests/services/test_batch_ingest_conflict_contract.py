from backend.models import Vulnerability, VulnerabilitySource
from backend.services.vuln_ingest import NormalizedVuln, upsert_vulnerabilities


def test_batch_ingest_merges_duplicate_cve_ids(app):
    with app.app_context():
        results = upsert_vulnerabilities(
            [
                NormalizedVuln(cve_id="CVE-2026-5555", title="First title", severity="Low"),
                NormalizedVuln(cve_id="CVE-2026-5555", title="Updated title", severity="Critical"),
            ],
            source="contract-test",
        )

        assert len(results) == 2
        assert results[0].id == results[1].id

        stored = Vulnerability.query.filter_by(cve_id="CVE-2026-5555").one()
        assert stored.title == "Updated title"
        assert stored.severity == "Critical"
        assert Vulnerability.query.filter_by(cve_id="CVE-2026-5555").count() == 1

        sources = VulnerabilitySource.query.filter_by(vulnerability_id=stored.id, source="contract-test").all()
        assert len(sources) == 1
        assert sources[0].source_id == "CVE-2026-5555"


def test_batch_ingest_title_conflict_updates_existing_record(app):
    with app.app_context():
        upsert_vulnerabilities(
            [NormalizedVuln(cve_id=None, title="Shared title", severity="Low")],
            source="contract-test",
        )

        upsert_vulnerabilities(
            [NormalizedVuln(cve_id=None, title="Shared title", severity="High", description="updated")],
            source="contract-test",
        )

        stored = Vulnerability.query.filter_by(title="Shared title").one()
        assert stored.severity == "High"
        assert stored.description == "updated"
        assert Vulnerability.query.filter_by(title="Shared title").count() == 1
