from backend.database import db
from backend.models import (
    Product,
    ProductVersion,
    SoftwareComponent,
    Vulnerability,
    VulnerabilityComponent,
)
from backend.services.component_correlation import (
    correlate_vulnerability_to_components,
    _extract_candidate_cpes,
    _extract_candidate_purls,
)


# ---------------------------------------------------------------------------
# Helper extraction functions
# ---------------------------------------------------------------------------

def test_extract_candidate_purls_from_nested_payload():
    payload = {
        "configurations": [
            {"nodes": [{"purl": "pkg:pypi/flask@2.0"}]},
        ],
        "purl": "pkg:pypi/requests@1.0",
    }
    result = _extract_candidate_purls(payload)
    assert result == {"pkg:pypi/flask@2.0", "pkg:pypi/requests@1.0"}


def test_extract_candidate_purls_returns_empty_for_none():
    assert _extract_candidate_purls(None) == set()


def test_extract_candidate_cpes_from_nested_payload():
    payload = {
        "nodes": [
            {"cpe23Uri": "cpe:2.3:a:vendor:product:1.0"},
            {"criteria": "cpe:2.3:a:other:lib:2.0"},
            {"cpe": "cpe:2.3:a:third:pkg:3.0"},
        ],
    }
    result = _extract_candidate_cpes(payload)
    assert "cpe:2.3:a:vendor:product:1.0" in result
    assert "cpe:2.3:a:other:lib:2.0" in result
    assert "cpe:2.3:a:third:pkg:3.0" in result


def test_extract_candidate_cpes_returns_empty_for_none():
    assert _extract_candidate_cpes(None) == set()


def test_extract_ignores_non_string_values():
    payload = {"purl": 123, "cpe": None}
    assert _extract_candidate_purls(payload) == set()
    assert _extract_candidate_cpes(payload) == set()


# ---------------------------------------------------------------------------
# Full correlation with DB
# ---------------------------------------------------------------------------

def test_returns_zero_when_cve_id_is_none(app):
    with app.app_context():
        vuln = Vulnerability(title="No CVE", severity="Low", status="Open")
        db.session.add(vuln)
        db.session.flush()
        assert correlate_vulnerability_to_components(vuln, source="test", cve_id=None) == 0


def test_correlate_by_sbom_cve_metadata(app, admin_user):
    with app.app_context():
        product = Product(name="P", description="d", created_by=admin_user.id)
        db.session.add(product)
        db.session.flush()
        pv = ProductVersion(product_id=product.id, version="1.0")
        db.session.add(pv)
        db.session.flush()

        comp = SoftwareComponent(
            product_version_id=pv.id,
            bom_ref="comp-1",
            name="libfoo",
            metadata_json={"cves": ["CVE-2026-9999"]},
        )
        db.session.add(comp)
        db.session.flush()

        vuln = Vulnerability(cve_id="CVE-2026-9999", title="V", severity="High", status="Open", created_by=admin_user.id)
        db.session.add(vuln)
        db.session.flush()

        linked = correlate_vulnerability_to_components(
            vuln, source="test", cve_id="CVE-2026-9999", product_version_id=pv.id,
        )
        assert linked == 1

        vc = VulnerabilityComponent.query.filter_by(vulnerability_id=vuln.id).first()
        assert vc is not None
        assert vc.match_type == "sbom_cve"
        assert vc.source == "test"


def test_correlate_by_purl(app, admin_user):
    with app.app_context():
        product = Product(name="P2", description="d", created_by=admin_user.id)
        db.session.add(product)
        db.session.flush()
        pv = ProductVersion(product_id=product.id, version="2.0")
        db.session.add(pv)
        db.session.flush()

        comp = SoftwareComponent(
            product_version_id=pv.id,
            bom_ref="comp-purl",
            name="libbar",
            purl="pkg:pypi/libbar@1.0",
        )
        db.session.add(comp)
        db.session.flush()

        vuln = Vulnerability(cve_id="CVE-2026-8888", title="V2", severity="Medium", status="Open", created_by=admin_user.id)
        db.session.add(vuln)
        db.session.flush()

        payload = {"affected": [{"purl": "pkg:pypi/libbar@1.0"}]}
        linked = correlate_vulnerability_to_components(
            vuln, source="nvd", cve_id="CVE-2026-8888", raw_payload=payload, product_version_id=pv.id,
        )
        assert linked == 1

        vc = VulnerabilityComponent.query.filter_by(vulnerability_id=vuln.id).first()
        assert vc.match_type == "purl"


def test_correlate_by_cpe(app, admin_user):
    with app.app_context():
        product = Product(name="P3", description="d", created_by=admin_user.id)
        db.session.add(product)
        db.session.flush()
        pv = ProductVersion(product_id=product.id, version="3.0")
        db.session.add(pv)
        db.session.flush()

        comp = SoftwareComponent(
            product_version_id=pv.id,
            bom_ref="comp-cpe",
            name="libbaz",
            cpe="cpe:2.3:a:vendor:libbaz:1.0",
        )
        db.session.add(comp)
        db.session.flush()

        vuln = Vulnerability(cve_id="CVE-2026-7777", title="V3", severity="Low", status="Open", created_by=admin_user.id)
        db.session.add(vuln)
        db.session.flush()

        payload = {"configurations": [{"nodes": [{"criteria": "cpe:2.3:a:vendor:libbaz:1.0"}]}]}
        linked = correlate_vulnerability_to_components(
            vuln, source="nvd", cve_id="CVE-2026-7777", raw_payload=payload, product_version_id=pv.id,
        )
        assert linked == 1

        vc = VulnerabilityComponent.query.filter_by(vulnerability_id=vuln.id).first()
        assert vc.match_type == "cpe"


def test_correlate_updates_existing_link(app, admin_user):
    with app.app_context():
        product = Product(name="P4", description="d", created_by=admin_user.id)
        db.session.add(product)
        db.session.flush()
        pv = ProductVersion(product_id=product.id, version="4.0")
        db.session.add(pv)
        db.session.flush()

        comp = SoftwareComponent(
            product_version_id=pv.id,
            bom_ref="comp-dup",
            name="libdup",
            purl="pkg:pypi/libdup@1.0",
            metadata_json={"cves": ["CVE-2026-6666"]},
        )
        db.session.add(comp)
        db.session.flush()

        vuln = Vulnerability(cve_id="CVE-2026-6666", title="V4", severity="High", status="Open", created_by=admin_user.id)
        db.session.add(vuln)
        db.session.flush()

        # First correlation — sbom_cve match
        linked1 = correlate_vulnerability_to_components(
            vuln, source="test", cve_id="CVE-2026-6666", product_version_id=pv.id,
        )
        assert linked1 == 1

        # Second correlation with same source — should update, not create new
        linked2 = correlate_vulnerability_to_components(
            vuln, source="test", cve_id="CVE-2026-6666", product_version_id=pv.id,
        )
        assert linked2 == 0  # no new links

        assert VulnerabilityComponent.query.filter_by(vulnerability_id=vuln.id).count() == 1


def test_correlate_no_match_returns_zero(app, admin_user):
    with app.app_context():
        product = Product(name="P5", description="d", created_by=admin_user.id)
        db.session.add(product)
        db.session.flush()
        pv = ProductVersion(product_id=product.id, version="5.0")
        db.session.add(pv)
        db.session.flush()

        comp = SoftwareComponent(
            product_version_id=pv.id,
            bom_ref="comp-nomatch",
            name="libother",
        )
        db.session.add(comp)
        db.session.flush()

        vuln = Vulnerability(cve_id="CVE-2026-5555", title="V5", severity="Low", status="Open", created_by=admin_user.id)
        db.session.add(vuln)
        db.session.flush()

        linked = correlate_vulnerability_to_components(
            vuln, source="test", cve_id="CVE-2026-5555", product_version_id=pv.id,
        )
        assert linked == 0


def test_correlate_reads_dependency_path_from_metadata(app, admin_user):
    with app.app_context():
        product = Product(name="P6", description="d", created_by=admin_user.id)
        db.session.add(product)
        db.session.flush()
        pv = ProductVersion(product_id=product.id, version="6.0")
        db.session.add(pv)
        db.session.flush()

        comp = SoftwareComponent(
            product_version_id=pv.id,
            bom_ref="comp-path",
            name="libpath",
            metadata_json={"cves": ["CVE-2026-4444"], "dependency_path": "root > mid > libpath"},
        )
        db.session.add(comp)
        db.session.flush()

        vuln = Vulnerability(cve_id="CVE-2026-4444", title="V6", severity="Medium", status="Open", created_by=admin_user.id)
        db.session.add(vuln)
        db.session.flush()

        correlate_vulnerability_to_components(
            vuln, source="test", cve_id="CVE-2026-4444", product_version_id=pv.id,
        )

        vc = VulnerabilityComponent.query.filter_by(vulnerability_id=vuln.id).first()
        assert vc.dependency_path == "root > mid > libpath"
        assert vc.transitive_depth == 2
