import pytest

from backend.database import db
from backend.models import (
    ComponentDependency,
    Product,
    ProductVersion,
    SoftwareComponent,
    Vulnerability,
    VulnerabilityComponent,
)
from backend.services.sbom_ingest import (
    SbomFormatError,
    ingest_sbom,
    _parse_cyclonedx,
    _parse_spdx,
    _ecosystem_from_purl,
    _compute_depths,
)


# ---------------------------------------------------------------------------
# _ecosystem_from_purl
# ---------------------------------------------------------------------------

def test_ecosystem_from_purl_extracts_type():
    assert _ecosystem_from_purl("pkg:pypi/flask@2.0") == "pypi"
    assert _ecosystem_from_purl("pkg:npm/lodash@4.17.21") == "npm"
    assert _ecosystem_from_purl("pkg:maven/org.apache/commons@1.0") == "maven"


def test_ecosystem_from_purl_returns_none_for_invalid():
    assert _ecosystem_from_purl(None) is None
    assert _ecosystem_from_purl("") is None
    assert _ecosystem_from_purl("not-a-purl") is None
    assert _ecosystem_from_purl(123) is None


# ---------------------------------------------------------------------------
# _compute_depths
# ---------------------------------------------------------------------------

def test_compute_depths_simple_graph():
    graph = {"A": ["B", "C"], "B": ["D"], "C": []}
    depths = _compute_depths("A", graph)
    assert depths["B"] == 1
    assert depths["C"] == 1
    assert depths["D"] == 2


def test_compute_depths_handles_cycles():
    graph = {"A": ["B"], "B": ["A"]}
    depths = _compute_depths("A", graph)
    assert depths["B"] == 1


def test_compute_depths_empty_graph():
    assert _compute_depths("A", {}) == {}


# ---------------------------------------------------------------------------
# _parse_cyclonedx
# ---------------------------------------------------------------------------

def test_parse_cyclonedx_extracts_components():
    payload = {
        "components": [
            {"bom-ref": "ref-1", "name": "flask", "version": "2.0", "purl": "pkg:pypi/flask@2.0", "type": "library"},
            {"bom-ref": "ref-2", "name": "requests", "version": "1.0"},
        ],
        "dependencies": [
            {"ref": "ref-1", "dependsOn": ["ref-2"]},
        ],
    }
    result = _parse_cyclonedx(payload)
    assert len(result["components"]) == 2
    assert result["components"][0]["name"] == "flask"
    assert result["components"][0]["bom_ref"] == "ref-1"
    assert result["components"][0]["ecosystem"] == "pypi"
    assert result["dependencies"] == {"ref-1": ["ref-2"]}


def test_parse_cyclonedx_extracts_cves_from_properties():
    payload = {
        "components": [
            {
                "name": "libfoo",
                "properties": [
                    {"name": "uvt:cve", "value": "CVE-2026-0001"},
                    {"name": "other", "value": "ignored"},
                ],
            },
        ],
    }
    result = _parse_cyclonedx(payload)
    assert result["components"][0]["metadata"]["cves"] == ["CVE-2026-0001"]


def test_parse_cyclonedx_rejects_missing_components():
    with pytest.raises(SbomFormatError, match="components array"):
        _parse_cyclonedx({"not_components": []})


def test_parse_cyclonedx_skips_invalid_entries():
    payload = {
        "components": [
            "not a dict",
            {"name": ""},
            {"name": None},
            {"version": "1.0"},  # no name
            {"name": "valid", "version": "1.0"},
        ],
    }
    result = _parse_cyclonedx(payload)
    assert len(result["components"]) == 1
    assert result["components"][0]["name"] == "valid"


def test_parse_cyclonedx_handles_missing_dependencies():
    payload = {"components": [{"name": "lib", "version": "1.0"}]}
    result = _parse_cyclonedx(payload)
    assert result["dependencies"] == {}


# ---------------------------------------------------------------------------
# _parse_spdx
# ---------------------------------------------------------------------------

def test_parse_spdx_extracts_packages():
    payload = {
        "packages": [
            {
                "SPDXID": "SPDXRef-pkg1",
                "name": "flask",
                "versionInfo": "2.0",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:pypi/flask@2.0"},
                    {"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:*:flask:2.0"},
                ],
            },
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-pkg1", "relationshipType": "DEPENDS_ON"},
            {"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-pkg2", "relationshipType": "DESCRIBED_BY"},
        ],
    }
    result = _parse_spdx(payload)
    assert len(result["components"]) == 1
    comp = result["components"][0]
    assert comp["name"] == "flask"
    assert comp["purl"] == "pkg:pypi/flask@2.0"
    assert comp["cpe"] == "cpe:2.3:a:*:flask:2.0"
    assert comp["bom_ref"] == "SPDXRef-pkg1"
    # Only DEPENDS_ON relationships included
    assert result["dependencies"] == {"SPDXRef-root": ["SPDXRef-pkg1"]}


def test_parse_spdx_rejects_missing_packages():
    with pytest.raises(SbomFormatError, match="packages array"):
        _parse_spdx({"not_packages": []})


def test_parse_spdx_skips_invalid_entries():
    payload = {
        "packages": [
            "not a dict",
            {"name": ""},
            {"SPDXID": "ref", "name": "valid"},
        ],
    }
    result = _parse_spdx(payload)
    assert len(result["components"]) == 1


# ---------------------------------------------------------------------------
# Full ingest_sbom integration
# ---------------------------------------------------------------------------

def test_ingest_sbom_cyclonedx(app, admin_user):
    with app.app_context():
        product = Product(name="Ingest-Test", description="d", created_by=admin_user.id)
        db.session.add(product)
        db.session.flush()
        pv = ProductVersion(product_id=product.id, version="1.0")
        db.session.add(pv)
        db.session.commit()

        sbom = {
            "components": [
                {"bom-ref": "c1", "name": "libA", "version": "1.0", "purl": "pkg:pypi/libA@1.0"},
                {"bom-ref": "c2", "name": "libB", "version": "2.0"},
            ],
            "dependencies": [
                {"ref": "c1", "dependsOn": ["c2"]},
            ],
        }

        result = ingest_sbom(product_version_id=pv.id, sbom_payload=sbom, fmt="cyclonedx")
        assert result["components_ingested"] == 2
        assert result["dependencies_ingested"] == 1

        assert SoftwareComponent.query.filter_by(product_version_id=pv.id).count() == 2
        assert ComponentDependency.query.filter_by(product_version_id=pv.id).count() == 1

        dep = ComponentDependency.query.filter_by(product_version_id=pv.id).first()
        assert dep.is_direct is True
        assert dep.depth == 1


def test_ingest_sbom_spdx(app, admin_user):
    with app.app_context():
        product = Product(name="Ingest-SPDX", description="d", created_by=admin_user.id)
        db.session.add(product)
        db.session.flush()
        pv = ProductVersion(product_id=product.id, version="1.0")
        db.session.add(pv)
        db.session.commit()

        sbom = {
            "packages": [
                {"SPDXID": "SPDXRef-A", "name": "libA", "versionInfo": "1.0"},
                {"SPDXID": "SPDXRef-B", "name": "libB", "versionInfo": "2.0"},
            ],
            "relationships": [
                {"spdxElementId": "SPDXRef-A", "relatedSpdxElement": "SPDXRef-B", "relationshipType": "DEPENDS_ON"},
            ],
        }

        result = ingest_sbom(product_version_id=pv.id, sbom_payload=sbom, fmt="spdx")
        assert result["components_ingested"] == 2
        assert result["dependencies_ingested"] == 1


def test_ingest_sbom_maps_vulnerabilities(app, admin_user):
    with app.app_context():
        product = Product(name="Ingest-Vuln", description="d", created_by=admin_user.id)
        db.session.add(product)
        db.session.flush()
        pv = ProductVersion(product_id=product.id, version="1.0")
        db.session.add(pv)
        db.session.flush()

        vuln = Vulnerability(
            cve_id="CVE-2026-1234", title="Test", severity="High", status="Open", created_by=admin_user.id,
        )
        db.session.add(vuln)
        db.session.commit()

        sbom = {
            "components": [
                {
                    "bom-ref": "c1",
                    "name": "libVuln",
                    "version": "1.0",
                    "properties": [{"name": "uvt:cve", "value": "CVE-2026-1234"}],
                },
            ],
        }

        result = ingest_sbom(product_version_id=pv.id, sbom_payload=sbom, fmt="cyclonedx")
        assert result["vulnerabilities_mapped"] == 1
        assert VulnerabilityComponent.query.filter_by(vulnerability_id=vuln.id).count() == 1


def test_ingest_sbom_unknown_product_version_raises(app):
    with app.app_context():
        with pytest.raises(SbomFormatError, match="Unknown product version"):
            ingest_sbom(product_version_id=99999, sbom_payload={"components": []}, fmt="cyclonedx")


def test_ingest_sbom_upserts_existing_components(app, admin_user):
    with app.app_context():
        product = Product(name="Upsert-Test", description="d", created_by=admin_user.id)
        db.session.add(product)
        db.session.flush()
        pv = ProductVersion(product_id=product.id, version="1.0")
        db.session.add(pv)
        db.session.commit()

        sbom = {
            "components": [
                {"bom-ref": "c1", "name": "libA", "version": "1.0"},
            ],
        }
        ingest_sbom(product_version_id=pv.id, sbom_payload=sbom, fmt="cyclonedx")
        assert SoftwareComponent.query.filter_by(product_version_id=pv.id).count() == 1

        # Ingest again with updated version
        sbom["components"][0]["version"] = "2.0"
        ingest_sbom(product_version_id=pv.id, sbom_payload=sbom, fmt="cyclonedx")
        assert SoftwareComponent.query.filter_by(product_version_id=pv.id).count() == 1

        comp = SoftwareComponent.query.filter_by(product_version_id=pv.id).first()
        assert comp.version == "2.0"
