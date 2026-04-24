import io
import json

from backend.database import db
from backend.models import Vulnerability


NESSUS_SAMPLE = b"""<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Report name="pytest">
    <ReportHost name="host-1">
      <ReportItem port="443" svc_name="https" protocol="tcp"
                  severity="4" pluginID="12345" pluginName="OpenSSL Heartbleed"
                  pluginFamily="Web Servers">
        <risk_factor>Critical</risk_factor>
        <cvss3_base_score>9.4</cvss3_base_score>
        <cve>CVE-2014-0160</cve>
        <synopsis>The remote host has OpenSSL vulnerability.</synopsis>
        <description>Full description here.</description>
        <plugin_publication_date>2014-04-07</plugin_publication_date>
      </ReportItem>
      <ReportItem port="0" pluginID="99" pluginName="Info Item" severity="1">
        <risk_factor>Low</risk_factor>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def test_list_supported_scanners(client, admin_user, auth_header):
    resp = client.get("/api/imports", headers=auth_header(admin_user))
    assert resp.status_code == 200
    assert set(resp.get_json()["supported"]) == {"nessus", "qualys", "trivy"}


def test_viewer_cannot_import(client, user_factory, auth_header):
    viewer = user_factory(role="Viewer")
    resp = client.post(
        "/api/imports/nessus",
        data={"file": (io.BytesIO(NESSUS_SAMPLE), "sample.nessus")},
        content_type="multipart/form-data",
        headers=auth_header(viewer),
    )
    assert resp.status_code == 403


def test_import_nessus_creates_vulns(app, client, admin_user, auth_header):
    resp = client.post(
        "/api/imports/nessus",
        data={"file": (io.BytesIO(NESSUS_SAMPLE), "sample.nessus")},
        content_type="multipart/form-data",
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 202, resp.get_json()
    body = resp.get_json()
    assert body["vulnerabilities_ingested"] == 2

    with app.app_context():
        assert Vulnerability.query.filter_by(cve_id="CVE-2014-0160").first() is not None


def test_import_qualys_csv(app, client, admin_user, auth_header):
    csv_bytes = (
        "Title,QID,CVE ID,Severity,CVSS Base,Description,First Detected,Last Detected\n"
        'OpenSSH vuln,38909,"CVE-2024-6387",High,8.1,Sample finding,2024-07-01,2024-07-10\n'
        ",12345,CVE-2024-0001,Medium,5.0,No title but has QID,2024-01-01,2024-01-02\n"
    ).encode("utf-8")

    resp = client.post(
        "/api/imports/qualys",
        data={"file": (io.BytesIO(csv_bytes), "report.csv")},
        content_type="multipart/form-data",
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 202, resp.get_json()
    # Second row has no title — should fall back to "QID ..." so both ingest.
    assert resp.get_json()["vulnerabilities_ingested"] == 2

    with app.app_context():
        assert Vulnerability.query.filter_by(cve_id="CVE-2024-6387").first() is not None


def test_import_trivy_json(app, client, admin_user, auth_header):
    trivy_payload = {
        "Results": [
            {
                "Target": "image",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-2222",
                        "Title": "libfoo RCE",
                        "Severity": "HIGH",
                        "CVSS": {"nvd": {"V3Score": 8.8}},
                    }
                ],
            }
        ]
    }
    data = json.dumps(trivy_payload).encode("utf-8")
    resp = client.post(
        "/api/imports/trivy",
        data={"file": (io.BytesIO(data), "scan.json")},
        content_type="multipart/form-data",
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 202
    assert resp.get_json()["vulnerabilities_ingested"] == 1


def test_unknown_scanner_rejected(client, admin_user, auth_header):
    resp = client.post(
        "/api/imports/burp",
        data={"file": (io.BytesIO(b"x"), "f.xml")},
        content_type="multipart/form-data",
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 400


def test_missing_file_rejected(client, admin_user, auth_header):
    resp = client.post(
        "/api/imports/nessus",
        data={},
        content_type="multipart/form-data",
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 400


def test_invalid_nessus_xml_rejected(client, admin_user, auth_header):
    resp = client.post(
        "/api/imports/nessus",
        data={"file": (io.BytesIO(b"<not-valid"), "broken.nessus")},
        content_type="multipart/form-data",
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 422
