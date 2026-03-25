from backend.auth import generate_token, hash_password
from backend.database import db
from backend.models import TerminalImpact, User, Vulnerability, VulnerabilityTerminalImpact


def _make_user(app, role="Admin"):
    with app.app_context():
        u = User(username=f"u_{role.lower()}", email=f"{role.lower()}@example.com", password_hash=hash_password("pw"), role=role)
        db.session.add(u)
        db.session.commit()
        db.session.refresh(u)
        db.session.expunge(u)
        return u


def _headers(user):
    token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    return {"Authorization": f"Bearer {token}"}


def test_terminal_impact_crud(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    # Create
    resp = client.post("/api/terminal_impacts", headers=headers, json={"name": "Data Loss", "description": "Permanent data destruction"})
    assert resp.status_code == 201
    impact = resp.get_json()
    assert impact["name"] == "Data Loss"
    impact_id = impact["id"]

    # List
    resp = client.get("/api/terminal_impacts", headers=headers)
    assert resp.status_code == 200
    assert any(i["id"] == impact_id for i in resp.get_json())

    # Get
    resp = client.get(f"/api/terminal_impacts/{impact_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "Data Loss"

    # Update
    resp = client.patch(f"/api/terminal_impacts/{impact_id}", headers=headers, json={"name": "Complete Data Loss"})
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "Complete Data Loss"

    # Delete
    resp = client.delete(f"/api/terminal_impacts/{impact_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True

    # Verify deleted
    resp = client.get(f"/api/terminal_impacts/{impact_id}", headers=headers)
    assert resp.status_code == 404


def test_terminal_impact_validation(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    resp = client.post("/api/terminal_impacts", headers=headers, json={"name": ""})
    assert resp.status_code == 400

    resp = client.post("/api/terminal_impacts", headers=headers, json={"name": "Valid"})
    tid = resp.get_json()["id"]
    resp = client.patch(f"/api/terminal_impacts/{tid}", headers=headers, json={"name": ""})
    assert resp.status_code == 400


def test_terminal_impact_role_enforcement(app, client):
    viewer = _make_user(app, "Viewer")
    headers = _headers(viewer)

    resp = client.post("/api/terminal_impacts", headers=headers, json={"name": "Blocked"})
    assert resp.status_code == 403

    resp = client.get("/api/terminal_impacts", headers=headers)
    assert resp.status_code == 200


def test_vulnerability_terminal_impact_mapping(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    with app.app_context():
        vuln = Vulnerability(cve_id="CVE-2026-8001", title="Test", severity="High", status="Open", created_by=admin.id)
        impact = TerminalImpact(name="Service Outage")
        db.session.add_all([vuln, impact])
        db.session.commit()
        vuln_id, impact_id = vuln.id, impact.id

    # Attach
    resp = client.post(f"/api/vulnerabilities/{vuln_id}/terminal_impacts", headers=headers, json={
        "terminal_impact_ids": [impact_id]
    })
    assert resp.status_code == 200
    assert resp.get_json()["added"] == 1

    # Duplicate attach
    resp = client.post(f"/api/vulnerabilities/{vuln_id}/terminal_impacts", headers=headers, json={
        "terminal_impact_ids": [impact_id]
    })
    assert resp.get_json()["added"] == 0

    # List
    resp = client.get(f"/api/vulnerabilities/{vuln_id}/terminal_impacts", headers=headers)
    assert resp.status_code == 200
    mappings = resp.get_json()
    assert len(mappings) == 1
    mapping_id = mappings[0]["id"]

    # Delete mapping
    resp = client.delete(f"/api/vulnerabilities/{vuln_id}/terminal_impacts/{mapping_id}", headers=headers)
    assert resp.status_code == 200


def test_attach_invalid_terminal_impact(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    with app.app_context():
        vuln = Vulnerability(cve_id="CVE-2026-8002", title="Test", severity="High", status="Open", created_by=admin.id)
        db.session.add(vuln)
        db.session.commit()
        vuln_id = vuln.id

    resp = client.post(f"/api/vulnerabilities/{vuln_id}/terminal_impacts", headers=headers, json={
        "terminal_impact_ids": [99999]
    })
    assert resp.status_code == 400
