from backend.auth import generate_token, hash_password
from backend.database import db
from backend.models import AttackVector, User, Vulnerability, VulnerabilityAttackVector, ProductVersion, Product


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


def test_attack_vector_crud(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    # Create
    resp = client.post("/api/attack_vectors", headers=headers, json={"name": "Phishing", "description": "Social engineering"})
    assert resp.status_code == 201
    vector = resp.get_json()
    assert vector["name"] == "Phishing"
    assert vector["description"] == "Social engineering"
    vector_id = vector["id"]

    # List
    resp = client.get("/api/attack_vectors", headers=headers)
    assert resp.status_code == 200
    assert any(v["id"] == vector_id for v in resp.get_json())

    # Get
    resp = client.get(f"/api/attack_vectors/{vector_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "Phishing"

    # Update
    resp = client.patch(f"/api/attack_vectors/{vector_id}", headers=headers, json={"name": "Spear Phishing"})
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "Spear Phishing"

    # Delete
    resp = client.delete(f"/api/attack_vectors/{vector_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True

    # Verify deleted
    resp = client.get(f"/api/attack_vectors/{vector_id}", headers=headers)
    assert resp.status_code == 404


def test_attack_vector_validation(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    # Empty name
    resp = client.post("/api/attack_vectors", headers=headers, json={"name": ""})
    assert resp.status_code == 400

    # Create then update with empty name
    resp = client.post("/api/attack_vectors", headers=headers, json={"name": "Valid"})
    vid = resp.get_json()["id"]
    resp = client.patch(f"/api/attack_vectors/{vid}", headers=headers, json={"name": ""})
    assert resp.status_code == 400


def test_attack_vector_role_enforcement(app, client):
    viewer = _make_user(app, "Viewer")
    headers = _headers(viewer)

    resp = client.post("/api/attack_vectors", headers=headers, json={"name": "Blocked"})
    assert resp.status_code == 403

    resp = client.get("/api/attack_vectors", headers=headers)
    assert resp.status_code == 200


def test_vulnerability_attack_vector_mapping(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    with app.app_context():
        vuln = Vulnerability(cve_id="CVE-2026-9001", title="Test", severity="High", status="Open", created_by=admin.id)
        vector = AttackVector(name="Network")
        db.session.add_all([vuln, vector])
        db.session.commit()
        vuln_id, vector_id = vuln.id, vector.id

    # Attach
    resp = client.post(f"/api/vulnerabilities/{vuln_id}/attack_vectors", headers=headers, json={
        "mappings": [{"attack_vector_id": vector_id}]
    })
    assert resp.status_code == 200
    assert resp.get_json()["added"] == 1

    # Duplicate attach should add 0
    resp = client.post(f"/api/vulnerabilities/{vuln_id}/attack_vectors", headers=headers, json={
        "mappings": [{"attack_vector_id": vector_id}]
    })
    assert resp.get_json()["added"] == 0

    # List mappings
    resp = client.get(f"/api/vulnerabilities/{vuln_id}/attack_vectors", headers=headers)
    assert resp.status_code == 200
    mappings = resp.get_json()
    assert len(mappings) == 1
    mapping_id = mappings[0]["id"]

    # Delete mapping
    resp = client.delete(f"/api/vulnerabilities/{vuln_id}/attack_vectors/{mapping_id}", headers=headers)
    assert resp.status_code == 200


def test_attach_invalid_attack_vector(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    with app.app_context():
        vuln = Vulnerability(cve_id="CVE-2026-9002", title="Test", severity="High", status="Open", created_by=admin.id)
        db.session.add(vuln)
        db.session.commit()
        vuln_id = vuln.id

    resp = client.post(f"/api/vulnerabilities/{vuln_id}/attack_vectors", headers=headers, json={
        "mappings": [{"attack_vector_id": 99999}]
    })
    assert resp.status_code == 400
