from backend.auth import generate_token, hash_password
from backend.database import db
from backend.models import Product, ProductVersion, SoftwareComponent, ComponentDependency, User


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


def _seed_product_version(app, admin):
    with app.app_context():
        product = Product(name="TestApp", description="Test", created_by=admin.id)
        db.session.add(product)
        db.session.flush()
        version = ProductVersion(product_id=product.id, version="1.0.0")
        db.session.add(version)
        db.session.commit()
        return version.id


def _seed_components(app, pv_id):
    with app.app_context():
        parent = SoftwareComponent(product_version_id=pv_id, name="flask", version="3.0.0", ecosystem="pypi", component_type="library", bom_ref="flask-3")
        child = SoftwareComponent(product_version_id=pv_id, name="werkzeug", version="3.0.1", ecosystem="pypi", component_type="library", bom_ref="werkzeug-3")
        db.session.add_all([parent, child])
        db.session.flush()
        dep = ComponentDependency(product_version_id=pv_id, parent_component_id=parent.id, child_component_id=child.id, depth=1, is_direct=True)
        db.session.add(dep)
        db.session.commit()
        return parent.id, child.id


def test_list_components(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)
    pv_id = _seed_product_version(app, admin)
    _seed_components(app, pv_id)

    resp = client.get(f"/api/product_versions/{pv_id}/components", headers=headers)
    assert resp.status_code == 200
    components = resp.get_json()
    assert len(components) == 2
    names = {c["name"] for c in components}
    assert "flask" in names
    assert "werkzeug" in names


def test_list_components_includes_dependencies(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)
    pv_id = _seed_product_version(app, admin)
    _seed_components(app, pv_id)

    resp = client.get(f"/api/product_versions/{pv_id}/components", headers=headers)
    flask_component = next(c for c in resp.get_json() if c["name"] == "flask")
    assert len(flask_component["dependencies"]) == 1


def test_list_components_404_for_missing_version(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    resp = client.get("/api/product_versions/99999/components", headers=headers)
    assert resp.status_code == 404


def test_dependency_graph(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)
    pv_id = _seed_product_version(app, admin)
    _seed_components(app, pv_id)

    resp = client.get(f"/api/product_versions/{pv_id}/dependency_graph", headers=headers)
    assert resp.status_code == 200
    graph = resp.get_json()
    assert "nodes" in graph
    assert "edges" in graph
    assert "root_node_ids" in graph
    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 1


def test_sbom_import_validation(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)
    pv_id = _seed_product_version(app, admin)

    # Invalid format
    resp = client.post(f"/api/product_versions/{pv_id}/sbom", headers=headers, json={
        "format": "invalid",
        "sbom": {},
    })
    assert resp.status_code == 400

    # Missing sbom object
    resp = client.post(f"/api/product_versions/{pv_id}/sbom", headers=headers, json={
        "format": "cyclonedx",
        "sbom": "not-an-object",
    })
    assert resp.status_code == 400


def test_compare_components_requires_params(app, client):
    admin = _make_user(app, "Admin")
    headers = _headers(admin)

    resp = client.get("/api/product_versions/compare/components", headers=headers)
    assert resp.status_code == 400
