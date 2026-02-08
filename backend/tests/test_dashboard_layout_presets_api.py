from backend.auth import create_user, generate_token
from backend.database import db


def _auth_header(user):
    token = generate_token(user.id, user.username, user.role, user.token_version, user.last_revoked_at)
    return {"Authorization": f"Bearer {token}"}


def _create_user(app, username, role="Analyst"):
    with app.app_context():
        user = create_user(username, f"{username}@example.com", "secret", role=role)
        db.session.refresh(user)
        db.session.expunge(user)
        return user


def test_dashboard_layout_presets_crud_and_default(app, client):
    user = _create_user(app, "layout_owner")

    create_resp = client.post(
        "/api/dashboard/layout-presets",
        headers=_auth_header(user),
        json={
            "name": "Daily board",
            "visibility": "private",
            "is_default": True,
            "widget_config_json": {"order": ["risk-overview"], "visibility": {}, "settings": {}},
        },
    )
    assert create_resp.status_code == 201
    created = create_resp.get_json()
    assert created["name"] == "Daily board"
    assert created["is_default"] is True

    list_resp = client.get("/api/dashboard/layout-presets", headers=_auth_header(user))
    assert list_resp.status_code == 200
    listed = list_resp.get_json()
    assert len(listed) == 1
    assert listed[0]["id"] == created["id"]

    update_resp = client.put(
        f"/api/dashboard/layout-presets/{created['id']}",
        headers=_auth_header(user),
        json={"name": "Weekly board", "visibility": "team"},
    )
    assert update_resp.status_code == 200
    updated = update_resp.get_json()
    assert updated["name"] == "Weekly board"
    assert updated["visibility"] == "team"

    default_resp = client.get("/api/dashboard/layout-presets/default", headers=_auth_header(user))
    assert default_resp.status_code == 200
    default_payload = default_resp.get_json()
    assert default_payload["default"]["id"] == created["id"]


def test_dashboard_layout_presets_visibility_access(app, client):
    owner = _create_user(app, "owner_user")
    viewer = _create_user(app, "viewer_user")

    private_resp = client.post(
        "/api/dashboard/layout-presets",
        headers=_auth_header(owner),
        json={"name": "Owner private", "visibility": "private", "widget_config_json": {"order": [], "visibility": {}, "settings": {}}},
    )
    assert private_resp.status_code == 201

    team_resp = client.post(
        "/api/dashboard/layout-presets",
        headers=_auth_header(owner),
        json={"name": "Owner team", "visibility": "team", "widget_config_json": {"order": [], "visibility": {}, "settings": {}}},
    )
    assert team_resp.status_code == 201

    list_resp = client.get("/api/dashboard/layout-presets", headers=_auth_header(viewer))
    assert list_resp.status_code == 200
    names = {item["name"] for item in list_resp.get_json()}
    assert "Owner team" in names
    assert "Owner private" not in names


def test_dashboard_layout_presets_forbid_non_owner_update(app, client):
    owner = _create_user(app, "preset_owner")
    other = _create_user(app, "preset_other")

    create_resp = client.post(
        "/api/dashboard/layout-presets",
        headers=_auth_header(owner),
        json={"name": "Locked", "visibility": "private", "widget_config_json": {"order": [], "visibility": {}, "settings": {}}},
    )
    preset_id = create_resp.get_json()["id"]

    update_resp = client.put(
        f"/api/dashboard/layout-presets/{preset_id}",
        headers=_auth_header(other),
        json={"name": "Attempt"},
    )
    assert update_resp.status_code == 403
