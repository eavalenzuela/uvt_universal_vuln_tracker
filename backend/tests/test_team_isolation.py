"""F15 Phase 1 — team isolation tests.

Covers:
  1. Default-team posture: every user lands in Default, visibility unchanged.
  2. Cross-team deny: user in team A cannot see team B's products/vulns; 404 not 403.
  3. Admin bypass: Admins see every team.
  4. X-UVT-Team-Id header selects active team for writes; non-members fall back.
  5. Shared-pool vulns (team_id IS NULL) visible to every authenticated user.
"""

from __future__ import annotations

import pytest

from backend.database import db
from backend.models import Product, Team, UserTeam, Vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def default_team(app):
    with app.app_context():
        team = Team.query.filter_by(slug="default").first()
        assert team is not None, "Default team should be auto-seeded"
        db.session.expunge(team)
        return team


@pytest.fixture()
def two_teams(app):
    with app.app_context():
        team_a = Team(name="Alpha", slug="alpha", is_default=False)
        team_b = Team(name="Bravo", slug="bravo", is_default=False)
        db.session.add_all([team_a, team_b])
        db.session.commit()
        db.session.refresh(team_a)
        db.session.refresh(team_b)
        db.session.expunge(team_a)
        db.session.expunge(team_b)
        return team_a, team_b


def _add_to_team(app, user_id: int, team_id: int, *, is_default: bool = True) -> None:
    with app.app_context():
        # Remove the Default-team seed so the user's team is unambiguous.
        UserTeam.query.filter_by(user_id=user_id).delete()
        db.session.add(UserTeam(user_id=user_id, team_id=team_id, is_default=is_default))
        db.session.commit()


def _seed_product(app, *, team_id: int | None, name: str, admin_user) -> int:
    with app.app_context():
        p = Product(name=name, team_id=team_id, created_by=admin_user.id)
        db.session.add(p)
        db.session.commit()
        return p.id


def _seed_vuln(app, *, team_id: int | None, title: str, cve_id: str | None) -> int:
    with app.app_context():
        v = Vulnerability(
            title=title,
            cve_id=cve_id,
            severity="High",
            status="Open",
            team_id=team_id,
        )
        db.session.add(v)
        db.session.commit()
        return v.id


# ---------------------------------------------------------------------------
# 1. Default-team posture: existing behavior unchanged.
# ---------------------------------------------------------------------------

def test_every_user_lands_in_default_team(app, user_factory, default_team):
    user = user_factory(role="Analyst")
    with app.app_context():
        memberships = UserTeam.query.filter_by(user_id=user.id).all()
        assert len(memberships) == 1
        assert memberships[0].team_id == default_team.id


def test_listing_products_returns_default_team_products(app, client, user_factory, auth_header, admin_user, default_team):
    user = user_factory(role="Analyst")
    _seed_product(app, team_id=default_team.id, name="Widget", admin_user=admin_user)
    resp = client.get("/api/products", headers=auth_header(user))
    assert resp.status_code == 200
    items = resp.get_json()["items"]
    assert any(p["name"] == "Widget" for p in items)


# ---------------------------------------------------------------------------
# 2. Cross-team deny.
# ---------------------------------------------------------------------------

def test_user_in_team_a_cannot_see_team_b_products(
    app, client, user_factory, auth_header, admin_user, two_teams,
):
    team_a, team_b = two_teams
    user = user_factory(role="Analyst")
    _add_to_team(app, user.id, team_a.id)

    pid_a = _seed_product(app, team_id=team_a.id, name="AlphaProduct", admin_user=admin_user)
    pid_b = _seed_product(app, team_id=team_b.id, name="BravoProduct", admin_user=admin_user)

    resp = client.get("/api/products", headers=auth_header(user))
    assert resp.status_code == 200
    names = {p["name"] for p in resp.get_json()["items"]}
    assert "AlphaProduct" in names
    assert "BravoProduct" not in names

    # Direct detail access on the forbidden product must 404, not 403.
    detail = client.get(f"/api/products/{pid_b}", headers=auth_header(user))
    assert detail.status_code == 404


def test_user_in_team_a_cannot_see_team_b_vulns(app, client, user_factory, auth_header, two_teams):
    team_a, team_b = two_teams
    user = user_factory(role="Analyst")
    _add_to_team(app, user.id, team_a.id)

    _seed_vuln(app, team_id=team_a.id, title="AlphaVuln", cve_id="CVE-2026-1000")
    vid_b = _seed_vuln(app, team_id=team_b.id, title="BravoVuln", cve_id="CVE-2026-1001")

    resp = client.get("/api/vulnerabilities", headers=auth_header(user))
    assert resp.status_code == 200
    ids = {v["cve_id"] for v in resp.get_json()["items"]}
    assert "CVE-2026-1000" in ids
    assert "CVE-2026-1001" not in ids

    detail = client.get(f"/api/vulnerabilities/{vid_b}", headers=auth_header(user))
    assert detail.status_code == 404


# ---------------------------------------------------------------------------
# 3. Admin bypass.
# ---------------------------------------------------------------------------

def test_admin_sees_every_team(app, client, admin_user, auth_header, two_teams):
    team_a, team_b = two_teams
    _seed_product(app, team_id=team_a.id, name="AlphaProduct", admin_user=admin_user)
    _seed_product(app, team_id=team_b.id, name="BravoProduct", admin_user=admin_user)

    resp = client.get("/api/products", headers=auth_header(admin_user))
    assert resp.status_code == 200
    names = {p["name"] for p in resp.get_json()["items"]}
    assert "AlphaProduct" in names
    assert "BravoProduct" in names


# ---------------------------------------------------------------------------
# 4. X-UVT-Team-Id for writes.
# ---------------------------------------------------------------------------

def test_create_product_stamps_active_team_from_header(
    app, client, user_factory, auth_header, two_teams,
):
    team_a, _team_b = two_teams
    user = user_factory(role="Analyst")
    _add_to_team(app, user.id, team_a.id)

    headers = {**auth_header(user), "X-UVT-Team-Id": str(team_a.id)}
    resp = client.post(
        "/api/products",
        json={"name": "FromHeader"},
        headers=headers,
    )
    assert resp.status_code == 201
    assert resp.get_json()["team_id"] == team_a.id


def test_non_admin_cannot_stamp_product_to_team_they_dont_belong_to(
    app, client, user_factory, auth_header, two_teams,
):
    team_a, team_b = two_teams
    user = user_factory(role="Analyst")
    _add_to_team(app, user.id, team_a.id)

    resp = client.post(
        "/api/products",
        json={"name": "StealAttempt", "team_id": team_b.id},
        headers=auth_header(user),
    )
    # Plan says 403 from create_product validation with status_code=403.
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 5. Shared-pool vulns (team_id IS NULL) are visible to everyone.
# ---------------------------------------------------------------------------

def test_shared_vulns_visible_to_everyone(app, client, user_factory, auth_header, two_teams):
    team_a, _team_b = two_teams
    user = user_factory(role="Analyst")
    _add_to_team(app, user.id, team_a.id)

    _seed_vuln(app, team_id=None, title="SharedCVE", cve_id="CVE-2026-9999")

    resp = client.get("/api/vulnerabilities", headers=auth_header(user))
    assert resp.status_code == 200
    ids = {v["cve_id"] for v in resp.get_json()["items"]}
    assert "CVE-2026-9999" in ids


# ---------------------------------------------------------------------------
# Teams CRUD smoke
# ---------------------------------------------------------------------------

def test_admin_can_create_and_list_teams(client, admin_user, auth_header):
    resp = client.post(
        "/api/teams",
        json={"name": "Platform", "slug": "platform"},
        headers=auth_header(admin_user),
    )
    assert resp.status_code == 201, resp.get_json()
    team = resp.get_json()
    assert team["slug"] == "platform"

    listing = client.get("/api/teams", headers=auth_header(admin_user)).get_json()
    assert any(t["slug"] == "platform" for t in listing["items"])


def test_non_admin_cannot_manage_teams(client, user_factory, auth_header):
    viewer = user_factory(role="Viewer")
    resp = client.post(
        "/api/teams",
        json={"name": "Shadow"},
        headers=auth_header(viewer),
    )
    assert resp.status_code == 403


def test_cannot_delete_default_team(client, admin_user, auth_header, default_team):
    resp = client.delete(f"/api/teams/{default_team.id}", headers=auth_header(admin_user))
    assert resp.status_code == 400


def test_me_teams_reports_current_team(client, user_factory, auth_header, default_team):
    user = user_factory(role="Analyst")
    resp = client.get("/api/me/teams", headers=auth_header(user))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["current_team_id"] == default_team.id
    assert any(item["slug"] == "default" for item in body["items"])
