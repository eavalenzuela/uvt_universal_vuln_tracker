"""Teams admin API (F15 Phase 1).

Admin-only CRUD for teams and membership. Non-admin endpoints for listing the
caller's own memberships live under ``/api/me/teams``.
"""

from __future__ import annotations

import re

from flask import Blueprint, jsonify, request
from sqlalchemy import asc
from sqlalchemy.exc import IntegrityError

from ..auth import admin_required, login_required
from ..database import db
from ..models import Team, User, UserTeam
from ..services.audit import record_audit as _audit
from ..services.team_scope import DEFAULT_TEAM_SLUG, resolve_current_team_id, team_ids_for_user
from .validation import error_response, required_string

bp = Blueprint("teams_api", __name__, url_prefix="/api")


_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]$")


def _team_json(team: Team, *, include_member_count: bool = False) -> dict:
    payload = {
        "id": team.id,
        "name": team.name,
        "slug": team.slug,
        "description": team.description,
        "is_default": team.is_default,
        "created_at": team.created_at.isoformat() if team.created_at else None,
    }
    if include_member_count:
        payload["member_count"] = UserTeam.query.filter_by(team_id=team.id).count()
    return payload


# ---------------------------------------------------------------------------
# /api/me/teams — list the caller's memberships
# ---------------------------------------------------------------------------

@bp.get("/me/teams")
@login_required
def list_my_teams():
    memberships = (
        UserTeam.query.filter_by(user_id=request.user.id).all()
    )
    team_ids = [m.team_id for m in memberships]
    teams = {t.id: t for t in Team.query.filter(Team.id.in_(team_ids)).all()} if team_ids else {}
    # login_required runs after the before_request hook that stamps
    # request.current_team_id, so for unscoped paths we resolve lazily here.
    current = getattr(request, "current_team_id", None) or resolve_current_team_id(request.user)
    items = [
        {
            **_team_json(teams[m.team_id]),
            "is_my_default": m.is_default,
            "is_current": teams[m.team_id].id == current,
        }
        for m in memberships
        if m.team_id in teams
    ]
    return jsonify({"items": items, "current_team_id": current})


# ---------------------------------------------------------------------------
# /api/teams — Admin-only CRUD
# ---------------------------------------------------------------------------

@bp.get("/teams")
@admin_required
def list_teams():
    teams = Team.query.order_by(asc(Team.name)).all()
    return jsonify({"items": [_team_json(t, include_member_count=True) for t in teams]})


@bp.post("/teams")
@admin_required
def create_team():
    data = request.get_json(silent=True) or {}
    try:
        name = required_string(data, "name")
    except Exception as exc:
        return error_response(str(exc), field="name")

    slug = (data.get("slug") or name).strip().lower().replace(" ", "-")
    if not _SLUG_RE.match(slug):
        return error_response(
            "slug must be lowercase alphanumeric with '-'/'_'; 2-64 chars",
            field="slug",
        )
    if slug == DEFAULT_TEAM_SLUG:
        return error_response("slug 'default' is reserved", field="slug")

    team = Team(
        name=name,
        slug=slug,
        description=data.get("description") if isinstance(data.get("description"), str) else None,
        is_default=False,
    )
    db.session.add(team)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return error_response("slug already exists", field="slug", status_code=409)

    _audit("team.create", "teams", team.id, new_values={"name": name, "slug": slug})
    db.session.commit()
    return jsonify(_team_json(team, include_member_count=True)), 201


@bp.patch("/teams/<int:team_id>")
@admin_required
def update_team(team_id: int):
    team = db.session.get(Team, team_id)
    if team is None:
        return error_response("team not found", status_code=404)
    if team.is_default:
        return error_response("cannot modify the Default team", status_code=400)

    data = request.get_json(silent=True) or {}
    if "name" in data:
        if not isinstance(data["name"], str) or not data["name"].strip():
            return error_response("name must be a non-empty string", field="name")
        team.name = data["name"].strip()
    if "description" in data:
        team.description = data["description"] if isinstance(data["description"], str) else None

    db.session.commit()
    _audit("team.update", "teams", team.id, new_values={"name": team.name})
    db.session.commit()
    return jsonify(_team_json(team, include_member_count=True))


@bp.delete("/teams/<int:team_id>")
@admin_required
def delete_team(team_id: int):
    team = db.session.get(Team, team_id)
    if team is None:
        return error_response("team not found", status_code=404)
    if team.is_default:
        return error_response("cannot delete the Default team", status_code=400)

    db.session.delete(team)
    db.session.commit()
    _audit("team.delete", "teams", team_id)
    db.session.commit()
    return "", 204


# ---------------------------------------------------------------------------
# Membership management (Admin-only)
# ---------------------------------------------------------------------------

@bp.get("/teams/<int:team_id>/members")
@admin_required
def list_team_members(team_id: int):
    team = db.session.get(Team, team_id)
    if team is None:
        return error_response("team not found", status_code=404)
    rows = UserTeam.query.filter_by(team_id=team_id).all()
    user_map = {u.id: u for u in User.query.filter(User.id.in_([r.user_id for r in rows])).all()} if rows else {}
    items = [
        {
            "user_id": r.user_id,
            "username": user_map[r.user_id].username if r.user_id in user_map else None,
            "role": user_map[r.user_id].role if r.user_id in user_map else None,
            "is_default": r.is_default,
            "joined_at": r.joined_at.isoformat() if r.joined_at else None,
        }
        for r in rows
    ]
    return jsonify({"items": items})


@bp.post("/teams/<int:team_id>/members")
@admin_required
def add_team_member(team_id: int):
    team = db.session.get(Team, team_id)
    if team is None:
        return error_response("team not found", status_code=404)

    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if not isinstance(user_id, int):
        return error_response("user_id must be an integer", field="user_id")

    user = db.session.get(User, user_id)
    if user is None:
        return error_response("user not found", field="user_id", status_code=404)

    existing = UserTeam.query.filter_by(user_id=user_id, team_id=team_id).first()
    if existing is not None:
        return jsonify({"user_id": user_id, "team_id": team_id, "already_member": True}), 200

    membership = UserTeam(user_id=user_id, team_id=team_id, is_default=False)
    db.session.add(membership)
    db.session.commit()
    _audit("team.add_member", "user_teams", membership.id, new_values={"user_id": user_id, "team_id": team_id})
    db.session.commit()
    return jsonify({"user_id": user_id, "team_id": team_id, "already_member": False}), 201


@bp.delete("/teams/<int:team_id>/members/<int:user_id>")
@admin_required
def remove_team_member(team_id: int, user_id: int):
    team = db.session.get(Team, team_id)
    if team is None:
        return error_response("team not found", status_code=404)
    if team.is_default:
        return error_response("cannot remove members from the Default team", status_code=400)

    membership = UserTeam.query.filter_by(user_id=user_id, team_id=team_id).first()
    if membership is None:
        return error_response("membership not found", status_code=404)

    db.session.delete(membership)
    db.session.commit()
    _audit("team.remove_member", "user_teams", membership.id, old_values={"user_id": user_id, "team_id": team_id})
    db.session.commit()
    return "", 204
