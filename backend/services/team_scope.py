"""F15 Phase 1: team scoping and seeding.

Default-team posture means every user is a member of the Default team and every
scoped resource is stamped with that team. The `team_scope()` filter helper is
load-bearing from day one, even when there is only one team — that way Phase 2
(surfacing team creation in the UI) activates naturally without a flag flip.

See docs/plans/F15-team-acl.md.
"""

from __future__ import annotations

from typing import Iterable

from flask import current_app, request
from sqlalchemy import event, or_

from backend.database import db
from backend.models import Team, User, UserTeam


DEFAULT_TEAM_SLUG = "default"
DEFAULT_TEAM_NAME = "Default"


def ensure_default_team() -> Team:
    """Return the Default team, creating it if absent.

    Also backfills memberships for any user that isn't already in at least one
    team — idempotent and cheap enough to run on every app boot.
    """
    team = Team.query.filter_by(slug=DEFAULT_TEAM_SLUG).first()
    if team is None:
        team = Team(
            slug=DEFAULT_TEAM_SLUG,
            name=DEFAULT_TEAM_NAME,
            description="Default team — every user is a member until explicit teams are created.",
            is_default=True,
        )
        db.session.add(team)
        db.session.flush()

    # Add any user missing a membership into Default.
    existing = {row.user_id for row in UserTeam.query.filter_by(team_id=team.id).all()}
    for user in User.query.all():
        if user.id in existing:
            continue
        db.session.add(UserTeam(
            user_id=user.id,
            team_id=team.id,
            is_default=True,
        ))
    db.session.commit()
    return team


def team_ids_for_user(user: User | None) -> set[int]:
    if user is None:
        return set()
    rows = UserTeam.query.filter_by(user_id=user.id).all()
    return {row.team_id for row in rows}


def default_team_id_for_user(user: User | None) -> int | None:
    """The user's preferred team to use when none is explicit on the request."""
    if user is None:
        return None
    row = (
        UserTeam.query.filter_by(user_id=user.id, is_default=True).first()
        or UserTeam.query.filter_by(user_id=user.id).first()
    )
    return row.team_id if row else None


def resolve_current_team_id(user: User | None) -> int | None:
    """The team for the current request.

    Order of precedence: explicit ``X-UVT-Team-Id`` header → user's default
    membership. Admins may pass any team_id; non-admins must be a member of
    the team they request, otherwise the header is ignored (defaults applied).
    """
    if user is None:
        return None

    header = request.headers.get("X-UVT-Team-Id") if request else None
    if header:
        try:
            requested = int(header)
        except (TypeError, ValueError):
            requested = None
        if requested is not None:
            if user.role == "Admin" or requested in team_ids_for_user(user):
                return requested
    return default_team_id_for_user(user)


def is_admin(user: User | None) -> bool:
    return bool(user and getattr(user, "role", None) == "Admin")


def team_scope(query, model, user: User | None, *, allow_null_team: bool = False):
    """Restrict ``query`` to rows whose ``team_id`` is visible to ``user``.

    - Admins bypass entirely — the query is returned unchanged.
    - Non-admins see rows where ``team_id`` is in their memberships.
    - If ``allow_null_team=True``, rows with ``team_id IS NULL`` are included
      (shared-pool vulnerabilities, etc.).
    """
    if is_admin(user):
        return query

    ids = team_ids_for_user(user)
    column = getattr(model, "team_id", None)
    if column is None:
        return query  # model has no team column — nothing to scope
    if not ids:
        # User is in no team at all; fall back to NULL-only (or nothing).
        return query.filter(column.is_(None)) if allow_null_team else query.filter(False)
    if allow_null_team:
        return query.filter(or_(column.in_(ids), column.is_(None)))
    return query.filter(column.in_(ids))


def user_can_access_team(user: User | None, team_id: int | None) -> bool:
    """Admins always; others must be a member."""
    if is_admin(user):
        return True
    if team_id is None:
        return True  # shared pool is visible to everyone authenticated
    return team_id in team_ids_for_user(user)


# ---------------------------------------------------------------------------
# Auto-enroll new users into the Default team
# ---------------------------------------------------------------------------

@event.listens_for(User, "after_insert")
def _auto_enroll_new_user(_mapper, connection, target):
    """Every freshly-created user joins the Default team (F15 Phase 1 posture).

    Uses a raw connection insert to stay inside the current transaction without
    disturbing SQLAlchemy's unit-of-work for the User being inserted.
    """
    team_table = Team.__table__
    ut_table = UserTeam.__table__
    row = connection.execute(
        team_table.select().where(team_table.c.slug == DEFAULT_TEAM_SLUG)
    ).first()
    if row is None:
        return  # Default team not yet seeded; ensure_default_team() on boot handles it
    default_team_id = row.id
    connection.execute(
        ut_table.insert().values(
            user_id=target.id,
            team_id=default_team_id,
            is_default=True,
        )
    )
