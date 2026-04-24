"""Per-user preferences (F16).

Endpoints:
  GET  /api/me/preferences   — returns stored prefs, or defaults if unset
  PUT  /api/me/preferences   — upserts, returns the saved row
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..auth import login_required
from ..database import db
from ..models import (
    DashboardLayoutPreset,
    SavedVulnerabilityFilter,
    UserPreferences,
)
from .validation import error_response

bp = Blueprint("user_preferences_api", __name__, url_prefix="/api")


_ALLOWED_THEMES = {"auto", "light", "dark"}
_ALLOWED_DIGEST = {"off", "daily", "weekly"}
_BOOL_FIELDS = (
    "notify_on_mention",
    "notify_on_assignment",
    "notify_on_watched_vuln_update",
    "notify_on_sla_breach",
)


def _prefs_json(prefs: UserPreferences) -> dict:
    return {
        "timezone": prefs.timezone,
        "theme": prefs.theme,
        "language": prefs.language,
        "default_vuln_filter_id": prefs.default_vuln_filter_id,
        "default_dashboard_preset_id": prefs.default_dashboard_preset_id,
        "notify_on_mention": prefs.notify_on_mention,
        "notify_on_assignment": prefs.notify_on_assignment,
        "notify_on_watched_vuln_update": prefs.notify_on_watched_vuln_update,
        "notify_on_sla_breach": prefs.notify_on_sla_breach,
        "email_digest_frequency": prefs.email_digest_frequency,
        "updated_at": prefs.updated_at.isoformat() if prefs.updated_at else None,
    }


def _get_or_create_prefs(user_id: int) -> UserPreferences:
    prefs = UserPreferences.query.filter_by(user_id=user_id).first()
    if prefs is None:
        prefs = UserPreferences(user_id=user_id)
        db.session.add(prefs)
        db.session.flush()
    return prefs


@bp.get("/me/preferences")
@login_required
def get_my_preferences():
    prefs = _get_or_create_prefs(request.user.id)
    db.session.commit()
    return jsonify(_prefs_json(prefs))


@bp.put("/me/preferences")
@login_required
def update_my_preferences():
    data = request.get_json(silent=True) or {}
    prefs = _get_or_create_prefs(request.user.id)

    if "timezone" in data:
        tz = data["timezone"]
        if not isinstance(tz, str) or not tz.strip() or len(tz) > 64:
            return error_response("timezone must be an IANA name under 64 chars", field="timezone")
        prefs.timezone = tz.strip()

    if "theme" in data:
        if data["theme"] not in _ALLOWED_THEMES:
            return error_response(
                f"theme must be one of {sorted(_ALLOWED_THEMES)}", field="theme",
            )
        prefs.theme = data["theme"]

    if "language" in data:
        lang = data["language"]
        if not isinstance(lang, str) or len(lang) > 8:
            return error_response("language must be a short locale code", field="language")
        prefs.language = lang.strip()

    if "email_digest_frequency" in data:
        if data["email_digest_frequency"] not in _ALLOWED_DIGEST:
            return error_response(
                f"email_digest_frequency must be one of {sorted(_ALLOWED_DIGEST)}",
                field="email_digest_frequency",
            )
        prefs.email_digest_frequency = data["email_digest_frequency"]

    if "default_vuln_filter_id" in data:
        value = data["default_vuln_filter_id"]
        if value is not None:
            if not isinstance(value, int):
                return error_response("default_vuln_filter_id must be an integer or null", field="default_vuln_filter_id")
            filt = db.session.get(SavedVulnerabilityFilter, value)
            if filt is None or filt.owner_id != request.user.id:
                return error_response("filter not found", field="default_vuln_filter_id", status_code=404)
        prefs.default_vuln_filter_id = value

    if "default_dashboard_preset_id" in data:
        value = data["default_dashboard_preset_id"]
        if value is not None:
            if not isinstance(value, int):
                return error_response("default_dashboard_preset_id must be an integer or null", field="default_dashboard_preset_id")
            preset = db.session.get(DashboardLayoutPreset, value)
            if preset is None or preset.owner_id != request.user.id:
                return error_response("preset not found", field="default_dashboard_preset_id", status_code=404)
        prefs.default_dashboard_preset_id = value

    for field in _BOOL_FIELDS:
        if field in data:
            setattr(prefs, field, bool(data[field]))

    db.session.commit()
    return jsonify(_prefs_json(prefs))
