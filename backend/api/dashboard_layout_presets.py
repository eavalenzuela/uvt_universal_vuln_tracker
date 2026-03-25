from flask import Blueprint, jsonify, request
from sqlalchemy import asc, or_

from ..auth import login_required
from ..database import db
from ..models import DashboardLayoutPreset
from .validation import ValidationError, enum_value, error_response, required_string

bp = Blueprint("dashboard_layout_presets_api", __name__, url_prefix="/api/dashboard/layout-presets")

VISIBILITY_OPTIONS = {"private", "team"}


def _serialize(item):
    owner = item.owner
    return {
        "id": item.id,
        "name": item.name,
        "widget_config_json": item.widget_config_json or {},
        "visibility": item.visibility,
        "is_default": item.is_default,
        "owner": {
            "id": owner.id if owner else None,
            "username": owner.username if owner else None,
        },
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def _query_visible_presets(user):
    if user.role == "Admin":
        return DashboardLayoutPreset.query
    return DashboardLayoutPreset.query.filter(
        or_(
            DashboardLayoutPreset.owner_id == user.id,
            DashboardLayoutPreset.visibility == "team",
        )
    )


def _can_manage(user, item):
    return user.role == "Admin" or item.owner_id == user.id


@bp.get("")
@login_required
def list_layout_presets():
    user = request.user
    items = _query_visible_presets(user).order_by(
        asc(DashboardLayoutPreset.name),
        asc(DashboardLayoutPreset.id),
    ).all()
    return jsonify([_serialize(item) for item in items])


@bp.get("/default")
@login_required
def get_default_layout_preset():
    user = request.user
    item = _query_visible_presets(user).filter_by(is_default=True).order_by(DashboardLayoutPreset.id.desc()).first()
    if not item:
        return jsonify({"default": None})
    return jsonify({"default": _serialize(item)})


@bp.post("")
@login_required
def create_layout_preset():
    user = request.user
    data = request.get_json(silent=True) or {}

    try:
        name = required_string(data, "name")
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    widget_config_json = data.get("widget_config_json")
    if not isinstance(widget_config_json, dict):
        return error_response("widget_config_json must be an object", field="widget_config_json")

    try:
        visibility = enum_value((data.get("visibility") or "private").strip().lower(), field="visibility", options=VISIBILITY_OPTIONS)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    is_default = bool(data.get("is_default"))
    if is_default:
        DashboardLayoutPreset.query.filter_by(owner_id=user.id, is_default=True).update({"is_default": False})

    item = DashboardLayoutPreset(
        name=name,
        widget_config_json=widget_config_json,
        visibility=visibility,
        owner_id=user.id,
        is_default=is_default,
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(_serialize(item)), 201


@bp.put("/<int:preset_id>")
@login_required
def update_layout_preset(preset_id):
    user = request.user
    item = DashboardLayoutPreset.query.get(preset_id)
    if not item:
        return error_response("Dashboard layout preset not found", status_code=404)
    if not _can_manage(user, item):
        return error_response("Forbidden", status_code=403)

    data = request.get_json(silent=True) or {}

    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            return error_response("name is required", field="name")
        item.name = name

    if "widget_config_json" in data:
        if not isinstance(data.get("widget_config_json"), dict):
            return error_response("widget_config_json must be an object", field="widget_config_json")
        item.widget_config_json = data.get("widget_config_json")

    if "visibility" in data:
        visibility = (data.get("visibility") or "").strip().lower()
        if visibility not in VISIBILITY_OPTIONS:
            return error_response(
                f"visibility must be one of {sorted(VISIBILITY_OPTIONS)}",
                field="visibility",
                details={"allowed": sorted(VISIBILITY_OPTIONS)},
            )
        item.visibility = visibility

    if "is_default" in data:
        is_default = bool(data.get("is_default"))
        if is_default:
            DashboardLayoutPreset.query.filter_by(owner_id=item.owner_id, is_default=True).update({"is_default": False})
        item.is_default = is_default

    db.session.add(item)
    db.session.commit()
    return jsonify(_serialize(item))


@bp.delete("/<int:preset_id>")
@login_required
def delete_layout_preset(preset_id):
    user = request.user
    item = DashboardLayoutPreset.query.get(preset_id)
    if not item:
        return error_response("Dashboard layout preset not found", status_code=404)
    if not _can_manage(user, item):
        return error_response("Forbidden", status_code=403)

    db.session.delete(item)
    db.session.commit()
    return "", 204
