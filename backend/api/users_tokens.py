from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from ..database import db
from ..models import ApiToken, User
from ..auth import create_api_token, role_required
from .validation import error_response
from .users_crud import _parse_token_create_payload, _api_token_json

bp = Blueprint("users_tokens_api", __name__, url_prefix="/api")


@bp.get("/users/me/api-tokens")
@role_required("Admin", "Analyst", "Viewer")
def list_my_api_tokens():
    tokens = (
        ApiToken.query.filter_by(owner_id=request.user.id)
        .order_by(ApiToken.created_at.desc())
        .all()
    )
    return jsonify([_api_token_json(token) for token in tokens])


@bp.post("/users/me/api-tokens")
@role_required("Admin", "Analyst", "Viewer")
def create_my_api_token():
    payload = request.get_json(silent=True) or {}
    parsed, err = _parse_token_create_payload(payload, request.user)
    if err:
        return err

    plaintext, token = create_api_token(request.user, parsed["name"], parsed["scopes"], parsed["expires_at"])
    db.session.commit()
    return jsonify({"token": plaintext, "api_token": _api_token_json(token)}), 201


@bp.post("/users/me/api-tokens/<int:token_id>/revoke")
@role_required("Admin", "Analyst", "Viewer")
def revoke_my_api_token(token_id: int):
    token = ApiToken.query.get_or_404(token_id)
    if token.owner_id != request.user.id:
        return error_response("Forbidden", status_code=403)
    if token.revoked_at is None:
        token.revoked_at = datetime.now(timezone.utc)
        db.session.add(token)
        db.session.commit()
    return jsonify(_api_token_json(token))


@bp.get("/users/<int:user_id>/api-tokens")
@role_required("Admin")
def list_user_api_tokens(user_id: int):
    User.query.get_or_404(user_id)
    tokens = ApiToken.query.filter_by(owner_id=user_id).order_by(ApiToken.created_at.desc()).all()
    return jsonify([_api_token_json(token) for token in tokens])


@bp.post("/users/<int:user_id>/api-tokens")
@role_required("Admin")
def create_user_api_token(user_id: int):
    owner = User.query.get_or_404(user_id)
    payload = request.get_json(silent=True) or {}
    parsed, err = _parse_token_create_payload(payload, owner)
    if err:
        return err
    plaintext, token = create_api_token(owner, parsed["name"], parsed["scopes"], parsed["expires_at"])
    db.session.commit()
    return jsonify({"token": plaintext, "api_token": _api_token_json(token)}), 201


@bp.post("/users/<int:user_id>/api-tokens/<int:token_id>/revoke")
@role_required("Admin")
def revoke_user_api_token(user_id: int, token_id: int):
    token = ApiToken.query.get_or_404(token_id)
    if token.owner_id != user_id:
        return error_response("Token does not belong to user", status_code=404)
    if token.revoked_at is None:
        token.revoked_at = datetime.now(timezone.utc)
        db.session.add(token)
        db.session.commit()
    return jsonify(_api_token_json(token))
