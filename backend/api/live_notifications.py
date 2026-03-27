from __future__ import annotations

import json
from typing import Any

import jwt
from flask import Blueprint, Response, current_app, request, stream_with_context

from ..auth import get_user_by_id
from ..live_notifications import queue_generator

bp = Blueprint("live_notifications", __name__, url_prefix="/api")


def _resolve_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()
    if request.args.get("token"):
        return request.args.get("token")
    return request.cookies.get("uvt_auth_token")


def _authenticate_stream_user() -> tuple[Any | None, tuple[dict[str, str], int] | None]:
    token = _resolve_token()
    if not token:
        return None, ({"error": "Missing Bearer token"}, 401)
    try:
        claims = jwt.decode(token, current_app.config["JWT_SECRET"], algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None, ({"error": "Token expired"}, 401)
    except jwt.InvalidTokenError:
        return None, ({"error": "Invalid token"}, 401)

    user = get_user_by_id(int(claims["sub"]))
    if not user or not user.is_active:
        return None, ({"error": "User inactive or not found"}, 401)

    if int(claims.get("token_version", 0)) != int(user.token_version or 0):
        return None, ({"error": "Token revoked"}, 401)

    return user, None


@bp.get("/notifications/stream")
def notification_stream():
    """Server-Sent Events stream for live notifications.
    ---
    get:
      summary: SSE stream for live notifications
      description: >
        Opens a persistent Server-Sent Events connection. Authentication
        can be provided via Bearer token header, a `token` query parameter,
        or a `uvt_auth_token` cookie.
      parameters:
        - in: query
          name: token
          schema:
            type: string
          description: JWT auth token (alternative to Authorization header)
      responses:
        200:
          description: SSE event stream
          content:
            text/event-stream:
              schema:
                type: string
                description: Newline-delimited SSE events
        401:
          description: Missing, expired, invalid, or revoked token
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    user, auth_error = _authenticate_stream_user()
    if auth_error:
        body, status = auth_error
        return body, status

    @stream_with_context
    def _stream():
        yield "event: connected\ndata: {}\n\n"
        for event in queue_generator(user.id):
            event_type = event.get("type", "notification")
            payload = json.dumps(event, sort_keys=True)
            yield f"event: {event_type}\ndata: {payload}\n\n"

    return Response(
        _stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
