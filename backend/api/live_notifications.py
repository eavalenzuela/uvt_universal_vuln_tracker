from __future__ import annotations

import json
from typing import Any

from flask import Blueprint, Response, request, stream_with_context

from ..auth import authenticate_request
from ..live_notifications import TooManyStreamsError, queue_generator

bp = Blueprint("live_notifications", __name__, url_prefix="/api")


def _authenticate_stream_user() -> tuple[Any | None, tuple[dict[str, str], int] | None]:
    """Authenticate an SSE subscriber.

    This used to accept ``?token=<jwt>`` from the query string and reimplement
    token validation locally, which meant credentials landed in access logs,
    proxy logs, browser history and Referer headers — and that the
    ``last_revoked_at`` check performed everywhere else was silently missing
    here.

    The browser sends the ``uvt_auth_token`` cookie with the SSE request
    (``EventSource(..., {withCredentials: true})``), so delegating to the
    shared ``authenticate_request`` costs nothing and keeps one code path.
    """
    user, _claims, error = authenticate_request()
    if error:
        body, status = error
        return None, (body.get_json(), status)
    return user, None


@bp.get("/notifications/stream")
def notification_stream():
    """Server-Sent Events stream for live notifications.
    ---
    get:
      summary: SSE stream for live notifications
      description: >
        Opens a persistent Server-Sent Events connection. Authentication uses
        the `Authorization: Bearer` header or the `uvt_auth_token` cookie.
        Credentials are never accepted from the query string, because URLs are
        recorded in access logs, proxy logs and browser history.
      security:
        - BearerAuth: []
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

    try:
        generator = queue_generator(user.id)
    except TooManyStreamsError as exc:
        return {"error": str(exc)}, 429

    @stream_with_context
    def _stream():
        yield "event: connected\ndata: {}\n\n"
        for event in generator:
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
