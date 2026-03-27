from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..auth import login_required
from ..database import db
from ..models import Notification
from .validation import ValidationError, error_response, parse_bool, parse_int

bp = Blueprint("notifications_api", __name__, url_prefix="/api/notifications")

MAX_PAGE_SIZE = 100


def _notification_json(row: Notification):
    vulnerability = row.vulnerability
    return {
        "id": row.id,
        "user_id": row.user_id,
        "vulnerability_id": row.vulnerability_id,
        "message": row.message,
        "is_read": bool(row.is_read),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "vulnerability": {
            "id": vulnerability.id,
            "title": vulnerability.title,
            "severity": vulnerability.severity,
            "status": vulnerability.status,
        } if vulnerability else None,
    }


@bp.get("")
@login_required
def list_notifications():
    """List notifications for the current user.
    ---
    get:
      summary: List notifications for the current user
      security:
        - BearerAuth: []
      parameters:
        - in: query
          name: page
          schema:
            type: integer
            default: 1
        - in: query
          name: page_size
          schema:
            type: integer
            default: 20
            maximum: 100
        - in: query
          name: unread_only
          schema:
            type: boolean
            default: false
      responses:
        200:
          description: Paginated list of notifications
          content:
            application/json:
              schema:
                type: object
                properties:
                  ok:
                    type: boolean
                  data:
                    type: object
                    properties:
                      items:
                        type: array
                        items:
                          $ref: '#/components/schemas/Notification'
                      pagination:
                        type: object
                        properties:
                          page:
                            type: integer
                          page_size:
                            type: integer
                          pages:
                            type: integer
                          total:
                            type: integer
                          has_next:
                            type: boolean
                          has_prev:
                            type: boolean
                      unread_count:
                        type: integer
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    try:
        page = parse_int(request.args.get("page", 1), field="page", minimum=1, required=True)
        page_size = parse_int(request.args.get("page_size", 20), field="page_size", minimum=1, maximum=MAX_PAGE_SIZE, required=True)
        unread_only = request.args.get("unread_only")
        unread_only = parse_bool(unread_only, field="unread_only") if unread_only is not None else False
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details, status_code=exc.status_code)

    query = Notification.query.filter_by(user_id=request.user.id)
    if unread_only:
        query = query.filter(Notification.is_read.is_(False))

    ordered_query = query.order_by(Notification.created_at.desc(), Notification.id.desc())
    page_obj = ordered_query.paginate(page=page, per_page=page_size, error_out=False)
    unread_count = Notification.query.filter_by(user_id=request.user.id, is_read=False).count()

    return jsonify({
        "ok": True,
        "data": {
            "items": [_notification_json(row) for row in page_obj.items],
            "pagination": {
                "page": page_obj.page,
                "page_size": page_obj.per_page,
                "pages": page_obj.pages,
                "total": page_obj.total,
                "has_next": page_obj.has_next,
                "has_prev": page_obj.has_prev,
            },
            "unread_count": unread_count,
        },
    })


@bp.patch("/<int:notification_id>")
@login_required
def update_notification(notification_id: int):
    """Update a notification's read status.
    ---
    patch:
      summary: Update a notification's read status
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: notification_id
          required: true
          schema:
            type: integer
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - is_read
              properties:
                is_read:
                  type: boolean
      responses:
        200:
          description: Notification updated
          content:
            application/json:
              schema:
                type: object
                properties:
                  ok:
                    type: boolean
                  data:
                    type: object
                    properties:
                      notification:
                        $ref: '#/components/schemas/Notification'
                      unread_count:
                        type: integer
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        404:
          description: Notification not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    row = Notification.query.filter_by(id=notification_id, user_id=request.user.id).first()
    if not row:
        return error_response("Notification not found", field="notification_id", status_code=404)

    body = request.get_json(silent=True) or {}
    try:
        is_read = parse_bool(body.get("is_read"), field="is_read", required=True)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details, status_code=exc.status_code)

    row.is_read = is_read
    db.session.add(row)
    db.session.commit()

    unread_count = Notification.query.filter_by(user_id=request.user.id, is_read=False).count()
    return jsonify({"ok": True, "data": {"notification": _notification_json(row), "unread_count": unread_count}})


@bp.post("/read-all")
@login_required
def mark_all_notifications_read():
    """Mark all unread notifications as read for the current user.
    ---
    post:
      summary: Mark all notifications as read
      security:
        - BearerAuth: []
      responses:
        200:
          description: All notifications marked as read
          content:
            application/json:
              schema:
                type: object
                properties:
                  ok:
                    type: boolean
                  data:
                    type: object
                    properties:
                      updated:
                        type: integer
                      unread_count:
                        type: integer
    """
    updated = Notification.query.filter_by(user_id=request.user.id, is_read=False).update(
        {Notification.is_read: True},
        synchronize_session=False,
    )
    db.session.commit()
    return jsonify({"ok": True, "data": {"updated": updated, "unread_count": 0}})


@bp.delete("/<int:notification_id>")
@login_required
def archive_or_delete_notification(notification_id: int):
    """Delete or archive a notification.
    ---
    delete:
      summary: Delete or archive a notification
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: notification_id
          required: true
          schema:
            type: integer
        - in: query
          name: mode
          schema:
            type: string
            enum: [delete, archive]
            default: delete
      responses:
        200:
          description: Notification deleted or archived
          content:
            application/json:
              schema:
                type: object
                properties:
                  ok:
                    type: boolean
                  data:
                    type: object
                    properties:
                      deleted:
                        type: boolean
                      mode:
                        type: string
                      notification_id:
                        type: integer
                      unread_count:
                        type: integer
        400:
          description: Invalid mode
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        404:
          description: Notification not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    row = Notification.query.filter_by(id=notification_id, user_id=request.user.id).first()
    if not row:
        return error_response("Notification not found", field="notification_id", status_code=404)

    mode = (request.args.get("mode") or "delete").strip().lower()
    if mode not in {"delete", "archive"}:
        return error_response("mode must be delete or archive", field="mode", details={"allowed": ["delete", "archive"]})

    db.session.delete(row)
    db.session.commit()

    unread_count = Notification.query.filter_by(user_id=request.user.id, is_read=False).count()
    return jsonify({"ok": True, "data": {"deleted": True, "mode": mode, "notification_id": notification_id, "unread_count": unread_count}})
