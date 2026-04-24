from flask import Blueprint, jsonify, request
from sqlalchemy import asc

from ..database import db
from ..models import (
    Vulnerability,
    VulnerabilityComment,
)
from ..auth import login_required, role_required
from ..services.team_scope import get_vulnerability_or_404
from ..services.audit import record_audit
from ..services.notification_rules import trigger_mention_notifications
from .validation import ValidationError, error_response, required_string
from ..serializers.vulnerability_serializers import serialize_comment

bp = Blueprint("vuln_comments_api", __name__, url_prefix="/api")


def _can_moderate_comment(user, comment):
    return bool(user and (user.role == "Admin" or comment.author_id == user.id))


def _serialize_comment(comment):
    return serialize_comment(comment)


@bp.get("/vulnerabilities/<int:vuln_id>/comments")
@login_required
def list_vulnerability_comments(vuln_id: int):
    """List all comments for a vulnerability.
    ---
    get:
      summary: List comments for a vulnerability
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vuln_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Array of comments ordered by creation time
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/VulnerabilityComment'
        401:
          description: Unauthorized
        404:
          description: Vulnerability not found
    """
    get_vulnerability_or_404(vuln_id)
    comments = (
        VulnerabilityComment.query
        .filter_by(vulnerability_id=vuln_id)
        .order_by(asc(VulnerabilityComment.created_at), asc(VulnerabilityComment.id))
        .all()
    )
    return jsonify([_serialize_comment(comment) for comment in comments])


@bp.post("/vulnerabilities/<int:vuln_id>/comments")
@role_required("Admin", "Analyst")
def create_vulnerability_comment(vuln_id: int):
    """Create a comment on a vulnerability.
    ---
    post:
      summary: Create a comment on a vulnerability
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vuln_id
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
                - body
              properties:
                body:
                  type: string
                  description: Comment text (supports @mentions)
      responses:
        201:
          description: Comment created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/VulnerabilityComment'
        400:
          description: Validation error (missing body)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        401:
          description: Unauthorized
        403:
          description: Forbidden — requires Admin or Analyst role
        404:
          description: Vulnerability not found
    """
    get_vulnerability_or_404(vuln_id)
    data = request.get_json(silent=True) or {}
    try:
        body = required_string(data, "body")
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    comment = VulnerabilityComment(
        vulnerability_id=vuln_id,
        author_id=request.user.id,
        body=body,
        updated_by=request.user.id,
    )
    db.session.add(comment)
    db.session.flush()

    trigger_mention_notifications(
        vulnerability_id=vuln_id,
        actor_id=request.user.id,
        comment_id=comment.id,
        comment_text=body,
    )

    record_audit("CREATE", "vulnerability_comments", comment.id, old_values=None, new_values={"body": comment.body})
    db.session.commit()
    return jsonify(_serialize_comment(comment)), 201


@bp.put("/vulnerabilities/<int:vuln_id>/comments/<int:comment_id>")
@role_required("Admin", "Analyst")
def update_vulnerability_comment(vuln_id: int, comment_id: int):
    """Update a comment on a vulnerability.
    ---
    put:
      summary: Update a vulnerability comment
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vuln_id
          required: true
          schema:
            type: integer
        - in: path
          name: comment_id
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
                - body
              properties:
                body:
                  type: string
      responses:
        200:
          description: Updated comment
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/VulnerabilityComment'
        400:
          description: Validation error (missing body)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        401:
          description: Unauthorized
        403:
          description: Forbidden — requires Admin or Analyst role, or comment authorship
        404:
          description: Vulnerability or comment not found
    """
    get_vulnerability_or_404(vuln_id)
    comment = VulnerabilityComment.query.filter_by(id=comment_id, vulnerability_id=vuln_id).first_or_404()
    if not _can_moderate_comment(request.user, comment):
        return error_response("Not permitted to edit this comment", status_code=403)

    data = request.get_json(silent=True) or {}
    try:
        body = required_string(data, "body")
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    old_values = {"body": comment.body}
    comment.body = body
    comment.updated_by = request.user.id

    trigger_mention_notifications(
        vulnerability_id=vuln_id,
        actor_id=request.user.id,
        comment_id=comment.id,
        comment_text=body,
    )

    record_audit("UPDATE", "vulnerability_comments", comment.id, old_values=old_values, new_values={"body": comment.body})
    db.session.commit()
    return jsonify(_serialize_comment(comment))


@bp.delete("/vulnerabilities/<int:vuln_id>/comments/<int:comment_id>")
@role_required("Admin", "Analyst")
def delete_vulnerability_comment(vuln_id: int, comment_id: int):
    """Delete a comment on a vulnerability.
    ---
    delete:
      summary: Delete a vulnerability comment
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vuln_id
          required: true
          schema:
            type: integer
        - in: path
          name: comment_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Deletion successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Ok'
        401:
          description: Unauthorized
        403:
          description: Forbidden — requires Admin or Analyst role, or comment authorship
        404:
          description: Vulnerability or comment not found
    """
    get_vulnerability_or_404(vuln_id)
    comment = VulnerabilityComment.query.filter_by(id=comment_id, vulnerability_id=vuln_id).first_or_404()
    if not _can_moderate_comment(request.user, comment):
        return error_response("Not permitted to delete this comment", status_code=403)

    old_values = {"body": comment.body, "author_id": comment.author_id}
    record_audit("DELETE", "vulnerability_comments", comment.id, old_values=old_values, new_values=None)
    db.session.delete(comment)
    db.session.commit()
    return jsonify({"ok": True})
