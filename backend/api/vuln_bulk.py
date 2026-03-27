from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import asc

from sqlalchemy.exc import SQLAlchemyError

from ..database import db
from ..models import (
    Vulnerability,
    VulnerabilityWatcher,
    User,
)
from ..auth import login_required, role_required
from ..services.audit import build_field_diff, record_audit
from ..services.sla import recompute_vulnerability_sla
from ..rate_limiter import rate_limit
from .validation import ValidationError, enum_value, error_response, parse_int, parse_query_bool
from ..services.vulnerability_service import (
    SEVERITY_OPTIONS,
    STATUS_OPTIONS,
    parse_sla_due_at,
)
from ..serializers.vulnerability_serializers import serialize_watcher

bp = Blueprint("vuln_bulk_api", __name__, url_prefix="/api")


def _parse_sla_due_at(value, *, field="sla_due_at"):
    return parse_sla_due_at(value, field=field)


def _serialize_watcher(watcher):
    return serialize_watcher(watcher)


@bp.patch("/vulnerabilities/batch")
@role_required("Admin", "Analyst")
@rate_limit("RATE_LIMIT_WRITE_LIMIT", "RATE_LIMIT_WRITE_WINDOW_SECONDS", identifier="vuln_batch_update")
def batch_update_vulnerabilities():
    """Batch update multiple vulnerabilities (alias for /bulk).
    ---
    patch:
      summary: Batch update multiple vulnerabilities
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - vulnerability_ids
              properties:
                vulnerability_ids:
                  type: array
                  items:
                    type: integer
                  description: List of vulnerability IDs to update
                status:
                  type: string
                  enum: [Open, In Progress, Resolved, Closed, Accepted]
                severity:
                  type: string
                  enum: [Critical, High, Medium, Low, Informational]
                assigned_to:
                  type: integer
                  nullable: true
                sla_due_at:
                  type: string
                  format: date-time
                  nullable: true
      responses:
        200:
          description: Batch update results
          content:
            application/json:
              schema:
                type: object
                properties:
                  ok:
                    type: boolean
                  updated_ids:
                    type: array
                    items:
                      type: integer
                  updated_count:
                    type: integer
                  skipped_ids:
                    type: array
                    items:
                      type: integer
                  skipped_count:
                    type: integer
                  missing_ids:
                    type: array
                    items:
                      type: integer
                  missing_count:
                    type: integer
                  failed:
                    type: array
                    items:
                      type: object
                      properties:
                        id:
                          type: integer
                        error:
                          type: string
                  failed_count:
                    type: integer
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        401:
          description: Unauthorized
        403:
          description: Forbidden — requires Admin or Analyst role
    """
    return _bulk_update_vulnerabilities()


@bp.patch("/vulnerabilities/bulk")
@role_required("Admin", "Analyst")
@rate_limit("RATE_LIMIT_WRITE_LIMIT", "RATE_LIMIT_WRITE_WINDOW_SECONDS", identifier="vuln_bulk_update")
def bulk_update_vulnerabilities():
    """Bulk update multiple vulnerabilities.
    ---
    patch:
      summary: Bulk update multiple vulnerabilities
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - vulnerability_ids
              properties:
                vulnerability_ids:
                  type: array
                  items:
                    type: integer
                  description: List of vulnerability IDs to update
                status:
                  type: string
                  enum: [Open, In Progress, Resolved, Closed, Accepted]
                severity:
                  type: string
                  enum: [Critical, High, Medium, Low, Informational]
                assigned_to:
                  type: integer
                  nullable: true
                sla_due_at:
                  type: string
                  format: date-time
                  nullable: true
      responses:
        200:
          description: Bulk update results
          content:
            application/json:
              schema:
                type: object
                properties:
                  ok:
                    type: boolean
                  updated_ids:
                    type: array
                    items:
                      type: integer
                  updated_count:
                    type: integer
                  skipped_ids:
                    type: array
                    items:
                      type: integer
                  skipped_count:
                    type: integer
                  missing_ids:
                    type: array
                    items:
                      type: integer
                  missing_count:
                    type: integer
                  failed:
                    type: array
                    items:
                      type: object
                      properties:
                        id:
                          type: integer
                        error:
                          type: string
                  failed_count:
                    type: integer
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        401:
          description: Unauthorized
        403:
          description: Forbidden — requires Admin or Analyst role
    """
    return _bulk_update_vulnerabilities()


def _bulk_update_vulnerabilities():
    data = request.get_json(silent=True) or {}

    raw_ids = data.get("vulnerability_ids")
    if not isinstance(raw_ids, list) or not raw_ids:
        return error_response("vulnerability_ids must be a non-empty list", field="vulnerability_ids")

    normalized_ids = []
    for idx, raw_id in enumerate(raw_ids):
        try:
            parsed_id = parse_int(raw_id, field=f"vulnerability_ids[{idx}]", minimum=1, required=True)
        except ValidationError as exc:
            return error_response(exc.error, field=exc.field, details=exc.details)
        normalized_ids.append(parsed_id)

    vulnerability_ids = list(dict.fromkeys(normalized_ids))

    allowed_fields = {"status", "severity", "assigned_to", "sla_due_at"}
    updates = {}
    for field in allowed_fields:
        if field in data:
            updates[field] = data[field]

    if not updates:
        return error_response("At least one mutable field is required", field="updates")

    unknown_fields = [key for key in data.keys() if key not in {"vulnerability_ids", *allowed_fields}]
    if unknown_fields:
        return error_response(
            "Unknown fields in request",
            field="payload",
            details={"unknown_fields": sorted(unknown_fields), "allowed_fields": sorted(allowed_fields)},
        )

    try:
        parsed_updates = {}
        if "status" in updates:
            parsed_updates["status"] = enum_value(updates.get("status"), field="status", options=STATUS_OPTIONS, required=False) or "Open"
        if "severity" in updates:
            parsed_updates["severity"] = enum_value(updates.get("severity"), field="severity", options=SEVERITY_OPTIONS, required=False) or "Medium"
        if "assigned_to" in updates:
            parsed_updates["assigned_to"] = parse_int(updates.get("assigned_to"), field="assigned_to", minimum=1)
        if "sla_due_at" in updates:
            parsed_updates["sla_due_at"] = _parse_sla_due_at(updates.get("sla_due_at"), field="sla_due_at")
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    if "assigned_to" in parsed_updates and parsed_updates["assigned_to"] is not None and not User.query.get(parsed_updates["assigned_to"]):
        return error_response("assigned_to user not found", field="assigned_to")

    vulnerabilities = Vulnerability.query.filter(Vulnerability.id.in_(vulnerability_ids)).all()
    found_ids = {item.id for item in vulnerabilities}
    missing_ids = [vid for vid in vulnerability_ids if vid not in found_ids]

    updated = []
    skipped = []
    failed = []

    for vuln in vulnerabilities:
        if vuln.is_merged:
            failed.append({"id": vuln.id, "error": "merged vulnerabilities cannot be updated"})
            continue

        old = {
            "severity": vuln.severity,
            "status": vuln.status,
            "assigned_to": vuln.assigned_to,
            "sla_due_at": vuln.sla_due_at.isoformat() if vuln.sla_due_at else None,
        }

        try:
            with db.session.begin_nested():
                for field, value in parsed_updates.items():
                    setattr(vuln, field, value)

                if "sla_due_at" not in parsed_updates:
                    recompute_vulnerability_sla(vuln)

                new_values = {
                    "severity": vuln.severity,
                    "status": vuln.status,
                    "assigned_to": vuln.assigned_to,
                    "sla_due_at": vuln.sla_due_at.isoformat() if vuln.sla_due_at else None,
                }
                field_diff = build_field_diff(old, new_values, ["severity", "status", "assigned_to", "sla_due_at"])
                if not field_diff:
                    skipped.append(vuln.id)
                    continue

                new_values["field_diff"] = field_diff
                record_audit("BATCH_UPDATE", "vulnerabilities", vuln.id,
                             old_values=old, new_values=new_values)
                db.session.flush()
                updated.append(vuln.id)
        except SQLAlchemyError as exc:
            current_app.logger.exception("Batch update failed for vulnerability %s", vuln.id)
            db.session.rollback()
            failed.append({"id": vuln.id, "error": str(exc)})

    db.session.commit()

    return jsonify({
        "ok": True,
        "updated_ids": updated,
        "updated_count": len(updated),
        "skipped_ids": skipped,
        "skipped_count": len(skipped),
        "missing_ids": missing_ids,
        "missing_count": len(missing_ids),
        "failed": failed,
        "failed_count": len(failed),
    })


@bp.get("/vulnerabilities/<int:vuln_id>/watchers")
@login_required
def list_vulnerability_watchers(vuln_id: int):
    """List watchers for a vulnerability.
    ---
    get:
      summary: List watchers for a vulnerability
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
          description: Array of watchers ordered by creation time
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/VulnerabilityWatcher'
        401:
          description: Unauthorized
        404:
          description: Vulnerability not found
    """
    Vulnerability.query.get_or_404(vuln_id)
    watchers = (
        VulnerabilityWatcher.query
        .filter_by(vulnerability_id=vuln_id)
        .order_by(asc(VulnerabilityWatcher.created_at), asc(VulnerabilityWatcher.id))
        .all()
    )
    return jsonify([_serialize_watcher(watcher) for watcher in watchers])


@bp.post("/vulnerabilities/<int:vuln_id>/watch")
@role_required("Admin", "Analyst")
def watch_vulnerability(vuln_id: int):
    """Add a watcher to a vulnerability.
    ---
    post:
      summary: Watch a vulnerability
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vuln_id
          required: true
          schema:
            type: integer
      requestBody:
        required: false
        content:
          application/json:
            schema:
              type: object
              properties:
                user_id:
                  type: integer
                  description: User ID to add as watcher (defaults to current user; only admins can set other users)
      responses:
        200:
          description: User is already watching (returns existing watcher)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/VulnerabilityWatcher'
        201:
          description: Watcher created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/VulnerabilityWatcher'
        400:
          description: Invalid user_id
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        401:
          description: Unauthorized
        403:
          description: Forbidden — requires Admin or Analyst role; only admins can add watchers for other users
        404:
          description: Vulnerability or user not found
    """
    Vulnerability.query.get_or_404(vuln_id)
    data = request.get_json(silent=True) or {}
    requested_user_id = data.get("user_id", request.user.id)
    try:
        user_id = parse_int(requested_user_id, field="user_id", minimum=1, required=True)
    except ValidationError as exc:
        return error_response(exc.error, field=exc.field, details=exc.details)

    if request.user.role != "Admin" and user_id != request.user.id:
        return error_response("Only admins can add watchers for other users", status_code=403)

    user = User.query.get(user_id)
    if not user:
        return error_response("User not found", field="user_id", status_code=404)

    existing = VulnerabilityWatcher.query.filter_by(vulnerability_id=vuln_id, user_id=user_id).first()
    if existing:
        return jsonify(_serialize_watcher(existing))

    watcher = VulnerabilityWatcher(vulnerability_id=vuln_id, user_id=user_id, added_by=request.user.id)
    db.session.add(watcher)
    db.session.commit()
    return jsonify(_serialize_watcher(watcher)), 201


@bp.delete("/vulnerabilities/<int:vuln_id>/watch/<int:user_id>")
@role_required("Admin", "Analyst")
def unwatch_vulnerability(vuln_id: int, user_id: int):
    """Remove a watcher from a vulnerability.
    ---
    delete:
      summary: Unwatch a vulnerability
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: vuln_id
          required: true
          schema:
            type: integer
        - in: path
          name: user_id
          required: true
          schema:
            type: integer
      responses:
        200:
          description: Watcher removed (or was not watching)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Ok'
        401:
          description: Unauthorized
        403:
          description: Forbidden — requires Admin or Analyst role; only admins can remove watchers for other users
        404:
          description: Vulnerability not found
    """
    Vulnerability.query.get_or_404(vuln_id)
    if request.user.role != "Admin" and user_id != request.user.id:
        return error_response("Only admins can remove watchers for other users", status_code=403)

    watcher = VulnerabilityWatcher.query.filter_by(vulnerability_id=vuln_id, user_id=user_id).first()
    if not watcher:
        return jsonify({"ok": True})

    db.session.delete(watcher)
    db.session.commit()
    return jsonify({"ok": True})
