"""Risk acceptance, evidence attachments, and EPSS refresh.

Three gaps a vulnerability tracker cannot really do without:

* **Risk acceptance with an expiry.** "Accepted Risk" used to be a bare status
  string. An acceptance that never expires and records no approver or reason is
  a way of losing a finding, not a risk decision.
* **Evidence attachments.** Without them, scanner output and proof-of-fix end
  up in comment bodies or a chat thread, unscoped and unexported.
* **EPSS.** KEV says what *is* exploited; EPSS says what is *likely* to be.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request, send_file
from werkzeug.utils import secure_filename

from ..auth import login_required, role_required
from ..database import db
from ..models import VulnerabilityAttachment
from ..services.audit import record_audit
from ..services.epss import enrich_vulnerabilities_with_epss
from ..services.team_scope import current_team_id, get_vulnerability_or_404
from .validation import error_response, parse_iso_datetime_field, required_string

bp = Blueprint("vuln_risk_api", __name__, url_prefix="/api")

# Attachment policy. Deliberately an allowlist: evidence is uploaded by one
# user and downloaded by another, so anything the browser might execute in our
# origin (HTML, SVG) stays out regardless of Content-Disposition.
ALLOWED_ATTACHMENT_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml",
    ".pdf", ".zip", ".nessus", ".sarif",
})
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_ATTACHMENTS_PER_VULN = 25
MAX_ACCEPTANCE_DAYS = 365


def _attachment_dir() -> Path:
    path = Path(current_app.instance_path) / "vuln_attachments"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _attachment_json(row: VulnerabilityAttachment) -> dict:
    return {
        "id": row.id,
        "vulnerability_id": row.vulnerability_id,
        "filename": row.filename,
        "content_type": row.content_type,
        "size_bytes": row.size_bytes,
        "sha256": row.sha256,
        "description": row.description,
        "uploaded_by": row.uploaded_by,
        "uploader_username": row.uploader.username if row.uploader else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "download_url": f"/api/vulnerabilities/{row.vulnerability_id}/attachments/{row.id}/download",
    }


# ---------------------------------------------------------------------------
# Risk acceptance
# ---------------------------------------------------------------------------

@bp.post("/vulnerabilities/<int:vuln_id>/risk-acceptance")
@role_required("Admin", "Analyst")
def accept_risk(vuln_id: int):
    """Accept the risk for a vulnerability, with a mandatory expiry and reason.
    ---
    post:
      summary: Accept risk for a vulnerability
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [reason, until]
              properties:
                reason:
                  type: string
                  description: Why this risk is being accepted
                until:
                  type: string
                  format: date-time
                  description: When the acceptance lapses and the finding returns for review
      responses:
        200:
          description: Risk accepted
        400:
          description: Missing reason, missing expiry, or expiry out of range
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    vuln = get_vulnerability_or_404(vuln_id)
    data = request.get_json(silent=True) or {}

    try:
        reason = required_string(data, "reason")
    except Exception as exc:
        return error_response(str(exc), field="reason")
    if len(reason) < 10:
        return error_response(
            "Give a reason of at least 10 characters — this is the record of why "
            "the finding was not fixed.",
            field="reason",
        )

    until, err = parse_iso_datetime_field(data.get("until"), field="until")
    if err:
        return err
    if until is None:
        return error_response(
            "An acceptance must have an expiry date, so the decision comes back for review.",
            field="until",
        )

    now = datetime.now(timezone.utc)
    if until <= now:
        return error_response("Expiry must be in the future", field="until")
    if (until - now).days > MAX_ACCEPTANCE_DAYS:
        return error_response(
            f"Acceptances may run for at most {MAX_ACCEPTANCE_DAYS} days. "
            "Re-accept when it lapses if the reasoning still holds.",
            field="until",
        )

    vuln.risk_accepted = True
    vuln.risk_accepted_at = now
    vuln.risk_accepted_until = until
    vuln.risk_accepted_by = request.user.id
    vuln.risk_acceptance_reason = reason
    db.session.add(vuln)
    db.session.commit()

    record_audit(
        "vulnerability.risk_accepted", "vulnerabilities", vuln.id,
        new_values={"until": until.isoformat(), "reason": reason},
    )
    db.session.commit()

    return jsonify({
        "risk_accepted": True,
        "risk_accepted_until": until.isoformat(),
        "risk_accepted_by": request.user.id,
        "risk_acceptance_reason": reason,
    })


@bp.delete("/vulnerabilities/<int:vuln_id>/risk-acceptance")
@role_required("Admin", "Analyst")
def revoke_risk_acceptance(vuln_id: int):
    """Revoke an acceptance and return the finding to the active queue.
    ---
    delete:
      summary: Revoke risk acceptance
      security:
        - BearerAuth: []
      responses:
        200:
          description: Acceptance revoked
    """
    vuln = get_vulnerability_or_404(vuln_id)
    vuln.risk_accepted = False
    vuln.risk_accepted_at = None
    vuln.risk_accepted_until = None
    vuln.risk_accepted_by = None
    vuln.risk_acceptance_reason = None
    db.session.add(vuln)
    db.session.commit()

    record_audit("vulnerability.risk_acceptance_revoked", "vulnerabilities", vuln.id)
    db.session.commit()
    return jsonify({"risk_accepted": False})


@bp.get("/vulnerabilities/risk-acceptances/expiring")
@login_required
def list_expiring_acceptances():
    """Acceptances that have lapsed or are about to.
    ---
    get:
      summary: List expiring risk acceptances
      security:
        - BearerAuth: []
      parameters:
        - in: query
          name: within_days
          schema:
            type: integer
            default: 30
      responses:
        200:
          description: Acceptances due for review
    """
    from ..models import Vulnerability
    from ..services.team_scope import team_scope

    try:
        within_days = int(request.args.get("within_days", 30))
    except ValueError:
        return error_response("within_days must be an integer", field="within_days")
    within_days = max(0, min(within_days, 365))

    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) + timedelta(days=within_days)

    rows = (
        team_scope(Vulnerability.query, Vulnerability, getattr(request, "user", None))
        .filter(
            Vulnerability.risk_accepted.is_(True),
            Vulnerability.risk_accepted_until.isnot(None),
            Vulnerability.risk_accepted_until <= cutoff,
        )
        .order_by(Vulnerability.risk_accepted_until.asc())
        .limit(200)
        .all()
    )

    now = datetime.now(timezone.utc)
    return jsonify({"items": [
        {
            "id": v.id,
            "cve_id": v.cve_id,
            "title": v.title,
            "severity": v.severity,
            "risk_accepted_until": v.risk_accepted_until.isoformat(),
            "expired": v.risk_accepted_until <= now,
            "risk_acceptance_reason": v.risk_acceptance_reason,
            "risk_accepted_by": v.risk_accepted_by,
        }
        for v in rows
    ]})


# ---------------------------------------------------------------------------
# Evidence attachments
# ---------------------------------------------------------------------------

@bp.get("/vulnerabilities/<int:vuln_id>/attachments")
@login_required
def list_attachments(vuln_id: int):
    """List evidence attached to a vulnerability.
    ---
    get:
      summary: List vulnerability attachments
      security:
        - BearerAuth: []
      responses:
        200:
          description: Attachment metadata
    """
    get_vulnerability_or_404(vuln_id)
    rows = (
        VulnerabilityAttachment.query
        .filter_by(vulnerability_id=vuln_id)
        .order_by(VulnerabilityAttachment.created_at.desc())
        .all()
    )
    return jsonify({"items": [_attachment_json(r) for r in rows]})


@bp.post("/vulnerabilities/<int:vuln_id>/attachments")
@role_required("Admin", "Analyst")
def upload_attachment(vuln_id: int):
    """Attach evidence to a vulnerability (multipart field ``file``).
    ---
    post:
      summary: Upload a vulnerability attachment
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                file:
                  type: string
                  format: binary
                description:
                  type: string
      responses:
        201:
          description: Attachment stored
        400:
          description: Missing file, disallowed type, or file too large
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    get_vulnerability_or_404(vuln_id)

    existing = VulnerabilityAttachment.query.filter_by(vulnerability_id=vuln_id).count()
    if existing >= MAX_ATTACHMENTS_PER_VULN:
        return error_response(
            f"This vulnerability already has the maximum of {MAX_ATTACHMENTS_PER_VULN} attachments.",
            status_code=400,
        )

    file = request.files.get("file") if request.files else None
    if file is None or not file.filename:
        return error_response("A file is required (multipart field 'file')", field="file")

    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_ATTACHMENT_EXTS:
        return error_response(
            f"'{ext or 'no extension'}' is not an accepted attachment type. "
            f"Allowed: {', '.join(sorted(ALLOWED_ATTACHMENT_EXTS))}",
            field="file",
        )

    data = file.read()
    if not data:
        return error_response("The file is empty", field="file")
    if len(data) > MAX_ATTACHMENT_BYTES:
        return error_response(
            f"Attachments must be {MAX_ATTACHMENT_BYTES // (1024 * 1024)} MB or smaller "
            f"(this one is {len(data) // (1024 * 1024)} MB)",
            field="file",
        )

    digest = hashlib.sha256(data).hexdigest()
    # Stored under a generated name so a crafted filename can never influence
    # the path, and two uploads of the same name never collide.
    stored_name = f"{uuid.uuid4().hex}{ext}"
    target = _attachment_dir() / stored_name
    target.write_bytes(data)

    row = VulnerabilityAttachment(
        vulnerability_id=vuln_id,
        filename=filename[:255],
        content_type=(file.mimetype or "application/octet-stream")[:120],
        size_bytes=len(data),
        sha256=digest,
        storage_path=str(target),
        description=(request.form.get("description") or None),
        uploaded_by=request.user.id,
        team_id=current_team_id(),
    )
    db.session.add(row)
    db.session.commit()

    record_audit(
        "vulnerability.attachment_added", "vulnerability_attachments", row.id,
        new_values={"filename": row.filename, "size_bytes": row.size_bytes, "sha256": digest},
    )
    db.session.commit()

    return jsonify(_attachment_json(row)), 201


@bp.get("/vulnerabilities/<int:vuln_id>/attachments/<int:attachment_id>/download")
@login_required
def download_attachment(vuln_id: int, attachment_id: int):
    """Download an attachment.
    ---
    get:
      summary: Download a vulnerability attachment
      security:
        - BearerAuth: []
      responses:
        200:
          description: The file
        404:
          description: Not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    # Team scoping is enforced through the parent vulnerability.
    get_vulnerability_or_404(vuln_id)
    row = VulnerabilityAttachment.query.filter_by(
        id=attachment_id, vulnerability_id=vuln_id
    ).first()
    if row is None or not Path(row.storage_path).exists():
        return error_response("Attachment not found", status_code=404)

    # Always as_attachment, and never the caller's content type: an uploaded
    # file must not be rendered in this origin.
    return send_file(
        row.storage_path,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=row.filename,
    )


@bp.delete("/vulnerabilities/<int:vuln_id>/attachments/<int:attachment_id>")
@role_required("Admin", "Analyst")
def delete_attachment(vuln_id: int, attachment_id: int):
    """Delete an attachment.
    ---
    delete:
      summary: Delete a vulnerability attachment
      security:
        - BearerAuth: []
      responses:
        204:
          description: Deleted
    """
    get_vulnerability_or_404(vuln_id)
    row = VulnerabilityAttachment.query.filter_by(
        id=attachment_id, vulnerability_id=vuln_id
    ).first()
    if row is None:
        return error_response("Attachment not found", status_code=404)

    try:
        Path(row.storage_path).unlink(missing_ok=True)
    except OSError:
        current_app.logger.warning("Could not remove attachment file %s", row.storage_path)

    db.session.delete(row)
    db.session.commit()
    record_audit("vulnerability.attachment_deleted", "vulnerability_attachments", attachment_id)
    db.session.commit()
    return "", 204


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------

@bp.post("/vulnerabilities/epss-refresh")
@role_required("Admin", "Analyst")
def refresh_epss():
    """Refresh EPSS scores from FIRST.org for all CVEs on record.
    ---
    post:
      summary: Refresh EPSS scores
      security:
        - BearerAuth: []
      responses:
        200:
          description: Number of vulnerabilities updated
          content:
            application/json:
              schema:
                type: object
                properties:
                  updated:
                    type: integer
        502:
          description: The EPSS service could not be reached
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    try:
        updated = enrich_vulnerabilities_with_epss()
    except Exception as exc:
        current_app.logger.warning("EPSS refresh failed: %s", exc)
        return error_response(f"EPSS refresh failed: {exc}", status_code=502)
    return jsonify({"updated": updated})
