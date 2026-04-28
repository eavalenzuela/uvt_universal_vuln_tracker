"""Admin endpoints for organization PDF branding (F17 Slice 3).

GET  /api/admin/branding         — return current settings.
PUT  /api/admin/branding         — update primary_color and footer_text.
POST /api/admin/branding/logo    — upload a logo (PNG or SVG, ≤1 MB).
DELETE /api/admin/branding/logo  — remove the logo.
"""

import os
import re
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

from ..auth import admin_required, login_required
from ..database import db
from ..models import OrganizationBranding
from .validation import error_response

bp = Blueprint("branding_api", __name__, url_prefix="/api/admin/branding")

ALLOWED_LOGO_MIMES = {"image/png", "image/svg+xml", "image/jpeg"}
ALLOWED_LOGO_EXTS = {".png", ".svg", ".jpg", ".jpeg"}
MAX_LOGO_BYTES = 1024 * 1024  # 1 MiB
HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def _branding_dir() -> str:
    root = current_app.config.get("BRANDING_DIR") or os.path.join(
        current_app.instance_path, "branding"
    )
    Path(root).mkdir(parents=True, exist_ok=True)
    return root


def _serialize(row: OrganizationBranding) -> dict:
    return {
        "primary_color": row.primary_color,
        "footer_text": row.footer_text,
        "has_logo": bool(row.logo_path and Path(row.logo_path).exists()),
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@bp.get("")
@login_required
def get_branding():
    row = OrganizationBranding.get_or_create()
    return jsonify(_serialize(row))


@bp.put("")
@admin_required
def update_branding():
    payload = request.get_json(silent=True) or {}
    row = OrganizationBranding.get_or_create()

    if "primary_color" in payload:
        color = (payload.get("primary_color") or "").strip()
        if not HEX_COLOR_RE.match(color):
            return error_response(
                "primary_color must be a 6-digit hex string like #2563eb",
                status_code=400,
                field="primary_color",
            )
        row.primary_color = color.lower()

    if "footer_text" in payload:
        text = payload.get("footer_text")
        if text is None:
            text = ""
        text = str(text)
        if len(text) > 255:
            return error_response(
                "footer_text must be 255 characters or fewer",
                status_code=400,
                field="footer_text",
            )
        row.footer_text = text

    db.session.commit()
    return jsonify(_serialize(row))


@bp.post("/logo")
@admin_required
def upload_logo():
    file = request.files.get("logo") if request.files else None
    if file is None or not file.filename:
        return error_response("logo file is required (multipart field 'logo')", status_code=400)

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_LOGO_EXTS:
        return error_response(
            f"logo must be one of {sorted(ALLOWED_LOGO_EXTS)}",
            status_code=400,
            field="logo",
        )

    if file.mimetype and file.mimetype not in ALLOWED_LOGO_MIMES:
        return error_response(
            f"logo content-type must be one of {sorted(ALLOWED_LOGO_MIMES)} (got {file.mimetype})",
            status_code=400,
            field="logo",
        )

    data = file.read()
    if len(data) > MAX_LOGO_BYTES:
        return error_response(
            f"logo must be {MAX_LOGO_BYTES} bytes or fewer (got {len(data)})",
            status_code=400,
            field="logo",
        )
    if not data:
        return error_response("logo file is empty", status_code=400, field="logo")

    row = OrganizationBranding.get_or_create()
    target = Path(_branding_dir()) / f"logo{ext}"

    # If extension changed, drop the previous file so we don't accumulate stale logos.
    if row.logo_path and Path(row.logo_path).exists() and Path(row.logo_path) != target:
        try:
            Path(row.logo_path).unlink()
        except OSError:
            pass

    target.write_bytes(data)
    row.logo_path = str(target)
    db.session.commit()
    return jsonify(_serialize(row))


@bp.delete("/logo")
@admin_required
def delete_logo():
    row = OrganizationBranding.get_or_create()
    if row.logo_path:
        try:
            Path(row.logo_path).unlink(missing_ok=True)
        except OSError:
            pass
    row.logo_path = None
    db.session.commit()
    return jsonify(_serialize(row))
