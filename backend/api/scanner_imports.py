"""Bulk scanner import endpoints (F19).

POST /api/imports/<scanner>
  multipart/form-data with a ``file`` field; scanner is one of
  ``nessus``, ``qualys``, ``trivy``.

Analyst or Admin role required. File size is capped to mitigate resource
abuse; parsing is streaming-friendly but commit still happens per-row via the
shared ``upsert_vulnerability`` path.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..auth import role_required
from ..database import db
from ..services.audit import record_audit as _audit
from ..services.scanner_imports import PARSERS, ScannerImportError, import_scanner_file
from .validation import error_response

bp = Blueprint("scanner_imports_api", __name__, url_prefix="/api")

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB


@bp.get("/imports")
@role_required("Admin", "Analyst")
def list_supported_scanners():
    return jsonify({"supported": sorted(PARSERS.keys())})


@bp.post("/imports/<scanner>")
@role_required("Admin", "Analyst")
def import_scanner(scanner: str):
    if scanner not in PARSERS:
        return error_response(
            f"unsupported scanner '{scanner}'",
            field="scanner",
            details={"supported": sorted(PARSERS.keys())},
            status_code=400,
        )

    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return error_response("file upload required (multipart field 'file')", status_code=400)

    data = upload.read(_MAX_UPLOAD_BYTES + 1)
    if len(data) > _MAX_UPLOAD_BYTES:
        return error_response(
            f"file exceeds maximum size of {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
            status_code=413,
        )

    try:
        ingested = import_scanner_file(
            scanner=scanner,
            file_bytes=data,
            source_label=f"import:{scanner}:{upload.filename}",
        )
    except ScannerImportError as exc:
        return error_response(str(exc), status_code=422)

    _audit(
        "scanner_import",
        "vulnerabilities",
        None,
        new_values={
            "scanner": scanner,
            "filename": upload.filename,
            "vulnerabilities_ingested": ingested,
        },
    )
    db.session.commit()

    return jsonify({"accepted": True, "scanner": scanner, "vulnerabilities_ingested": ingested}), 202
