"""Inbound webhook endpoints (F14).

External systems POST to ``/api/webhooks/ingest/<endpoint_id>`` with an
``X-UVT-Signature`` header. The endpoint secret (the ``uvtwh_...`` value
returned exactly once at creation or rotation) is the shared credential.

Senders must also send ``X-UVT-Timestamp`` (unix seconds). The signed material
is ``"{timestamp}.{raw_body}"`` and the HMAC key is ``sha256(secret)``, which
the sender derives from the secret it holds. Signing the timestamp bounds
replay to ``REPLAY_WINDOW_SECONDS``; keying on the digest keeps the raw secret
out of the database entirely.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import desc

from ..auth import admin_required
from ..database import db
from ..models import WebhookDeliveryLog, WebhookEndpoint
from ..rate_limiter import get_client_ip, rate_limit
from ..services.audit import record_audit as _audit
from ..services.team_scope import team_scope, user_can_access_team, current_team_id
from ..services.webhook_ingest import WebhookPayloadError, ingest_webhook_payload
from .validation import error_response, required_string


def _get_endpoint_or_404(endpoint_id: int):
    """Admin-scoped, but team-filtered so the endpoint also matches where
    used: Admins bypass, members see only their teams' endpoints."""
    from flask import abort
    scoped = team_scope(
        WebhookEndpoint.query, WebhookEndpoint, getattr(request, "user", None),
    ).filter(WebhookEndpoint.id == endpoint_id)
    row = scoped.first()
    if row is None:
        abort(404)
    return row

bp = Blueprint("webhooks_api", __name__, url_prefix="/api")

# How far a sender's X-UVT-Timestamp may be from server time. Wide enough to
# tolerate ordinary clock drift, narrow enough that a captured request stops
# being useful quickly.
REPLAY_WINDOW_SECONDS = 300


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_secret(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _generate_secret() -> str:
    return f"uvtwh_{secrets.token_urlsafe(32)}"


def _endpoint_json(endpoint: WebhookEndpoint, *, include_secret: str | None = None) -> dict:
    data = {
        "id": endpoint.id,
        "name": endpoint.name,
        "source_type": endpoint.source_type,
        "is_enabled": endpoint.is_enabled,
        "product_version_id": endpoint.product_version_id,
        "owner_id": endpoint.owner_id,
        "last_delivery_at": endpoint.last_delivery_at.isoformat() if endpoint.last_delivery_at else None,
        "delivery_count": endpoint.delivery_count,
        "failure_count": endpoint.failure_count,
        "created_at": endpoint.created_at.isoformat() if endpoint.created_at else None,
    }
    if include_secret is not None:
        # Shown exactly once, at creation or rotation. Nothing else can
        # retrieve it, because only its digest is stored.
        data["secret"] = include_secret
        data["ingest_url"] = f"/api/webhooks/ingest/{endpoint.id}"
        data["signing"] = {
            "algorithm": "HMAC-SHA256",
            "key": "sha256(secret) as lowercase hex",
            "signed_payload": "{X-UVT-Timestamp}.{raw_request_body}",
            "headers": ["X-UVT-Timestamp", "X-UVT-Signature: sha256=<hex>"],
            "max_clock_skew_seconds": REPLAY_WINDOW_SECONDS,
        }
    return data


def _log_delivery(
    endpoint_id: int,
    *,
    status: str,
    status_code: int,
    payload_bytes: int,
    vulnerabilities_ingested: int = 0,
    error_message: str | None = None,
) -> None:
    log = WebhookDeliveryLog(
        endpoint_id=endpoint_id,
        status=status,
        status_code=status_code,
        payload_bytes=payload_bytes,
        vulnerabilities_ingested=vulnerabilities_ingested,
        error_message=error_message,
        # Trusted-proxy-aware client IP (honors RATE_LIMIT_TRUSTED_PROXIES)
        # instead of the proxy's own address.
        client_ip=(get_client_ip() or "")[:64],
    )
    db.session.add(log)


# ---------------------------------------------------------------------------
# CRUD (Admin-only)
# ---------------------------------------------------------------------------

@bp.get("/webhooks")
@admin_required
def list_webhooks():
    query = team_scope(
        WebhookEndpoint.query, WebhookEndpoint, getattr(request, "user", None),
    )
    endpoints = query.order_by(desc(WebhookEndpoint.created_at)).all()
    return jsonify({"items": [_endpoint_json(e) for e in endpoints]})


@bp.post("/webhooks")
@admin_required
def create_webhook():
    data = request.get_json(silent=True) or {}
    try:
        name = required_string(data, "name")
    except Exception as exc:
        return error_response(str(exc), field="name")

    source_type = (data.get("source_type") or "generic").strip().lower()
    if source_type not in {"generic", "github", "dependabot", "trivy", "nessus", "qualys"}:
        return error_response("unsupported source_type", field="source_type")

    product_version_id = data.get("product_version_id")
    if product_version_id is not None and not isinstance(product_version_id, int):
        return error_response("product_version_id must be an integer", field="product_version_id")

    # F15: endpoint team stamp. Admins may choose any team (including NULL
    # for shared-pool ingest); non-admins are locked to their active team.
    user = getattr(request, "user", None)
    req_team = data.get("team_id")
    if req_team is not None and not isinstance(req_team, int):
        return error_response("team_id must be an integer or null", field="team_id")
    if req_team is None:
        req_team = current_team_id()
    if not user_can_access_team(user, req_team):
        return error_response("you are not a member of this team", field="team_id", status_code=403)

    raw_secret = _generate_secret()
    endpoint = WebhookEndpoint(
        name=name,
        source_type=source_type,
        secret_hash=_hash_secret(raw_secret),
        product_version_id=product_version_id,
        owner_id=getattr(request.user, "id", None),
        team_id=req_team,
    )
    db.session.add(endpoint)
    db.session.commit()

    _audit(
        "webhook.create",
        "webhook_endpoints",
        endpoint.id,
        new_values={"name": endpoint.name, "source_type": endpoint.source_type},
    )
    db.session.commit()

    return jsonify(_endpoint_json(endpoint, include_secret=raw_secret)), 201


@bp.patch("/webhooks/<int:endpoint_id>")
@admin_required
def update_webhook(endpoint_id: int):
    endpoint = _get_endpoint_or_404(endpoint_id)

    data = request.get_json(silent=True) or {}
    if "name" in data:
        if not isinstance(data["name"], str) or not data["name"].strip():
            return error_response("name must be a non-empty string", field="name")
        endpoint.name = data["name"].strip()
    if "is_enabled" in data:
        endpoint.is_enabled = bool(data["is_enabled"])
    if "product_version_id" in data:
        pvid = data["product_version_id"]
        if pvid is not None and not isinstance(pvid, int):
            return error_response("product_version_id must be an integer or null", field="product_version_id")
        endpoint.product_version_id = pvid

    db.session.commit()
    _audit(
        "webhook.update",
        "webhook_endpoints",
        endpoint.id,
        new_values={"name": endpoint.name, "is_enabled": endpoint.is_enabled},
    )
    db.session.commit()
    return jsonify(_endpoint_json(endpoint))


@bp.delete("/webhooks/<int:endpoint_id>")
@admin_required
def delete_webhook(endpoint_id: int):
    endpoint = _get_endpoint_or_404(endpoint_id)
    db.session.delete(endpoint)
    db.session.commit()
    _audit("webhook.delete", "webhook_endpoints", endpoint_id)
    db.session.commit()
    return "", 204


@bp.post("/webhooks/<int:endpoint_id>/rotate-secret")
@admin_required
def rotate_webhook_secret(endpoint_id: int):
    endpoint = _get_endpoint_or_404(endpoint_id)
    raw_secret = _generate_secret()
    endpoint.secret_hash = _hash_secret(raw_secret)
    db.session.commit()
    _audit("webhook.rotate_secret", "webhook_endpoints", endpoint.id)
    db.session.commit()
    return jsonify(_endpoint_json(endpoint, include_secret=raw_secret))


@bp.get("/webhooks/<int:endpoint_id>/deliveries")
@admin_required
def list_webhook_deliveries(endpoint_id: int):
    endpoint = _get_endpoint_or_404(endpoint_id)
    logs = (
        WebhookDeliveryLog.query.filter_by(endpoint_id=endpoint_id)
        .order_by(desc(WebhookDeliveryLog.created_at))
        .limit(100)
        .all()
    )
    return jsonify({
        "items": [
            {
                "id": log.id,
                "status": log.status,
                "status_code": log.status_code,
                "payload_bytes": log.payload_bytes,
                "vulnerabilities_ingested": log.vulnerabilities_ingested,
                "error_message": log.error_message,
                "client_ip": log.client_ip,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ]
    })


# ---------------------------------------------------------------------------
# Ingest (unauthenticated, HMAC-verified)
# ---------------------------------------------------------------------------

def _ingest_rate_key() -> str:
    view_args = request.view_args or {}
    return f"webhook_ingest:{get_client_ip() or 'unknown'}:{view_args.get('endpoint_id', '0')}"


@bp.post("/webhooks/ingest/<int:endpoint_id>")
@rate_limit(
    "RATE_LIMIT_WRITE_LIMIT",
    "RATE_LIMIT_WRITE_WINDOW_SECONDS",
    key_func=_ingest_rate_key,
    identifier="webhook_ingest",
)
def ingest_webhook(endpoint_id: int):
    endpoint = db.session.get(WebhookEndpoint, endpoint_id)
    if endpoint is None or not endpoint.is_enabled:
        return error_response("webhook not found or disabled", status_code=404)

    raw_body = request.get_data(cache=True) or b""
    signature_header = request.headers.get("X-UVT-Signature", "")
    timestamp_header = request.headers.get("X-UVT-Timestamp", "")

    def _reject(message: str, status_code: int = 401):
        endpoint.failure_count += 1
        _log_delivery(
            endpoint_id,
            status="rejected",
            status_code=status_code,
            payload_bytes=len(raw_body),
            error_message=message,
        )
        db.session.commit()
        return error_response(message, status_code=status_code)

    if not signature_header:
        return _reject("missing X-UVT-Signature header")

    # Replay protection. Signing the body alone meant a captured request stayed
    # valid forever; binding a timestamp into the signed material and refusing
    # stale ones bounds the replay window to REPLAY_WINDOW_SECONDS.
    if not timestamp_header:
        return _reject("missing X-UVT-Timestamp header")
    try:
        sent_at = int(timestamp_header)
    except ValueError:
        return _reject("X-UVT-Timestamp must be a unix timestamp in seconds")

    skew = abs(int(datetime.now(timezone.utc).timestamp()) - sent_at)
    if skew > REPLAY_WINDOW_SECONDS:
        return _reject(
            f"X-UVT-Timestamp is {skew}s away from server time "
            f"(maximum {REPLAY_WINDOW_SECONDS}s)"
        )

    # The HMAC key is sha256(secret), which the sender derives from the raw
    # secret it holds. Keeping the raw secret out of the database costs
    # nothing here and means a database dump leaks no signing keys.
    signed_payload = timestamp_header.encode("utf-8") + b"." + raw_body
    expected = hmac.new(
        key=endpoint.secret_hash.encode("utf-8"),
        msg=signed_payload,
        digestmod=hashlib.sha256,
    ).hexdigest()
    provided = signature_header.removeprefix("sha256=").strip()

    if not hmac.compare_digest(expected, provided):
        return _reject("invalid signature")

    try:
        payload = json.loads(raw_body.decode("utf-8")) if raw_body else None
    except (ValueError, UnicodeDecodeError):
        endpoint.failure_count += 1
        _log_delivery(
            endpoint_id,
            status="error",
            status_code=400,
            payload_bytes=len(raw_body),
            error_message="invalid JSON body",
        )
        db.session.commit()
        return error_response("invalid JSON body", status_code=400)

    if not isinstance(payload, dict):
        endpoint.failure_count += 1
        _log_delivery(
            endpoint_id,
            status="error",
            status_code=400,
            payload_bytes=len(raw_body),
            error_message="payload must be a JSON object",
        )
        db.session.commit()
        return error_response("payload must be a JSON object", status_code=400)

    try:
        ingested = ingest_webhook_payload(
            source_type=endpoint.source_type,
            payload=payload,
            source_label=f"webhook:{endpoint.source_type}:{endpoint.id}",
            team_id=endpoint.team_id,
        )
    except WebhookPayloadError as exc:
        endpoint.failure_count += 1
        _log_delivery(
            endpoint_id,
            status="error",
            status_code=422,
            payload_bytes=len(raw_body),
            error_message=str(exc),
        )
        db.session.commit()
        return error_response(str(exc), status_code=422)
    except Exception as exc:
        current_app.logger.exception("webhook ingest failed: %s", exc)
        endpoint.failure_count += 1
        _log_delivery(
            endpoint_id,
            status="error",
            status_code=500,
            payload_bytes=len(raw_body),
            error_message=str(exc)[:500],
        )
        db.session.commit()
        return error_response("internal error", status_code=500)

    endpoint.last_delivery_at = datetime.now(timezone.utc)
    endpoint.delivery_count += 1
    _log_delivery(
        endpoint_id,
        status="success",
        status_code=202,
        payload_bytes=len(raw_body),
        vulnerabilities_ingested=ingested,
    )
    db.session.commit()

    return jsonify({"accepted": True, "vulnerabilities_ingested": ingested}), 202
