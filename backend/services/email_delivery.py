from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
import json
import os
import smtplib
import time
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request
from flask import has_app_context

from ..models import PluginConfig


class EmailDeliveryError(ValueError):
    def __init__(self, code: str, message: str, *, metadata: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.metadata = metadata or {}

    def as_dict(self) -> dict[str, Any]:
        return {
            "channel": "email",
            "error": {
                "code": self.code,
                "message": self.message,
                "metadata": self.metadata,
            },
        }


@dataclass
class EmailDeliveryConfig:
    provider: str
    host: str | None
    port: int | None
    username: str | None
    password: str | None
    sender: str
    use_tls: bool
    timeout_seconds: float
    api_url: str | None
    api_token: str | None


def _as_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _load_plugin_config(plugin_id: str = "email_delivery") -> dict[str, Any]:
    if not has_app_context():
        return {}
    row = PluginConfig.query.filter_by(plugin_id=plugin_id).first()
    if not row or not row.config_json:
        return {}
    return dict(row.config_json)


def resolve_email_config(*, overrides: dict[str, Any] | None = None, plugin_id: str = "email_delivery") -> EmailDeliveryConfig:
    env_cfg = {
        "provider": os.getenv("EMAIL_DELIVERY_PROVIDER", "smtp"),
        "host": os.getenv("EMAIL_HOST") or os.getenv("SMTP_HOST"),
        "port": os.getenv("EMAIL_PORT") or os.getenv("SMTP_PORT", "587"),
        "username": os.getenv("EMAIL_USERNAME") or os.getenv("SMTP_USERNAME"),
        "password": os.getenv("EMAIL_PASSWORD") or os.getenv("SMTP_PASSWORD"),
        "sender": os.getenv("EMAIL_SENDER") or os.getenv("SMTP_SENDER"),
        "use_tls": os.getenv("EMAIL_USE_TLS") or os.getenv("SMTP_USE_TLS", "true"),
        "timeout_seconds": os.getenv("EMAIL_TIMEOUT_SECONDS") or os.getenv("SMTP_TIMEOUT_SECONDS", "10"),
        "api_url": os.getenv("EMAIL_API_URL"),
        "api_token": os.getenv("EMAIL_API_TOKEN"),
    }
    cfg: dict[str, Any] = {}
    cfg.update(env_cfg)
    cfg.update(_load_plugin_config(plugin_id=plugin_id))
    cfg.update(overrides or {})

    provider = str(cfg.get("provider") or "smtp").strip().lower()
    if provider not in {"smtp", "api"}:
        raise EmailDeliveryError("invalid_provider", "Email provider must be smtp or api", metadata={"provider": provider})

    sender = str(cfg.get("sender") or "").strip()
    if not sender:
        raise EmailDeliveryError("missing_config", "Missing sender email", metadata={"field": "sender"})

    host = None
    port = None
    if provider == "smtp":
        host = str(cfg.get("host") or "").strip()
        if not host:
            raise EmailDeliveryError("missing_config", "Missing SMTP host", metadata={"field": "host"})
        try:
            port = int(cfg.get("port") or 0)
        except (TypeError, ValueError) as exc:
            raise EmailDeliveryError("invalid_config", "SMTP port must be an integer", metadata={"field": "port"}) from exc
        if port <= 0:
            raise EmailDeliveryError("invalid_config", "SMTP port must be greater than zero", metadata={"field": "port", "value": port})

    api_url = str(cfg.get("api_url") or "").strip() or None
    api_token = str(cfg.get("api_token") or "").strip() or None
    if provider == "api" and not api_url:
        raise EmailDeliveryError("missing_config", "Missing API provider URL", metadata={"field": "api_url"})

    try:
        timeout_seconds = float(cfg.get("timeout_seconds") or 0)
    except (TypeError, ValueError) as exc:
        raise EmailDeliveryError("invalid_config", "timeout_seconds must be numeric", metadata={"field": "timeout_seconds"}) from exc
    if timeout_seconds <= 0:
        raise EmailDeliveryError("invalid_config", "timeout_seconds must be greater than zero", metadata={"field": "timeout_seconds", "value": timeout_seconds})

    return EmailDeliveryConfig(
        provider=provider,
        host=host,
        port=port,
        username=(str(cfg.get("username")).strip() if cfg.get("username") else None),
        password=(str(cfg.get("password")) if cfg.get("password") else None),
        sender=sender,
        use_tls=_as_bool(cfg.get("use_tls"), default=True),
        timeout_seconds=timeout_seconds,
        api_url=api_url,
        api_token=api_token,
    )


def _send_via_smtp(cfg: EmailDeliveryConfig, msg: EmailMessage) -> None:
    with smtplib.SMTP(cfg.host, cfg.port, timeout=cfg.timeout_seconds) as smtp:
        if cfg.use_tls:
            smtp.starttls()
        if cfg.username:
            smtp.login(cfg.username, cfg.password or "")
        smtp.send_message(msg)


def _send_via_api(cfg: EmailDeliveryConfig, *, recipient: str, subject: str, body_text: str) -> dict[str, Any]:
    payload = {
        "from": cfg.sender,
        "to": recipient,
        "subject": subject,
        "text": body_text,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    req = urllib_request.Request(cfg.api_url, data=body, method="POST")
    req.add_header("Content-Type", "application/json; charset=utf-8")
    if cfg.api_token:
        req.add_header("Authorization", f"Bearer {cfg.api_token}")

    with urllib_request.urlopen(req, timeout=cfg.timeout_seconds) as resp:
        return {"status": resp.status}


def send_email(*, recipient: str, subject: str, body_text: str, config_overrides: dict[str, Any] | None = None, plugin_id: str = "email_delivery") -> dict[str, Any]:
    recipient_value = str(recipient or "").strip()
    if not recipient_value:
        raise EmailDeliveryError("invalid_recipient", "Email recipient is required", metadata={"field": "recipient"})

    cfg = resolve_email_config(overrides=config_overrides, plugin_id=plugin_id)

    msg = EmailMessage()
    msg["To"] = recipient_value
    msg["From"] = cfg.sender
    msg["Subject"] = subject
    msg.set_content(body_text)

    started_at = time.monotonic()
    api_result = None
    try:
        if cfg.provider == "api":
            api_result = _send_via_api(cfg, recipient=recipient_value, subject=subject, body_text=body_text)
        else:
            _send_via_smtp(cfg, msg)
    except (smtplib.SMTPException, urllib_error.URLError, OSError, ValueError) as exc:
        raise EmailDeliveryError(
            "delivery_failed",
            "Email delivery failed",
            metadata={"reason": str(exc), "provider": cfg.provider, "host": cfg.host, "port": cfg.port, "api_url": cfg.api_url},
        ) from exc

    elapsed_ms = round((time.monotonic() - started_at) * 1000, 3)
    return {
        "channel": "email",
        "provider": cfg.provider,
        "recipient": recipient_value,
        "sender": cfg.sender,
        "subject": subject,
        "transport": {
            "host": cfg.host,
            "port": cfg.port,
            "tls": cfg.use_tls,
            "timeout_seconds": cfg.timeout_seconds,
            "auth_enabled": bool(cfg.username or cfg.api_token),
            "api_url": cfg.api_url,
        },
        "metadata": {
            "elapsed_ms": elapsed_ms,
            "body_bytes": len(body_text.encode("utf-8")),
            "provider_response": api_result,
        },
    }
