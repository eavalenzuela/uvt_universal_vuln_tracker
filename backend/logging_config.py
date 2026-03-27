"""Structured JSON logging with request ID correlation.

Usage in ``create_app()``:
    from .logging_config import configure_logging
    configure_logging(app)
"""

import logging
import os
import time
import uuid

from flask import Flask, g, request
from pythonjsonlogger.json import JsonFormatter


def _log_level() -> int:
    name = os.getenv("LOG_LEVEL", "INFO").upper()
    return getattr(logging, name, logging.INFO)


def _json_enabled() -> bool:
    raw = os.getenv("LOG_FORMAT", "json").strip().lower()
    return raw != "text"


class _RequestIdFilter(logging.Filter):
    """Inject ``request_id`` into every log record."""

    def filter(self, record):
        record.request_id = getattr(g, "request_id", None) if _has_request_context() else None
        return True


def _has_request_context():
    try:
        from flask import has_request_context
        return has_request_context()
    except Exception:
        return False


def configure_logging(app: Flask) -> None:
    level = _log_level()
    root = logging.getLogger()
    root.setLevel(level)
    app.logger.setLevel(level)

    # Remove default handlers
    for h in root.handlers[:]:
        root.removeHandler(h)
    for h in app.logger.handlers[:]:
        app.logger.removeHandler(h)

    handler = logging.StreamHandler()
    handler.setLevel(level)

    if _json_enabled():
        formatter = JsonFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            rename_fields={"asctime": "timestamp", "levelname": "level"},
        )
    else:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s [%(request_id)s] %(name)s — %(message)s",
            defaults={"request_id": "-"},
        )

    handler.setFormatter(formatter)
    handler.addFilter(_RequestIdFilter())
    root.addHandler(handler)

    # Assign request ID
    @app.before_request
    def _assign_request_id():
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]

    # Access log
    @app.after_request
    def _access_log(response):
        if request.path == "/api/health":
            return response

        duration_ms = None
        if hasattr(g, "request_start"):
            duration_ms = round((time.monotonic() - g.request_start) * 1000, 1)

        user = getattr(request, "user", None)
        app.logger.info(
            "%s %s %s",
            request.method,
            request.path,
            response.status_code,
            extra={
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "user_id": user.id if user else None,
                "remote_addr": request.remote_addr,
            },
        )
        return response

    @app.before_request
    def _record_start():
        g.request_start = time.monotonic()

    # Expose request_id in response header
    @app.after_request
    def _set_request_id_header(response):
        rid = getattr(g, "request_id", None)
        if rid:
            response.headers["X-Request-ID"] = rid
        return response
