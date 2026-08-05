"""Application metrics using prometheus_client.

Exposes a ``/metrics`` endpoint in Prometheus text format and instruments
Flask request latency, counts, and application-level gauges.
"""

from __future__ import annotations

import hmac
import logging
import time

from flask import Flask, current_app, request, Response
from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    CollectorRegistry,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Custom registry (avoids default process/platform collectors in tests)
# ---------------------------------------------------------------------------
registry = CollectorRegistry()

# ---------------------------------------------------------------------------
# HTTP metrics
# ---------------------------------------------------------------------------

REQUEST_COUNT = Counter(
    "uvt_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
    registry=registry,
)

REQUEST_LATENCY = Histogram(
    "uvt_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=registry,
)

REQUESTS_IN_PROGRESS = Gauge(
    "uvt_http_requests_in_progress",
    "HTTP requests currently being processed",
    ["method"],
    registry=registry,
)

# ---------------------------------------------------------------------------
# Application metrics
# ---------------------------------------------------------------------------

VULNERABILITY_COUNT = Gauge(
    "uvt_vulnerabilities_total",
    "Total vulnerability count by severity",
    ["severity"],
    registry=registry,
)

ACTIVE_USERS = Gauge(
    "uvt_active_users",
    "Number of active user accounts",
    registry=registry,
)

PLUGIN_RUN_COUNT = Counter(
    "uvt_plugin_runs_total",
    "Total plugin runs by status",
    ["plugin_id", "status"],
    registry=registry,
)

PLUGIN_RUN_DURATION = Histogram(
    "uvt_plugin_run_duration_seconds",
    "Plugin run duration in seconds",
    ["plugin_id"],
    buckets=(1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0),
    registry=registry,
)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

def _sanitize_endpoint(endpoint: str | None) -> str:
    """Return a low-cardinality endpoint label (blueprint name or route rule)."""
    if not endpoint:
        return "unknown"
    # Use Flask endpoint name (e.g. "auth_api.login") — stable and low-cardinality
    return endpoint


def init_metrics(app: Flask) -> None:
    """Instrument the Flask app with Prometheus metrics."""

    @app.before_request
    def _start_timer():
        request._metrics_start = time.perf_counter()
        REQUESTS_IN_PROGRESS.labels(method=request.method).inc()

    @app.after_request
    def _record_metrics(response):
        latency = time.perf_counter() - getattr(request, "_metrics_start", time.perf_counter())
        endpoint = _sanitize_endpoint(request.endpoint)

        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=endpoint,
            status=response.status_code,
        ).inc()

        REQUEST_LATENCY.labels(
            method=request.method,
            endpoint=endpoint,
        ).observe(latency)

        REQUESTS_IN_PROGRESS.labels(method=request.method).dec()
        return response

    @app.get("/metrics")
    def prometheus_metrics():
        """Prometheus metrics endpoint.
        ---
        get:
          summary: Prometheus metrics
          tags:
            - Monitoring
          responses:
            200:
              description: Prometheus text format metrics
              content:
                text/plain:
                  schema:
                    type: string
        """
        # /metrics reports vulnerability counts by severity and active-user
        # numbers — business-sensitive on its own, and a useful reconnaissance
        # signal. It is unauthenticated by default because Prometheus scrapes
        # it from inside the deployment network (the compose file no longer
        # publishes the backend port). Setting METRICS_TOKEN requires a bearer
        # token, for deployments that must expose it more widely.
        expected = current_app.config.get("METRICS_TOKEN")
        if expected:
            provided = request.headers.get("Authorization", "")
            token = provided[7:].strip() if provided.lower().startswith("bearer ") else ""
            if not token or not hmac.compare_digest(token, expected):
                return Response("Unauthorized", status=401, mimetype="text/plain")

        _refresh_app_gauges()
        return Response(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)


def _refresh_app_gauges():
    """Update application-level gauges from the database."""
    try:
        from .database import db
        from .models import Vulnerability, User

        # Vulnerability counts by severity
        rows = (
            db.session.query(Vulnerability.severity, db.func.count(Vulnerability.id))
            .group_by(Vulnerability.severity)
            .all()
        )
        # Reset all severity labels first
        for sev in ("Critical", "High", "Medium", "Low", "None"):
            VULNERABILITY_COUNT.labels(severity=sev).set(0)
        for severity, count in rows:
            VULNERABILITY_COUNT.labels(severity=severity or "None").set(count)

        # Active user count
        active = User.query.filter_by(is_active=True).count()
        ACTIVE_USERS.set(active)

    except Exception:
        logger.debug("Could not refresh app gauges", exc_info=True)
