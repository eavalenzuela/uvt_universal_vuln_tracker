"""Outbound URL validation for operator-supplied delivery targets.

Notification rules carry Slack webhook URLs, Jira base URLs, and generic
webhook URLs in admin-editable config. Without validation a malicious or
compromised admin account can point deliveries at internal services
(cloud metadata endpoints, localhost admin panels, ...) and use the server
as an SSRF proxy.

``validate_outbound_url`` performs syntactic checks only — scheme, host
presence, IP-literal range checks, and obviously-local hostname patterns.
It deliberately does **not** resolve DNS: delivery runs in workers where a
resolution failure surfaces as a normal delivery error anyway, and keeping
the guard network-free makes it deterministic and testable.

Deployments that legitimately deliver to intranet targets can set
``OUTBOUND_ALLOW_PRIVATE_URLS=true`` to skip the private-target checks
(scheme and host-presence checks always apply).
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from flask import current_app, has_app_context

_ALLOWED_SCHEMES = ("http", "https")

# Hostname suffixes that never refer to a public host.
_LOCAL_HOSTNAME_SUFFIXES = (".localhost", ".local", ".internal")
_LOCAL_HOSTNAMES = ("localhost",)


class UnsafeOutboundUrlError(ValueError):
    """Raised when a delivery URL points at a disallowed target."""


def _allow_private_default() -> bool:
    if has_app_context():
        return bool(current_app.config.get("OUTBOUND_ALLOW_PRIVATE_URLS", False))
    return False


def _is_private_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_outbound_url(url: str, *, allow_private: bool | None = None, purpose: str = "delivery") -> str:
    """Validate an operator-supplied outbound URL and return it unchanged.

    Raises :class:`UnsafeOutboundUrlError` when the URL is malformed, uses a
    non-HTTP(S) scheme, or (unless private targets are allowed) points at a
    loopback / private / link-local / reserved IP literal or an
    obviously-local hostname.
    """
    if not url or not isinstance(url, str):
        raise UnsafeOutboundUrlError(f"Missing {purpose} URL")

    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise UnsafeOutboundUrlError(f"Invalid {purpose} URL: {url!r}") from exc

    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeOutboundUrlError(
            f"Unsupported {purpose} URL scheme {parsed.scheme!r} (expected http or https)"
        )

    hostname = parsed.hostname
    if not hostname:
        raise UnsafeOutboundUrlError(f"Invalid {purpose} URL (no host): {url!r}")

    if allow_private is None:
        allow_private = _allow_private_default()
    if allow_private:
        return url

    hostname = hostname.strip(".").lower()

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    if ip is not None:
        if _is_private_address(ip):
            raise UnsafeOutboundUrlError(
                f"Refusing {purpose} to private/loopback address {hostname!r} "
                "(set OUTBOUND_ALLOW_PRIVATE_URLS=true to permit intranet targets)"
            )
        return url

    if (
        hostname in _LOCAL_HOSTNAMES
        or hostname.endswith(_LOCAL_HOSTNAME_SUFFIXES)
        or "." not in hostname
    ):
        raise UnsafeOutboundUrlError(
            f"Refusing {purpose} to local hostname {hostname!r} "
            "(set OUTBOUND_ALLOW_PRIVATE_URLS=true to permit intranet targets)"
        )

    return url
