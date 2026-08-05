"""Outbound URL validation for operator-supplied delivery targets.

Notification rules carry Slack webhook URLs, Jira base URLs, and generic
webhook URLs in admin-editable config. Without validation a malicious or
compromised admin account can point deliveries at internal services
(cloud metadata endpoints, localhost admin panels, ...) and use the server
as an SSRF proxy.

The guard has two layers, because syntax alone is not enough:

1. :func:`validate_outbound_url` — scheme, host presence, IP-literal ranges,
   and obviously-local hostnames. Cheap, network-free, used at config-save
   time so an operator gets immediate feedback on a bad URL.

2. :func:`resolve_and_validate` — resolves the hostname and checks **every**
   address it maps to. This closes the hole where a perfectly ordinary-looking
   public hostname (``169.254.169.254.nip.io``, or any A record an attacker
   controls) sails through the syntactic pass and still reaches cloud
   metadata.

:func:`safe_urlopen` combines both and **refuses to follow redirects**, which
was the other bypass: every call site used ``urllib.request.urlopen``, which
follows redirects by default, so an allowed public host answering
``302 -> http://169.254.169.254/`` was followed without any revalidation.

Deployments that legitimately deliver to intranet targets can set
``OUTBOUND_ALLOW_PRIVATE_URLS=true`` to skip the private-target checks
(scheme and host-presence checks always apply).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlparse

from flask import current_app, has_app_context

_ALLOWED_SCHEMES = ("http", "https")

# Hostname suffixes that never refer to a public host.
_LOCAL_HOSTNAME_SUFFIXES = (".localhost", ".local", ".internal")
_LOCAL_HOSTNAMES = ("localhost",)


class UnsafeOutboundUrlError(ValueError):
    """Raised when a delivery URL points at a disallowed target."""


class OutboundResolutionError(UnsafeOutboundUrlError):
    """Raised when a delivery host cannot be resolved.

    A subclass of :class:`UnsafeOutboundUrlError` so it still fails closed —
    an unresolvable host is never dialled — but distinguishable, because it
    means "DNS is broken or the hostname is wrong", not "you aimed this at
    something internal", and delivery logs should say so.
    """


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


# ---------------------------------------------------------------------------
# Resolution-aware validation
# ---------------------------------------------------------------------------

def resolve_and_validate(url: str, *, allow_private: bool | None = None, purpose: str = "delivery") -> str:
    """Validate ``url`` syntactically, then check every address it resolves to.

    The syntactic pass alone can be walked straight past: ``nip.io``-style
    hostnames, or any DNS record the requester controls, look like ordinary
    public names while pointing at link-local or private space. Resolving here
    means the check applies to what the connection will actually reach.
    """
    validate_outbound_url(url, allow_private=allow_private, purpose=purpose)

    if allow_private is None:
        allow_private = _allow_private_default()
    if allow_private:
        return url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # IP literals were already range-checked by validate_outbound_url.
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return url
    except ValueError:
        pass

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise OutboundResolutionError(
            f"Could not resolve {purpose} host {hostname!r}: {exc}"
        ) from exc

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _is_private_address(ip):
            raise UnsafeOutboundUrlError(
                f"Refusing {purpose} to {hostname!r}: it resolves to the "
                f"private/loopback address {addr} "
                "(set OUTBOUND_ALLOW_PRIVATE_URLS=true to permit intranet targets)"
            )

    return url


class _NoRedirectHandler(urllib_request.HTTPRedirectHandler):
    """Turn any redirect into an error instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise UnsafeOutboundUrlError(
            f"Refusing to follow a redirect to {newurl!r}: outbound delivery targets "
            "are validated once and must not be re-pointed by the remote host"
        )


_opener = urllib_request.build_opener(_NoRedirectHandler)


def safe_urlopen(request_obj, *, timeout: int = 10, purpose: str = "delivery",
                 allow_private: bool | None = None):
    """``urlopen`` for operator-supplied URLs: resolution-checked, no redirects.

    Accepts a :class:`urllib.request.Request` (or a URL string) so call sites
    keep their existing headers and body.
    """
    url = request_obj.full_url if hasattr(request_obj, "full_url") else str(request_obj)
    resolve_and_validate(url, allow_private=allow_private, purpose=purpose)
    try:
        return _opener.open(request_obj, timeout=timeout)
    except urllib_error.HTTPError:
        # A non-2xx response is the caller's business, not a safety failure.
        raise
