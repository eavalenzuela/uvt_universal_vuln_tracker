import json
from urllib import error as urllib_error

import pytest

from backend.services import notification_rules


class _DummyResponse:
    def __init__(self, status=202):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_webhook_send_posts_valid_json_payload(monkeypatch):
    captured = {}

    # Patch the guarded opener, not urlopen: delivery now goes through
    # url_guard.safe_urlopen, which resolves the host and refuses redirects.
    def fake_safe_urlopen(req, timeout=10, purpose="delivery"):
        captured["timeout"] = timeout
        captured["purpose"] = purpose
        captured["content_type"] = dict(req.header_items()).get("Content-type")
        captured["data"] = req.data
        return _DummyResponse(status=200)

    monkeypatch.setattr(notification_rules, "safe_urlopen", fake_safe_urlopen)

    payload = {"text": "hello", "vulnerability_id": 42, "event_type": "status_change"}
    result = notification_rules._webhook_send({"webhook_url": "https://example.invalid/hook"}, payload)

    assert result == {"status": 200}
    assert captured["timeout"] == 10
    assert captured["content_type"] == "application/json; charset=utf-8"

    body_text = captured["data"].decode("utf-8")
    assert json.loads(body_text) == payload
    assert body_text == '{"event_type":"status_change","text":"hello","vulnerability_id":42}'


def test_webhook_send_wraps_url_errors(monkeypatch):
    def fake_safe_urlopen(req, timeout=10, purpose="delivery"):
        raise urllib_error.URLError("network down")

    monkeypatch.setattr(notification_rules, "safe_urlopen", fake_safe_urlopen)

    with pytest.raises(ValueError, match="webhook request failed"):
        notification_rules._webhook_send({"webhook_url": "https://example.invalid/hook"}, {"a": 1})


def test_webhook_send_refuses_host_that_resolves_to_link_local(monkeypatch):
    """A public-looking hostname that resolves internally must be refused.

    This is the bypass the syntactic check could not see: the name has dots,
    is not a .local/.internal suffix, and is not an IP literal — but it
    resolves to the cloud metadata address.
    """
    import socket

    from backend.services import url_guard

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

    monkeypatch.setattr(url_guard.socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(url_guard.UnsafeOutboundUrlError, match="169.254.169.254"):
        notification_rules._webhook_send(
            {"webhook_url": "https://metadata.example.com/hook"}, {"a": 1}
        )


def test_safe_urlopen_refuses_redirects():
    """A validated host must not be able to redirect the request elsewhere."""
    from urllib.request import Request

    from backend.services import url_guard

    handler = url_guard._NoRedirectHandler()
    with pytest.raises(url_guard.UnsafeOutboundUrlError, match="redirect"):
        handler.redirect_request(
            Request("https://allowed.example.com/"), None, 302, "Found", {},
            "http://169.254.169.254/latest/meta-data/",
        )
