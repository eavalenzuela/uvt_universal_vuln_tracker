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

    def fake_urlopen(req, timeout):
        captured["timeout"] = timeout
        captured["content_type"] = dict(req.header_items()).get("Content-type")
        captured["data"] = req.data
        return _DummyResponse(status=200)

    monkeypatch.setattr(notification_rules.urllib_request, "urlopen", fake_urlopen)

    payload = {"text": "hello", "vulnerability_id": 42, "event_type": "status_change"}
    result = notification_rules._webhook_send({"webhook_url": "https://example.invalid/hook"}, payload)

    assert result == {"status": 200}
    assert captured["timeout"] == 10
    assert captured["content_type"] == "application/json; charset=utf-8"

    body_text = captured["data"].decode("utf-8")
    assert json.loads(body_text) == payload
    assert body_text == '{"event_type":"status_change","text":"hello","vulnerability_id":42}'


def test_webhook_send_wraps_url_errors(monkeypatch):
    def fake_urlopen(req, timeout):
        raise urllib_error.URLError("network down")

    monkeypatch.setattr(notification_rules.urllib_request, "urlopen", fake_urlopen)

    with pytest.raises(ValueError, match="webhook request failed"):
        notification_rules._webhook_send({"webhook_url": "https://example.invalid/hook"}, {"a": 1})
