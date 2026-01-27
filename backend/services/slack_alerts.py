from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class SlackWebhookError(RuntimeError):
    pass


@dataclass(frozen=True)
class SlackResponse:
    status: int
    body: str


class SlackWebhookClient:
    def __init__(self, webhook_url: str, *, timeout: int = 10) -> None:
        self.webhook_url = webhook_url
        self.timeout = timeout

    def send_message(
        self,
        *,
        text: str,
        channel: str | None = None,
        username: str | None = None,
        icon_emoji: str | None = None,
        blocks: list[dict[str, Any]] | None = None,
    ) -> SlackResponse:
        payload: dict[str, Any] = {"text": text}
        if channel:
            payload["channel"] = channel
        if username:
            payload["username"] = username
        if icon_emoji:
            payload["icon_emoji"] = icon_emoji
        if blocks:
            payload["blocks"] = blocks

        data = json.dumps(payload).encode("utf-8")
        request = Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                status = response.getcode()
                body = response.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8") if exc.fp else ""
            raise SlackWebhookError(f"Slack webhook HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise SlackWebhookError(f"Slack webhook error: {exc}") from exc

        if status >= 400 or (body and body.strip().lower() not in ("ok", "")):
            raise SlackWebhookError(f"Slack webhook error: HTTP {status} {body}")

        return SlackResponse(status=status, body=body)
