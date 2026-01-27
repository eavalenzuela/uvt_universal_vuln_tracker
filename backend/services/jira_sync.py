from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


class JiraApiError(RuntimeError):
    pass


@dataclass(frozen=True)
class JiraResponse:
    status: int
    payload: dict[str, Any] | None


class JiraClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_token: str,
        user_email: str | None = None,
        timeout: int = 15,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.user_email = user_email
        self.timeout = timeout

    def create_issue(self, *, fields: dict[str, Any]) -> str:
        response = self._request(
            "POST",
            "/rest/api/3/issue",
            payload={"fields": fields},
        )
        if not response.payload or "key" not in response.payload:
            raise JiraApiError("Jira create issue response missing key.")
        return response.payload["key"]

    def update_issue(self, *, issue_key: str, fields: dict[str, Any]) -> None:
        self._request(
            "PUT",
            f"/rest/api/3/issue/{issue_key}",
            payload={"fields": fields},
        )

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> JiraResponse:
        url = urljoin(f"{self.base_url}/", path.lstrip("/"))
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(
            url,
            data=data,
            headers=self._headers(),
            method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                status = response.getcode()
                body = response.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8") if exc.fp else ""
            raise JiraApiError(f"Jira API error HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise JiraApiError(f"Jira API error: {exc}") from exc

        payload_data: dict[str, Any] | None = None
        if body:
            try:
                payload_data = json.loads(body)
            except json.JSONDecodeError as exc:
                raise JiraApiError(f"Invalid Jira JSON response: {body}") from exc

        if status >= 400:
            raise JiraApiError(f"Jira API error HTTP {status}: {body}")

        return JiraResponse(status=status, payload=payload_data)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.user_email:
            token = f"{self.user_email}:{self.api_token}".encode("utf-8")
            headers["Authorization"] = f"Basic {base64.b64encode(token).decode('utf-8')}"
        else:
            headers["Authorization"] = f"Bearer {self.api_token}"
        return headers
