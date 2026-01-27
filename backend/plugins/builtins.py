from __future__ import annotations

from typing import Any

from .base import BasePlugin


class SlackAlertsPlugin(BasePlugin):
    plugin_id = "slack"
    display_name = "Slack Alerts"
    version = "1.4.2"
    capabilities = ("notifications", "alerts")
    config_schema = {
        "fields": [
            {
                "name": "webhook_url",
                "label": "Webhook URL",
                "type": "string",
                "required": True,
                "secret": True,
            },
            {
                "name": "default_channel",
                "label": "Default channel",
                "type": "string",
                "default": "#security-triage",
            },
            {
                "name": "minimum_severity",
                "label": "Minimum severity",
                "type": "string",
                "default": "High",
            },
            {
                "name": "mention_group",
                "label": "Mention group",
                "type": "string",
            },
            {
                "name": "notify_on_status_change",
                "label": "Notify on status change",
                "type": "boolean",
                "default": True,
            },
        ],
    }

    def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"status": "noop"}


class JiraSyncPlugin(BasePlugin):
    plugin_id = "jira"
    display_name = "Jira Sync"
    version = "2.1.0"
    capabilities = ("ticketing", "assignments")
    config_schema = {
        "fields": [
            {
                "name": "base_url",
                "label": "Base URL",
                "type": "string",
                "required": True,
            },
            {
                "name": "project_key",
                "label": "Project key",
                "type": "string",
                "required": True,
            },
            {
                "name": "issue_type",
                "label": "Issue type",
                "type": "string",
                "default": "Bug",
            },
            {
                "name": "api_token",
                "label": "API token",
                "type": "string",
                "required": True,
                "secret": True,
            },
            {
                "name": "default_assignee",
                "label": "Default assignee",
                "type": "string",
            },
            {
                "name": "label_prefix",
                "label": "Label prefix",
                "type": "string",
                "default": "uvt-",
            },
        ],
    }

    def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"status": "noop"}


BUILTIN_PLUGINS: tuple[type[BasePlugin], ...] = (
    SlackAlertsPlugin,
    JiraSyncPlugin,
)
