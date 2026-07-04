from __future__ import annotations

from typing import Any

from backend.services.jira_sync import JiraApiError, JiraClient
from backend.services.slack_alerts import SlackWebhookClient, SlackWebhookError

from .base import BasePlugin
from .controls_import_plugins import (
    CisControlsImportPlugin,
    PciDssControlsImportPlugin,
    StigControlsImportPlugin,
)
from .vuln_feed_plugins import (
    ExploitDbVulnerabilityFeedPlugin,
    KevVulnerabilityFeedPlugin,
    NvdVulnerabilityFeedPlugin,
)


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
        webhook_url = self.config.get("webhook_url")
        if not webhook_url:
            raise SlackWebhookError("Missing Slack webhook URL.")

        channel = self.config.get("default_channel")
        mention_group = self.config.get("mention_group")
        minimum_severity = self.config.get("minimum_severity", "High")
        notify_on_status_change = self.config.get("notify_on_status_change", True)

        prefix = f"{mention_group} " if mention_group else ""
        text = (
            f"{prefix}UVT alert check-in. Minimum severity: {minimum_severity}. "
            f"Notify on status change: {bool(notify_on_status_change)}."
        )

        client = SlackWebhookClient(webhook_url)
        try:
            client.send_message(text=text, channel=channel)
        except SlackWebhookError as exc:
            raise SlackWebhookError(f"Slack webhook failed: {exc}") from exc

        return {"status": "success", "stats": {"sent": 1, "failed": 0}}


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
            {
                "name": "user_email",
                "label": "User email",
                "type": "string",
            },
            {
                "name": "summary",
                "label": "Summary",
                "type": "string",
                "default": "UVT vulnerability sync",
            },
            {
                "name": "description",
                "label": "Description",
                "type": "string",
                "default": "Issue synced from UVT.",
            },
            {
                "name": "issue_key",
                "label": "Issue key",
                "type": "string",
            },
        ],
    }

    def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        base_url = self.config.get("base_url")
        project_key = self.config.get("project_key")
        api_token = self.config.get("api_token")
        user_email = self.config.get("user_email")
        if not base_url or not project_key or not api_token:
            raise JiraApiError("Missing Jira configuration for base_url, project_key, or api_token.")

        client = JiraClient(
            base_url=base_url,
            api_token=api_token,
            user_email=user_email,
        )

        summary = self.config.get("summary", "UVT vulnerability sync")
        description = self.config.get("description", "Issue synced from UVT.")
        issue_type = self.config.get("issue_type", "Bug")

        fields = {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
        }

        issue_key = self.config.get("issue_key")
        stats = {"created": 0, "updated": 0}
        if issue_key:
            client.update_issue(issue_key=issue_key, fields=fields)
            stats["updated"] = 1
        else:
            issue_key = client.create_issue(fields=fields)
            stats["created"] = 1

        stats["issue_key"] = issue_key
        return {"status": "success", "stats": stats}


BUILTIN_PLUGINS: tuple[type[BasePlugin], ...] = (
    SlackAlertsPlugin,
    JiraSyncPlugin,
    NvdVulnerabilityFeedPlugin,
    ExploitDbVulnerabilityFeedPlugin,
    KevVulnerabilityFeedPlugin,
    CisControlsImportPlugin,
    PciDssControlsImportPlugin,
    StigControlsImportPlugin,
)
