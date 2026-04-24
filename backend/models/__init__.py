"""Compatibility export layer for SQLAlchemy models."""

from .teams import (
    Team,
    UserTeam,
)

from .auth import (
    User,
    ApiToken,
    RefreshToken,
    AuditLog,
)

from .products import (
    Product,
    ProductOwner,
    ProductVersion,
    Control,
    ControlSource,
    ProductControl,
    SoftwareComponent,
    ComponentDependency,
)

from .vulnerabilities import (
    SavedVulnerabilityFilter,
    DashboardLayoutPreset,
    Vulnerability,
    VulnerabilityComment,
    VulnerabilityWatcher,
    VulnerabilityComponent,
    VulnerabilityVersion,
    AttackVector,
    TerminalImpact,
    VulnerabilityAttackVector,
    VulnerabilityTerminalImpact,
    VulnerabilitySource,
    SlaPolicy,
)

from .notifications import (
    Notification,
    NotificationRule,
    NotificationDeliveryLog,
    NotificationDeliveryCheckpoint,
)

from .plugins import (
    PluginConfig,
    PluginRun,
    PluginRunArtifact,
    PluginRunArtifactLink,
    ExternalSourceState,
)

from .password_reset import (
    PasswordResetToken,
)

from .reports import (
    ReportSchedule,
    ReportTemplate,
    ReportArtifact,
)

from .webhooks import (
    WebhookEndpoint,
    WebhookDeliveryLog,
)

from .user_preferences import (
    UserPreferences,
)

__all__ = [
    "Team",
    "UserTeam",
    "User",
    "ApiToken",
    "RefreshToken",
    "AuditLog",
    "Product",
    "ProductOwner",
    "ProductVersion",
    "Control",
    "ControlSource",
    "ProductControl",
    "SoftwareComponent",
    "ComponentDependency",
    "SavedVulnerabilityFilter",
    "DashboardLayoutPreset",
    "Vulnerability",
    "VulnerabilityComment",
    "VulnerabilityWatcher",
    "VulnerabilityComponent",
    "VulnerabilityVersion",
    "AttackVector",
    "TerminalImpact",
    "VulnerabilityAttackVector",
    "VulnerabilityTerminalImpact",
    "VulnerabilitySource",
    "SlaPolicy",
    "Notification",
    "NotificationRule",
    "NotificationDeliveryLog",
    "NotificationDeliveryCheckpoint",
    "PluginConfig",
    "PluginRun",
    "PluginRunArtifact",
    "PluginRunArtifactLink",
    "ExternalSourceState",
    "PasswordResetToken",
    "ReportSchedule",
    "ReportTemplate",
    "ReportArtifact",
    "WebhookEndpoint",
    "WebhookDeliveryLog",
    "UserPreferences",
]
