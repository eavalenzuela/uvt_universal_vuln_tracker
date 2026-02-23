"""Compatibility export layer for SQLAlchemy models."""

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

from .reports import (
    ReportSchedule,
    ReportTemplate,
    ReportArtifact,
)

__all__ = [
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
    "ReportSchedule",
    "ReportTemplate",
    "ReportArtifact",
]
