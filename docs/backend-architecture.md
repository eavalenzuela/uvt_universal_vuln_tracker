# Backend Architecture: Model Bounded Contexts

The backend model layer is organized as a package at `backend/models/` and split by bounded context.

## Context modules

- `backend/models/auth.py`
  - Ownership: authentication and identity primitives.
  - Models: `User`, `ApiToken`, `RefreshToken`, `AuditLog`.
  - Add here when data is tied to login, token lifecycle, or actor auditing.

- `backend/models/products.py`
  - Ownership: product catalog, ownership, versioning, and controls.
  - Models: `Product`, `ProductOwner`, `ProductVersion`, `Control`, `ControlSource`, `ProductControl`, `SoftwareComponent`, `ComponentDependency`.
  - Add here when data is anchored to product/version topology.

- `backend/models/vulnerabilities.py`
  - Ownership: vulnerability records, scoring, metadata, and vulnerability workflow state.
  - Models: `SavedVulnerabilityFilter`, `DashboardLayoutPreset`, `Vulnerability`, `VulnerabilityComment`, `VulnerabilityWatcher`, `VulnerabilityComponent`, `VulnerabilityVersion`, `AttackVector`, `TerminalImpact`, `VulnerabilityAttackVector`, `VulnerabilityTerminalImpact`, `VulnerabilitySource`, `SlaPolicy`.
  - Add here when data exists to classify, enrich, triage, or track vulnerability state.

- `backend/models/notifications.py`
  - Ownership: outbound notification subscriptions and delivery telemetry.
  - Models: `Notification`, `NotificationRule`, `NotificationDeliveryLog`, `NotificationDeliveryCheckpoint`.
  - Add here when data is related to deciding who gets notified and what was delivered.

- `backend/models/plugins.py`
  - Ownership: plugin configuration, execution tracking, and generated artifact linkage.
  - Models: `PluginConfig`, `PluginRun`, `PluginRunArtifact`, `PluginRunArtifactLink`, `ExternalSourceState`.
  - Add here for ingestion/integration runtime state owned by plugin execution.

- `backend/models/reports.py`
  - Ownership: report templates, schedules, and generated exports.
  - Models: `ReportSchedule`, `ReportTemplate`, `ReportArtifact`.
  - Add here when data drives report generation and report delivery configuration.

## Cross-context relationships and import rules

- Prefer SQLAlchemy relationship targets as **strings** (for example `db.relationship("User")`) across contexts.
- Use foreign keys by table name (for example `db.ForeignKey("users.id")`) instead of importing model classes directly.
- Keep `backend/models/__init__.py` as the compatibility export layer to support incremental import migration.

## Adding new models

1. Place the model in the owning context module above.
2. Export it from `backend/models/__init__.py`.
3. Use string relationship targets to avoid circular imports.
4. If ownership is ambiguous, choose the context that owns lifecycle and write APIs for the entity.
