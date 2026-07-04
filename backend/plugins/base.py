from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


def resolve_plugin_file_path(path: str) -> Path:
    """Resolve a plugin ``file_path`` config value, enforcing ``PLUGIN_DATA_DIR``.

    Plugin config is admin-editable, so an unrestricted ``file_path`` lets an
    Admin (or a compromised Admin account) read arbitrary server files through
    feed/controls import plugins. When the ``PLUGIN_DATA_DIR`` config value is
    set, the resolved path must live inside that directory; when it is empty
    (the default) the legacy unrestricted behavior is preserved so existing
    installs are unaffected until an operator opts in.
    """
    resolved = Path(path).resolve()

    allowed_root = ""
    from flask import current_app, has_app_context

    if has_app_context():
        allowed_root = current_app.config.get("PLUGIN_DATA_DIR") or ""

    if allowed_root:
        root = Path(allowed_root).resolve()
        if not resolved.is_relative_to(root):
            raise ValueError(
                f"Plugin file_path {path!r} is outside PLUGIN_DATA_DIR ({allowed_root!r})."
            )
    return resolved


@dataclass(slots=True)
class PluginArtifactDescriptor:
    artifact_type: str
    storage_path: str
    checksum: str | None = None
    size: int | None = None
    content_type: str | None = None
    vulnerability_ids: list[int] = field(default_factory=list)
    product_version_ids: list[int] = field(default_factory=list)


class BasePlugin(ABC):
    artifact_descriptors: list[PluginArtifactDescriptor]
    plugin_id: str = ""
    display_name: str = ""
    version: str = "0.0.0"
    capabilities: Sequence[str] = ()
    config_schema: Mapping[str, Any] = {}

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        self.config = dict(config or {})
        self.artifact_descriptors = []

    def emit_artifact(self, descriptor: PluginArtifactDescriptor) -> None:
        self.artifact_descriptors.append(descriptor)

    @abstractmethod
    def run(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


class VulnerabilityFeedPlugin(BasePlugin):
    capabilities: Sequence[str] = ("vulnerability_feed",)

    @abstractmethod
    def run(self) -> Iterable[dict[str, Any]]:
        raise NotImplementedError


class ControlsImportPlugin(BasePlugin):
    capabilities: Sequence[str] = ("controls_import",)

    @abstractmethod
    def run(self) -> Iterable[dict[str, Any]]:
        raise NotImplementedError
