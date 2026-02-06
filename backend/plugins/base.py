from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence


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
