from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable, Mapping, Sequence


class BasePlugin(ABC):
    plugin_id: str = ""
    display_name: str = ""
    version: str = "0.0.0"
    capabilities: Sequence[str] = ()
    config_schema: Mapping[str, Any] = {}

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        self.config = dict(config or {})

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
