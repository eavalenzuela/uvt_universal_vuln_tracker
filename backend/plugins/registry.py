from __future__ import annotations

import importlib
import logging
from typing import Iterable, Mapping, Sequence, Type

from .base import BasePlugin
from .builtins import BUILTIN_PLUGINS

logger = logging.getLogger(__name__)


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, Type[BasePlugin]] = {}

    def clear(self) -> None:
        self._plugins.clear()

    def register(self, plugin_cls: Type[BasePlugin]) -> None:
        plugin_id = plugin_cls.plugin_id
        if not plugin_id:
            raise ValueError("Plugin classes must define a non-empty plugin_id.")
        if plugin_id in self._plugins:
            raise ValueError(f"Plugin '{plugin_id}' is already registered.")
        self._plugins[plugin_id] = plugin_cls

    def list_plugins(self) -> list[Type[BasePlugin]]:
        return list(self._plugins.values())

    def create(self, plugin_id: str, config: Mapping[str, object] | None = None) -> BasePlugin:
        plugin_cls = self._plugins.get(plugin_id)
        if not plugin_cls:
            raise KeyError(f"No plugin registered with id '{plugin_id}'.")
        return plugin_cls(config=config)


def load_plugins(
    registry: PluginRegistry,
    *,
    import_paths: Sequence[str] | None = None,
    builtin_plugins: Iterable[Type[BasePlugin]] = BUILTIN_PLUGINS,
) -> None:
    for plugin_cls in builtin_plugins:
        registry.register(plugin_cls)

    for module_path in import_paths or []:
        if not module_path:
            continue
        logger.info("Loading plugin module: %s", module_path)
        importlib.import_module(module_path)


def init_plugin_registry(app) -> PluginRegistry:
    registry = PluginRegistry()
    load_plugins(registry, import_paths=app.config.get("PLUGIN_IMPORT_PATHS", []))
    app.extensions["plugin_registry"] = registry
    return registry
