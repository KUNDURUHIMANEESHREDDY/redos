from __future__ import annotations

import importlib
import pkgutil
from typing import Any

from engine.attacks.base import AttackPlugin
from engine.model.errors import PluginError


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, AttackPlugin] = {}

    def register(self, plugin: AttackPlugin) -> AttackPlugin:
        if plugin.key in self._plugins:
            raise PluginError(f"duplicate attack plugin key: {plugin.key!r}")
        self._plugins[plugin.key] = plugin
        return plugin

    def get(self, key: str) -> AttackPlugin | None:
        return self._plugins.get(key)

    def require(self, key: str) -> AttackPlugin:
        plugin = self.get(key)
        if plugin is None:
            raise PluginError(f"no attack plugin registered for key {key!r}")
        return plugin

    def keys(self) -> list[str]:
        return sorted(self._plugins)

    def all(self) -> list[AttackPlugin]:
        return list(self._plugins.values())

    def instantiate(self, cls: type[AttackPlugin]) -> AttackPlugin:
        instance = cls()
        return self.register(instance)


def discover_plugins(package: str = "engine.attacks", registry: PluginRegistry | None = None) -> PluginRegistry:
    registry = registry or PLUGIN_REGISTRY
    package_mod = importlib.import_module(package)
    for module_info in pkgutil.iter_modules(package_mod.__path__):
        if module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{package}.{module_info.name}")
        for _, cls in vars(module).items():
            if not isinstance(cls, type) or not issubclass(cls, AttackPlugin) or cls is AttackPlugin:
                continue
            key = getattr(cls, "key", "")
            if not key or key in registry._plugins:
                continue
            registry.register(cls())
    return registry


def attack_plugin(cls: type[AttackPlugin]) -> type[AttackPlugin]:
    instance = cls()
    if not instance.key:
        raise PluginError(f"plugin {cls.__name__} must define a non-empty key")
    PLUGIN_REGISTRY.register(instance)
    return cls


PLUGIN_REGISTRY = PluginRegistry()