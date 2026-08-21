from engine.attacks.base import AttackPlugin
from engine.attacks.registry import PLUGIN_REGISTRY, PluginRegistry, attack_plugin, discover_plugins

from engine.attacks import (
    data_leakage,
    document,
    escalation,
    injection,
    jailbreak,
    manipulation,
    permission,
    rag_poison,
    tool_abuse,
    unsafe_tool,
)

discover_plugins()

__all__ = [
    "AttackPlugin",
    "PLUGIN_REGISTRY",
    "PluginRegistry",
    "attack_plugin",
    "discover_plugins",
]