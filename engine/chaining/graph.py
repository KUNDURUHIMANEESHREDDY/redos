from __future__ import annotations

from typing import Any

from engine.reconnaissance.profile import TargetProfile

RETRIEVAL_FAMILIES = ("rag_poisoning",)
TOOL_FAMILIES = ("unsafe_tool_call", "tool_abuse", "agent_escalation")


class DependencyGraph:
    def requires(self, plugin: str) -> set[str]:
        family = plugin.split(".", 1)[0]
        requirements: set[str] = set()
        if family in RETRIEVAL_FAMILIES:
            requirements.add("retrieval")
        if family in TOOL_FAMILIES:
            requirements.add("tools")
        return requirements

    def satisfied(self, plugin: str, profile: TargetProfile) -> bool:
        requirements = self.requires(plugin)
        if "tools" in requirements and not (profile.tool_capability or bool(profile.tools)):
            return False
        if "retrieval" in requirements and not profile.retrieval_supported:
            return False
        return True

    def candidates(self, plugins: list[str], profile: TargetProfile) -> list[str]:
        return [plugin for plugin in plugins if self.satisfied(plugin, profile)]

    def to_dict(self, profile: TargetProfile) -> dict[str, Any]:
        return {
            "retrieval_families": list(RETRIEVAL_FAMILIES),
            "tool_families": list(TOOL_FAMILIES),
            "satisfied_for_profile": {
                "retrieval": profile.retrieval_supported,
                "tools": profile.tool_capability or bool(profile.tools),
            },
        }