from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Mapping

from engine.attacks.registry import PLUGIN_REGISTRY
from engine.model.attack import AttackType
from engine.reconnaissance.profile import TargetProfile
from engine.strategies.selector import STRATEGY_OBSERVATION_DRIVEN, AttackCandidate

TOOL_PLUGINS = ("unsafe_tool_call.shell", "unsafe_tool_call.sql", "tool_abuse.negation", "tool_abuse.overload")


@dataclass(slots=True)
class ObservationDrivenStrategy:
    name: str = STRATEGY_OBSERVATION_DRIVEN
    probe_plugin: str = "data_leakage.probe"

    def _family(self, plugin: str) -> str:
        return plugin.split(".", 1)[0]

    def select(
        self,
        state: Any,
        coverage: Any,
        profile: TargetProfile,
        rng: random.Random,
        step_index: int,
    ) -> AttackCandidate | None:
        tools_available = profile.tool_capability or bool(profile.tools)
        retrieval_available = profile.retrieval_supported

        if not state.observations:
            return AttackCandidate(
                plugin=self.probe_plugin,
                attack_type=AttackType.DATA_LEAKAGE,
                params={},
                reasoning="no observations yet; baseline probe to map target response behavior",
            )

        probe = state.get(self.probe_plugin)
        tool_family_tried = coverage.attempted("unsafe_tool_call")

        if tools_available and not tool_family_tried:
            tool = "shell" if "shell" in profile.tool_names else profile.tool_names[0] if profile.tool_names else "shell"
            return AttackCandidate(
                plugin="unsafe_tool_call.shell",
                attack_type=AttackType.UNSAFE_TOOL_CALL,
                params={"command": "whoami", "tool": tool},
                reasoning=(
                    f"probe {self.probe_plugin!r} observed (outcome={probe.outcome if probe else 'n/a'}); "
                    f"reconnaissance discovered tool capability {tool!r} -> escalating to tool execution"
                ),
                depends_on=0,
            )

        if tools_available and state.family_failed_with_evidence("unsafe_tool_call") and not coverage.tried("unsafe_tool_call.sql"):
            return AttackCandidate(
                plugin="unsafe_tool_call.sql",
                attack_type=AttackType.UNSAFE_TOOL_CALL,
                params={},
                reasoning=(
                    f"tool execution observed (evidence={state.total_tool_evidence()} tool result(s)) but indicator not satisfied; "
                    "trying alternate tool plugin unsafe_tool_call.sql"
                ),
                depends_on=step_index - 1,
            )

        if retrieval_available and not coverage.attempted("rag_poisoning"):
            return AttackCandidate(
                plugin="rag_poisoning.plant",
                attack_type=AttackType.RAG_POISONING,
                params={},
                reasoning=(
                    f"reconnaissance confirmed retrieval endpoint; probe {self.probe_plugin!r} observed "
                    f"(outcome={probe.outcome if probe else 'n/a'}) -> poisoning the retrieval path"
                ),
                depends_on=0,
            )

        if not coverage.attempted("prompt_injection"):
            return AttackCandidate(
                plugin="prompt_injection.ignore_previous",
                attack_type=AttackType.PROMPT_INJECTION,
                params={"secret": "system prompt"},
                reasoning=f"baseline established by {self.probe_plugin!r} (outcome={probe.outcome if probe else 'n/a'}); attempting direct prompt injection",
                depends_on=0,
            )

        if not coverage.attempted("jailbreak"):
            return AttackCandidate(
                plugin="jailbreak.developer_mode",
                attack_type=AttackType.JAILBREAK,
                params={},
                reasoning="prompt injection did not extract content; attempting jailbreak technique",
            )

        if tools_available and not coverage.attempted("tool_abuse"):
            tool = profile.tool_names[0] if profile.tool_names else "read_file"
            return AttackCandidate(
                plugin="tool_abuse.negation",
                attack_type=AttackType.TOOL_ABUSE,
                params={"tool": tool},
                reasoning=f"tool capability confirmed earlier; probing tool policy with negation against {tool!r}",
            )

        untried = [
            ("malicious_document.inline", AttackType.MALICIOUS_DOCUMENT),
            ("model_manipulation.format_confusion", AttackType.MODEL_MANIPULATION),
            ("permission.sudo", AttackType.PERMISSION),
            ("agent_escalation.system_override", AttackType.AGENT_ESCALATION),
        ]
        for plugin, attack_type in untried:
            if not coverage.tried(plugin):
                return AttackCandidate(
                    plugin=plugin,
                    attack_type=attack_type,
                    params={},
                    reasoning=f"higher-priority techniques exhausted; expanding to {self._family(plugin)} family",
                )

        return None