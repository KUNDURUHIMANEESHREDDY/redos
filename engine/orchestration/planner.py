from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping
from uuid import uuid4

from engine.attacks.registry import PluginRegistry
from engine.model.attack import AttackType
from engine.model.plan import AttackDefinition, ExecutionPlan, PlanStep
from engine.model.errors import PluginError


@dataclass(slots=True)
class AttackPlanner:
    registry: PluginRegistry | None = None

    def _plugin(self, definition: AttackDefinition):
        if self.registry is None:
            from engine.attacks.registry import PLUGIN_REGISTRY

            self.registry = PLUGIN_REGISTRY
        plugin = self.registry.get(definition.plugin)
        if plugin is None:
            raise PluginError(f"no attack plugin registered for key {definition.plugin!r}")
        return plugin

    def plan(self, definition: AttackDefinition) -> ExecutionPlan:
        plugin = self._plugin(definition)
        resolved_params = {**plugin.default_params(), **dict(definition.params)}
        resolved = AttackDefinition(
            attack_id=definition.attack_id,
            name=definition.name,
            attack_type=definition.attack_type,
            plugin=definition.plugin,
            params=resolved_params,
            target=definition.target,
            policy=definition.policy,
            requires=definition.requires,
        )
        steps = self._steps(resolved)
        return ExecutionPlan(
            plan_id=uuid4().hex,
            attack=resolved,
            steps=tuple(steps),
            replay_hash=resolved.replay_hash(),
        )

    def _steps(self, definition: AttackDefinition) -> list[PlanStep]:
        kind = definition.attack_type
        steps = [
            PlanStep(0, "plan", "plan attack against target", {"target": definition.target.target_id, "plugin": definition.plugin}),
            PlanStep(1, "payload", f"construct {kind.value} payload", {"params": definition.params}),
        ]
        max_turns = definition.policy.max_turns
        if kind in (AttackType.TOOL_ABUSE, AttackType.UNSAFE_TOOL_CALL, AttackType.AGENT_ESCALATION):
            steps.append(PlanStep(2, "interaction", f"multi-turn interaction (max {max_turns} turns)", {"max_turns": max_turns}))
        elif kind in (AttackType.MALICIOUS_DOCUMENT, AttackType.RAG_POISONING):
            steps.append(PlanStep(2, "interaction", "inject content into target context", {}))
        else:
            steps.append(PlanStep(2, "interaction", "single-turn interaction", {}))
        steps.append(PlanStep(3, "evaluate", "evaluate observed evidence for outcome", {}))
        return steps