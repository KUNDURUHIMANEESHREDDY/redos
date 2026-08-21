from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from engine.model.plan import AttackDefinition


@dataclass(slots=True)
class ChainContext:
    observations: dict[str, Any] = field(default_factory=dict)

    def record(self, attack_id: str, data: Mapping[str, Any]) -> None:
        self.observations[attack_id] = dict(data)

    def get(self, attack_id: str) -> Any:
        return self.observations.get(attack_id)

    def render(self, text: str) -> str:
        out = text
        for attack_id, value in self.observations.items():
            token = f"{{chain.{attack_id}}}"
            if token in out:
                out = out.replace(token, str(value))
            prefix = f"{{chain.{attack_id}."
            if prefix in out:
                if isinstance(value, dict):
                    for field, field_value in value.items():
                        out = out.replace(prefix + field + "}", str(field_value))
                else:
                    out = out.replace(prefix, "")
                    out = out.replace("}", "")
        return out

    def render_params(self, params: Mapping[str, Any]) -> dict[str, Any]:
        rendered: dict[str, Any] = {}
        for key, value in params.items():
            if isinstance(value, str):
                rendered[key] = self.render(value)
            else:
                rendered[key] = value
        return rendered

    def render_definition(self, definition: AttackDefinition) -> AttackDefinition:
        return AttackDefinition(
            attack_id=definition.attack_id,
            name=definition.name,
            attack_type=definition.attack_type,
            plugin=definition.plugin,
            params=self.render_params(definition.params),
            target=definition.target,
            policy=definition.policy,
            requires=definition.requires,
        )