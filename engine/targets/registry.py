from __future__ import annotations

from engine.model.errors import ConfigurationError
from engine.targets.config import TargetConfig


class TargetRegistry:
    def __init__(self) -> None:
        self._targets: dict[str, TargetConfig] = {}

    def register(self, config: TargetConfig) -> TargetConfig:
        self._targets[config.target_id] = config
        return config

    def get(self, target_id: str) -> TargetConfig:
        try:
            return self._targets[target_id]
        except KeyError:
            raise ConfigurationError(f"unknown target_id: {target_id!r}") from None

    def list(self) -> list[TargetConfig]:
        return list(self._targets.values())

    def remove(self, target_id: str) -> None:
        self._targets.pop(target_id, None)


def register_target(config: TargetConfig) -> TargetConfig:
    from engine.targets.registry import _DEFAULT_REGISTRY

    return _DEFAULT_REGISTRY.register(config)


_DEFAULT_REGISTRY = TargetRegistry()