from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class CoverageTracker:
    available: list[str] = field(default_factory=list)
    attempts: dict[str, list[str]] = field(default_factory=dict)
    outcomes: dict[str, str] = field(default_factory=dict)

    def set_available(self, plugin_keys: list[str]) -> None:
        self.available = sorted(plugin_keys)

    def attempted(self, family: str) -> bool:
        return any(key.startswith(f"{family}.") for key in self.attempts)

    def tried(self, plugin: str) -> bool:
        return plugin in self.attempts

    def record_plugin(self, plugin: str, outcome: str) -> None:
        self.attempts.setdefault(plugin, []).append(outcome)
        self.outcomes[plugin] = outcome

    def families(self) -> list[str]:
        return sorted({key.split(".", 1)[0] for key in self.attempts})

    def uncovered_families(self) -> list[str]:
        return sorted({key.split(".", 1)[0] for key in self.available} - set(self.families()))

    def uncovered_plugins(self) -> list[str]:
        return [key for key in self.available if not self.tried(key)]

    def coverage_ratio(self) -> float:
        if not self.available:
            return 0.0
        return len([key for key in self.available if self.tried(key)]) / len(self.available)

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": list(self.available),
            "attempted_families": self.families(),
            "uncovered_families": self.uncovered_families(),
            "uncovered_plugins": self.uncovered_plugins(),
            "coverage_ratio": self.coverage_ratio(),
            "attempts": dict(self.attempts),
            "outcomes": dict(self.outcomes),
        }