from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SeedManager:
    seeds: dict[str, list[str]] = field(default_factory=dict)
    used: dict[str, set[str]] = field(default_factory=dict)

    @staticmethod
    def digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

    def add(self, plugin: str, text: str) -> str:
        digest = self.digest(text)
        existing = self.seeds.setdefault(plugin, [])
        if digest not in {self.digest(t) for t in existing}:
            existing.append(text)
        return digest

    def unused(self, plugin: str) -> list[str]:
        used = self.used.get(plugin, set())
        return [text for text in self.seeds.get(plugin, []) if self.digest(text) not in used]

    def mark_used(self, plugin: str, text: str) -> None:
        self.used.setdefault(plugin, set()).add(self.digest(text))

    def all_digests(self) -> list[str]:
        return sorted({self.digest(t) for texts in self.seeds.values() for t in texts})

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugins": {plugin: [self.digest(t) for t in texts] for plugin, texts in self.seeds.items()},
            "used": {plugin: sorted(used) for plugin, used in self.used.items()},
        }