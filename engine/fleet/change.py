from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from engine.attack_surface import AttackSurface


@dataclass(frozen=True, slots=True)
class TargetSnapshot:
    """A point-in-time view of one target: measured surface + finding ids."""

    target_id: str
    facts: dict[str, str] = field(default_factory=dict)
    finding_ids: frozenset[str] = frozenset()
    plugin_outcomes: dict[str, str] = field(default_factory=dict)
    recorded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "facts": dict(self.facts),
            "finding_ids": sorted(self.finding_ids),
            "plugin_outcomes": dict(self.plugin_outcomes),
            "recorded_at": self.recorded_at.isoformat(),
        }

    @classmethod
    def from_surface(cls, surface: AttackSurface) -> "TargetSnapshot":
        return cls(
            target_id=surface.target_id,
            facts={f.category: f.observation for f in surface.facts},
        )


@dataclass(frozen=True, slots=True)
class ChangeReport:
    """Diff between two snapshots of the same target."""

    target_id: str
    added_findings: tuple[str, ...]
    resolved_findings: tuple[str, ...]
    changed_facts: dict[str, tuple[str, str]]
    new_fact_categories: tuple[str, ...]
    removed_fact_categories: tuple[str, ...]
    changed_plugin_outcomes: dict[str, tuple[str, str]]
    observed_change: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "added_findings": list(self.added_findings),
            "resolved_findings": list(self.resolved_findings),
            "changed_facts": {k: list(v) for k, v in self.changed_facts.items()},
            "new_fact_categories": list(self.new_fact_categories),
            "removed_fact_categories": list(self.removed_fact_categories),
            "changed_plugin_outcomes": {k: list(v) for k, v in self.changed_plugin_outcomes.items()},
            "observed_change": self.observed_change,
        }


class ChangeDetector:
    """Detects what changed for a target between two scans.

    Findings are identified by their stable `finding_id`, facts by category,
    plugin outcomes by plugin name. The report records only observed
    differences; it never invents them.
    """

    def diff(self, previous: TargetSnapshot, current: TargetSnapshot) -> ChangeReport:
        if previous.target_id != current.target_id:
            raise ValueError(
                f"cannot diff different targets: {previous.target_id!r} vs {current.target_id!r}"
            )

        added = sorted(current.finding_ids - previous.finding_ids)
        resolved = sorted(previous.finding_ids - current.finding_ids)

        prev_facts = dict(previous.facts)
        curr_facts = dict(current.facts)
        changed = {
            cat: (prev_facts[cat], curr_facts[cat])
            for cat in prev_facts.keys() & curr_facts.keys()
            if prev_facts[cat] != curr_facts[cat]
        }
        new_cats = tuple(sorted(curr_facts.keys() - prev_facts.keys()))
        removed_cats = tuple(sorted(prev_facts.keys() - curr_facts.keys()))

        prev_outcomes = dict(previous.plugin_outcomes)
        curr_outcomes = dict(current.plugin_outcomes)
        changed_outcomes = {
            plugin: (prev_outcomes[plugin], curr_outcomes[plugin])
            for plugin in prev_outcomes.keys() & curr_outcomes.keys()
            if prev_outcomes[plugin] != curr_outcomes[plugin]
        }

        observed = bool(added or resolved or changed or new_cats or removed_cats or changed_outcomes)
        return ChangeReport(
            target_id=current.target_id,
            added_findings=tuple(added),
            resolved_findings=tuple(resolved),
            changed_facts=changed,
            new_fact_categories=new_cats,
            removed_fact_categories=removed_cats,
            changed_plugin_outcomes=changed_outcomes,
            observed_change=observed,
        )