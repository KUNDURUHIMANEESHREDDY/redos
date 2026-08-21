from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from engine.security import FindingRecord


def plugin_from_attack_id(attack_id: str) -> str:
    """Extract the plugin name from an attack_id.

    The intelligence runner records findings with attack_id
    ``"{plugin}:exp-{index}"``; direct submissions may use any id, in which
    case the id itself is returned.
    """
    return attack_id.split(":", 1)[0] or attack_id


@dataclass(frozen=True, slots=True)
class CorrelationCluster:
    plugin: str
    target_ids: tuple[str, ...]
    count: int
    severity_counts: dict[str, int]
    first_seen: datetime
    last_seen: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "target_ids": list(self.target_ids),
            "count": self.count,
            "severity_counts": dict(self.severity_counts),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


class CorrelationEngine:
    """Correlates findings across targets by the plugin that produced them.

    A cluster means the same vulnerability class was proven on multiple
    targets; spread (number of distinct targets) is the signal used by
    downstream risk and analytics layers. Correlation is always over real
    finding records; an empty input yields no clusters.
    """

    def cluster(self, records: Iterable[FindingRecord]) -> list[CorrelationCluster]:
        groups: dict[str, list[FindingRecord]] = {}
        for record in records:
            groups.setdefault(plugin_from_attack_id(record.attack_id), []).append(record)

        clusters: list[CorrelationCluster] = []
        for plugin, group in groups.items():
            targets = sorted({r.target_id for r in group})
            severity_counts: dict[str, int] = {}
            for r in group:
                level = str(r.severity).upper() if r.severity else None
                if level:
                    severity_counts[level] = severity_counts.get(level, 0) + 1
            times = sorted(r.stored_at for r in group)
            clusters.append(
                CorrelationCluster(
                    plugin=plugin,
                    target_ids=tuple(targets),
                    count=len(group),
                    severity_counts=severity_counts,
                    first_seen=times[0],
                    last_seen=times[-1],
                )
            )
        clusters.sort(key=lambda c: (c.count, len(c.target_ids)), reverse=True)
        return clusters