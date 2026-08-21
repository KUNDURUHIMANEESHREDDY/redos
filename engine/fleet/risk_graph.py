from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from engine.fleet.correlation import plugin_from_attack_id
from engine.fleet.posture import SEVERITY_WEIGHTS
from engine.security import FindingRecord


@dataclass(frozen=True, slots=True)
class RiskNode:
    node_id: str
    node_type: str
    risk: float
    finding_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "risk": self.risk,
            "finding_ids": list(self.finding_ids),
        }


@dataclass(slots=True)
class RiskGraph:
    """Finding-derived risk graph over targets, plugins, and findings.

    Nodes: one per target, one per plugin, one per finding. Edges: a finding
    is linked to its target and to the plugin that produced it. Risk of a
    node is the severity-weighted sum of its findings (unclassified findings
    contribute zero weight, mirroring `PostureEngine`).

    This is a risk summary derived from real finding records — it is not a
    full attack graph, which the codebase does not implement.
    """

    findings: list[FindingRecord] = field(default_factory=list)

    def add_findings(self, records: Iterable[FindingRecord]) -> None:
        self.findings.extend(records)

    def _weight(self, record: FindingRecord) -> float:
        level = str(record.severity).upper() if record.severity else None
        return SEVERITY_WEIGHTS.get(level, 0.0)

    def nodes(self) -> list[RiskNode]:
        by_target: dict[str, list[FindingRecord]] = {}
        by_plugin: dict[str, list[FindingRecord]] = {}
        by_finding: dict[str, FindingRecord] = {}
        for record in self.findings:
            by_target.setdefault(record.target_id, []).append(record)
            by_plugin.setdefault(plugin_from_attack_id(record.attack_id), []).append(record)
            by_finding[record.finding_id] = record

        nodes: list[RiskNode] = []
        for target_id, records in by_target.items():
            nodes.append(
                RiskNode(
                    node_id=f"target:{target_id}",
                    node_type="target",
                    risk=round(sum(self._weight(r) for r in records), 2),
                    finding_ids=tuple(sorted(r.finding_id for r in records)),
                )
            )
        for plugin, records in by_plugin.items():
            nodes.append(
                RiskNode(
                    node_id=f"plugin:{plugin}",
                    node_type="plugin",
                    risk=round(sum(self._weight(r) for r in records), 2),
                    finding_ids=tuple(sorted(r.finding_id for r in records)),
                )
            )
        for finding_id, record in by_finding.items():
            nodes.append(
                RiskNode(
                    node_id=f"finding:{finding_id}",
                    node_type="finding",
                    risk=round(self._weight(record), 2),
                    finding_ids=(finding_id,),
                )
            )
        return nodes

    def neighbors(self, node_id: str) -> list[RiskNode]:
        """Nodes directly linked to the given node."""
        prefix, sep, key = node_id.partition(":")
        if not sep:
            return []
        if prefix == "finding":
            record = next(r for r in self.findings if r.finding_id == key)
            targets = {f"target:{record.target_id}", f"plugin:{plugin_from_attack_id(record.attack_id)}"}
        else:
            members = [r for r in self.findings if self._belongs(prefix, key, r)]
            targets = {f"target:{r.target_id}" for r in members}
            targets.update(f"plugin:{plugin_from_attack_id(r.attack_id)}" for r in members)
            targets.discard(node_id)
        all_nodes = {n.node_id: n for n in self.nodes()}
        return [all_nodes[nid] for nid in sorted(targets) if nid in all_nodes]

    def _belongs(self, prefix: str, key: str, record: FindingRecord) -> bool:
        if prefix == "target":
            return record.target_id == key
        if prefix == "plugin":
            return plugin_from_attack_id(record.attack_id) == key
        return False

    def most_risky(self, node_type: str | None = None, limit: int = 5) -> list[RiskNode]:
        nodes = self.nodes()
        if node_type:
            nodes = [n for n in nodes if n.node_type == node_type]
        return sorted(nodes, key=lambda n: n.risk, reverse=True)[:limit]