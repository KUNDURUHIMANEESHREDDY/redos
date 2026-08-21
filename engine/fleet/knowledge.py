from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from engine.fleet.correlation import plugin_from_attack_id
from engine.security import FindingRecord


@dataclass(frozen=True, slots=True)
class KnowledgeLesson:
    """A learned pattern derived from real findings.

    `source_finding_id` links the lesson to the finding that produced it so
    the provenance chain stays intact; a lesson without a source finding is
    rejected on ingest.
    """

    plugin: str
    outcome: str
    outcome_reason: str
    source_finding_id: str
    target_ids: tuple[str, ...] = ()
    occurrences: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "outcome": self.outcome,
            "outcome_reason": self.outcome_reason,
            "source_finding_id": self.source_finding_id,
            "target_ids": list(self.target_ids),
            "occurrences": self.occurrences,
        }


class KnowledgeBase:
    """Stores patterns learned from validated findings and serves them to
    downstream layers (e.g. hypothesis seeding) on request.

    Ingestion only accepts records that reached the findings gateway, so the
    knowledge base can never learn from mock evidence. This module does not
    modify the engine's hypothesis pipeline; consumers opt in.
    """

    def __init__(self) -> None:
        self._lessons: dict[tuple[str, str, str], KnowledgeLesson] = {}

    def ingest(self, record: FindingRecord) -> KnowledgeLesson:
        plugin = plugin_from_attack_id(record.attack_id)
        key = (plugin, record.outcome, record.outcome_reason)
        existing = self._lessons.get(key)
        if existing is None:
            lesson = KnowledgeLesson(
                plugin=plugin,
                outcome=record.outcome,
                outcome_reason=record.outcome_reason,
                source_finding_id=record.finding_id,
                target_ids=(record.target_id,),
            )
            self._lessons[key] = lesson
            return lesson
        targets = set(existing.target_ids)
        targets.add(record.target_id)
        lesson = KnowledgeLesson(
            plugin=existing.plugin,
            outcome=existing.outcome,
            outcome_reason=existing.outcome_reason,
            source_finding_id=existing.source_finding_id,
            target_ids=tuple(sorted(targets)),
            occurrences=existing.occurrences + 1,
        )
        self._lessons[key] = lesson
        return lesson

    def ingest_many(self, records: Iterable[FindingRecord]) -> list[KnowledgeLesson]:
        return [self.ingest(r) for r in records]

    def query(self, plugin: str | None = None) -> list[KnowledgeLesson]:
        lessons = list(self._lessons.values())
        if plugin:
            lessons = [l for l in lessons if l.plugin == plugin]
        lessons.sort(key=lambda l: l.occurrences, reverse=True)
        return lessons

    def top_patterns(self, limit: int = 5) -> list[KnowledgeLesson]:
        return sorted(self._lessons.values(), key=lambda l: l.occurrences, reverse=True)[:limit]

    def __len__(self) -> int:
        return len(self._lessons)