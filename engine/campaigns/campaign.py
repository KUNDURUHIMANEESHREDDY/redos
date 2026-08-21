from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4

from engine.targets.config import TargetConfig


class CampaignStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    STOPPED = "stopped"
    FAILED = "failed"

    def is_terminal(self) -> bool:
        return self in (CampaignStatus.COMPLETED, CampaignStatus.CANCELLED, CampaignStatus.STOPPED, CampaignStatus.FAILED)


@dataclass(frozen=True, slots=True)
class CampaignBudget:
    max_attacks: int = 10
    max_duration_s: float = 300.0
    max_turns_total: int | None = None
    cost_per_turn: float = 0.0
    max_cost: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_attacks": self.max_attacks,
            "max_duration_s": self.max_duration_s,
            "max_turns_total": self.max_turns_total,
            "cost_per_turn": self.cost_per_turn,
            "max_cost": self.max_cost,
        }


@dataclass(frozen=True, slots=True)
class CampaignConfig:
    campaign_id: str
    name: str
    target: TargetConfig
    strategy: str = "observation_driven"
    seed: int = 0
    budget: CampaignBudget = field(default_factory=CampaignBudget)
    plugin_filter: tuple[str, ...] = ()

    def replay_hash(self) -> str:
        material = json.dumps(
            {
                "campaign_id": self.campaign_id,
                "name": self.name,
                "strategy": self.strategy,
                "seed": self.seed,
                "budget": self.budget.to_dict(),
                "plugin_filter": list(self.plugin_filter),
                "target": self.target.fingerprint(),
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    @staticmethod
    def create(
        name: str,
        target: TargetConfig,
        *,
        strategy: str = "observation_driven",
        seed: int = 0,
        budget: CampaignBudget | None = None,
        plugin_filter: tuple[str, ...] = (),
    ) -> "CampaignConfig":
        return CampaignConfig(
            campaign_id=uuid4().hex,
            name=name,
            target=target,
            strategy=strategy,
            seed=seed,
            budget=budget or CampaignBudget(),
            plugin_filter=tuple(plugin_filter),
        )


@dataclass(frozen=True, slots=True)
class CampaignStep:
    index: int
    plugin: str
    attack_type: str
    outcome: str
    status: str
    reasoning: str
    execution_id: str
    depends_on: int | None = None
    matched_indicators: tuple[str, ...] = ()
    tool_evidence: int = 0
    retrieval_evidence: int = 0
    turns_used: int = 0
    estimated_cost: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "plugin": self.plugin,
            "attack_type": self.attack_type,
            "outcome": self.outcome,
            "status": self.status,
            "reasoning": self.reasoning,
            "execution_id": self.execution_id,
            "depends_on": self.depends_on,
            "matched_indicators": list(self.matched_indicators),
            "tool_evidence": self.tool_evidence,
            "retrieval_evidence": self.retrieval_evidence,
            "turns_used": self.turns_used,
            "estimated_cost": self.estimated_cost,
        }


@dataclass(slots=True)
class Campaign:
    config: CampaignConfig
    status: CampaignStatus = CampaignStatus.PENDING
    steps: list[CampaignStep] = field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    stopped_reason: str | None = None
    evidence: dict[str, Any] | None = None

    def start(self) -> None:
        self.status = CampaignStatus.RUNNING
        self.started_at = self.started_at or datetime.now(timezone.utc)

    def finish(self, status: CampaignStatus, reason: str | None = None) -> None:
        self.status = status
        self.finished_at = datetime.now(timezone.utc)
        self.stopped_reason = reason

    def turns_used(self) -> int:
        return sum(step.turns_used for step in self.steps)

    def estimated_cost(self) -> float:
        return round(sum(step.estimated_cost for step in self.steps), 4)

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.config.campaign_id,
            "name": self.config.name,
            "strategy": self.config.strategy,
            "seed": self.config.seed,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "stopped_reason": self.stopped_reason,
            "steps": [step.to_dict() for step in self.steps],
            "turns_used": self.turns_used(),
            "estimated_cost": self.estimated_cost(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)