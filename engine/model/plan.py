from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4

from engine.model.attack import AttackPolicy, AttackType
from engine.targets.config import TargetConfig


@dataclass(frozen=True, slots=True)
class PlanStep:
    index: int
    kind: str
    description: str
    params: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "kind": self.kind, "description": self.description, "params": dict(self.params)}


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True, slots=True)
class AttackDefinition:
    attack_id: str
    name: str
    attack_type: AttackType
    plugin: str
    params: Mapping[str, Any]
    target: TargetConfig
    policy: AttackPolicy = field(default_factory=AttackPolicy)
    requires: tuple[str, ...] = ()

    @staticmethod
    def create(
        name: str,
        attack_type: AttackType,
        plugin: str,
        params: Mapping[str, Any],
        target: TargetConfig,
        policy: AttackPolicy | None = None,
        requires: tuple[str, ...] = (),
    ) -> "AttackDefinition":
        return AttackDefinition(
            attack_id=uuid4().hex,
            name=name,
            attack_type=attack_type,
            plugin=plugin,
            params=dict(params),
            target=target,
            policy=policy or AttackPolicy(),
            requires=tuple(requires),
        )

    def replay_hash(self) -> str:
        material = _canonical_json(
            {
                "attack_type": self.attack_type.value,
                "plugin": self.plugin,
                "params": self.params,
                "target": self.target.fingerprint(),
                "policy": {
                    "overall_timeout_s": self.policy.overall_timeout_s,
                    "per_turn_timeout_s": self.policy.per_turn_timeout_s,
                    "max_turns": self.policy.max_turns,
                    "max_retries": self.policy.max_retries,
                    "retry_backoff_s": self.policy.retry_backoff_s,
                    "max_artifacts": self.policy.max_artifacts,
                    "capture": {
                        "model_inputs": self.policy.capture.model_inputs,
                        "model_outputs": self.policy.capture.model_outputs,
                        "tool_calls": self.policy.capture.tool_calls,
                        "retrieved_documents": self.policy.capture.retrieved_documents,
                    },
                },
                "requires": list(self.requires),
            }
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "name": self.name,
            "attack_type": self.attack_type.value,
            "plugin": self.plugin,
            "params": dict(self.params),
            "target": self.target.to_dict(),
            "policy": {
                "overall_timeout_s": self.policy.overall_timeout_s,
                "per_turn_timeout_s": self.policy.per_turn_timeout_s,
                "max_turns": self.policy.max_turns,
                "max_retries": self.policy.max_retries,
                "retry_backoff_s": self.policy.retry_backoff_s,
                "max_artifacts": self.policy.max_artifacts,
                "capture": {
                    "model_inputs": self.policy.capture.model_inputs,
                    "model_outputs": self.policy.capture.model_outputs,
                    "tool_calls": self.policy.capture.tool_calls,
                    "retrieved_documents": self.policy.capture.retrieved_documents,
                },
            },
            "requires": list(self.requires),
        }


@dataclass(frozen=True, slots=True)
class ReplayManifest:
    replay_hash: str
    definition: Mapping[str, Any]
    target_fingerprint: str
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "replay_hash": self.replay_hash,
            "definition": dict(self.definition),
            "target_fingerprint": self.target_fingerprint,
            "created_at": self.created_at.isoformat(),
        }

    @staticmethod
    def from_definition(definition: AttackDefinition) -> "ReplayManifest":
        return ReplayManifest(
            replay_hash=definition.replay_hash(),
            definition=definition.to_dict(),
            target_fingerprint=definition.target.fingerprint(),
            created_at=datetime.now(timezone.utc),
        )


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    plan_id: str
    attack: AttackDefinition
    steps: tuple[PlanStep, ...]
    replay_hash: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "attack": self.attack.to_dict(),
            "steps": [s.to_dict() for s in self.steps],
            "replay_hash": self.replay_hash,
            "created_at": self.created_at.isoformat(),
        }
