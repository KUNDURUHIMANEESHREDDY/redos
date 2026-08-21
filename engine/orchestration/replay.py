from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from engine.model.attack import AttackPolicy, AttackType, CapturePolicy, TargetKind
from engine.model.errors import ReplayMismatch
from engine.model.execution import ExecutionResult
from engine.model.plan import AttackDefinition, ReplayManifest
from engine.orchestration.orchestrator import AttackOrchestrator


def build_manifest(definition: AttackDefinition) -> ReplayManifest:
    return ReplayManifest.from_definition(definition)


def verify_manifest(definition: AttackDefinition, manifest: ReplayManifest) -> None:
    if definition.replay_hash() != manifest.replay_hash:
        raise ReplayMismatch(
            f"definition replay hash {definition.replay_hash()} does not match manifest {manifest.replay_hash}"
        )
    if definition.target.fingerprint() != manifest.target_fingerprint:
        raise ReplayMismatch("target configuration differs from replay manifest")


def _rebuild_target(data: dict[str, Any]):
    from engine.targets.config import RAGTargetConfig, TargetConfig

    kind = TargetKind(data["kind"])
    if kind == TargetKind.RAG:
        return RAGTargetConfig(
            target_id=data["target_id"],
            kind=kind,
            base_url=data["base_url"],
            model=data.get("model"),
            api_key_ref=data.get("api_key_ref"),
            headers=dict(data.get("headers") or {}),
            extra=dict(data.get("extra") or {}),
            retrieval_url=data.get("retrieval_url"),
            retrieval_extra=dict(data.get("retrieval_extra") or {}),
        )
    return TargetConfig(
        target_id=data["target_id"],
        kind=kind,
        base_url=data["base_url"],
        model=data.get("model"),
        api_key_ref=data.get("api_key_ref"),
        headers=dict(data.get("headers") or {}),
        extra=dict(data.get("extra") or {}),
    )


def definition_from_manifest(manifest: ReplayManifest) -> AttackDefinition:
    definition = manifest.definition
    policy_data = definition.get("policy", {})
    capture_data = policy_data.get("capture", {})
    return AttackDefinition(
        attack_id=str(definition["attack_id"]),
        name=str(definition["name"]),
        attack_type=AttackType(definition["attack_type"]),
        plugin=str(definition["plugin"]),
        params=dict(definition.get("params") or {}),
        target=_rebuild_target(definition["target"]),
        policy=AttackPolicy(
            overall_timeout_s=float(policy_data.get("overall_timeout_s", 120.0)),
            per_turn_timeout_s=float(policy_data.get("per_turn_timeout_s", 60.0)),
            max_turns=int(policy_data.get("max_turns", 10)),
            max_retries=int(policy_data.get("max_retries", 2)),
            retry_backoff_s=float(policy_data.get("retry_backoff_s", 0.2)),
            max_artifacts=int(policy_data.get("max_artifacts", 100)),
            capture=CapturePolicy(
                model_inputs=bool(capture_data.get("model_inputs", True)),
                model_outputs=bool(capture_data.get("model_outputs", True)),
                tool_calls=bool(capture_data.get("tool_calls", True)),
                retrieved_documents=bool(capture_data.get("retrieved_documents", True)),
            ),
        ),
        requires=tuple(definition.get("requires") or ()),
    )


async def replay_attack(
    manifest: ReplayManifest,
    orchestrator: AttackOrchestrator,
    *,
    cancel_event=None,
) -> ExecutionResult:
    definition = definition_from_manifest(manifest)
    if definition.replay_hash() != manifest.replay_hash:
        raise ReplayMismatch(
            f"reconstructed definition hash {definition.replay_hash()} does not match manifest {manifest.replay_hash}"
        )
    return await orchestrator.execute(definition, cancel_event=cancel_event)


@dataclass(frozen=True, slots=True)
class RegressionCase:
    regression_test_id: str
    manifest: ReplayManifest
    baseline: dict[str, Any]
    recorded_at: datetime = field(default_factory=lambda: datetime.now())

    def to_dict(self) -> dict[str, Any]:
        return {
            "regression_test_id": self.regression_test_id,
            "manifest": self.manifest.to_dict(),
            "baseline": dict(self.baseline),
            "recorded_at": self.recorded_at.isoformat(),
        }


def make_regression_case(regression_test_id: str, manifest: ReplayManifest, result: ExecutionResult) -> RegressionCase:
    baseline = {
        "replay_hash": result.replay_hash,
        "outcome": result.outcome.value,
        "status": result.execution.status.value,
        "event_types": sorted({e.type for e in result.execution.events}),
        "model_interaction_count": len(result.execution.model_interactions),
    }
    return RegressionCase(regression_test_id=regression_test_id, manifest=manifest, baseline=baseline)


def compare_regression(case: RegressionCase, result: ExecutionResult) -> list[str]:
    """Compare a replayed result against the recorded baseline.

    The replay hash is compared at the result level (baseline vs replay):
    the plan resolves plugin default params, so an executed result's hash is
    plan-level and legitimately differs from the raw-definition manifest
    hash. Definition-to-manifest consistency is already enforced by
    `replay_attack`/`verify_manifest`.
    """
    differences: list[str] = []
    baseline = case.baseline
    if result.replay_hash != baseline.get("replay_hash"):
        differences.append(f"replay hash mismatch: {baseline.get('replay_hash')} -> {result.replay_hash}")
    if baseline.get("status") != result.execution.status.value:
        differences.append(f"status changed: {baseline.get('status')} -> {result.execution.status.value}")
    if baseline.get("event_types") != sorted({e.type for e in result.execution.events}):
        differences.append("evidence event types differ from baseline")
    return differences