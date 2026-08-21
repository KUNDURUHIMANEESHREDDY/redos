from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from engine.adapters.base import TargetAdapter
from engine.execution.context import AttackContext
from engine.execution.timeouts import AttackClock, TurnBudget, await_guarded
from engine.model.attack import AttackObservation, AttackOutcome, Provenance
from engine.model.errors import AttackCancelled, AttackTimeout, EngineError, TargetError
from engine.model.events import EvidenceEvent, EventTypes
from engine.model.execution import ExecutionResult, ExecutionStatus, ObservedExecution
from engine.model.plan import ExecutionPlan
from engine.security.capture import CaptureEnforcer
from engine.security.guard import validate_evidence_chain
from engine.security.secrets import SecretsVault

AuditEmitter = Callable[[dict], None]


@dataclass(slots=True)
class ExecutionEnvironment:
    adapter: TargetAdapter
    vault: SecretsVault = field(default_factory=SecretsVault)
    audit: AuditEmitter | None = None
    rate_limiter: Any | None = None

    def build_context(
        self,
        execution: ObservedExecution,
        clock: AttackClock,
        turns: TurnBudget,
        per_turn_timeout_s: float = 60.0,
        max_retries: int = 2,
        retry_backoff_s: float = 0.2,
        max_artifacts: int = 100,
    ) -> AttackContext:
        secret_values = tuple(v for v in self.vault.store.values() if v)
        return AttackContext(
            execution_id=execution.execution_id,
            adapter=self.adapter,
            enforcer=CaptureEnforcer(execution.policy_capture, secret_values),
            execution=execution,
            clock=clock,
            turns=turns,
            audit=self.audit,
            rate_limiter=self.rate_limiter,
            per_turn_timeout_s=per_turn_timeout_s,
            max_retries=max_retries,
            retry_backoff_s=retry_backoff_s,
            max_artifacts=max_artifacts,
            _secrets=self.vault,
        )


class AttackExecutor:
    def __init__(self, environment: ExecutionEnvironment, registry=None) -> None:
        self.environment = environment
        self.registry = registry

    def _plugin(self, plan: ExecutionPlan):
        plugin = self.registry.get(plan.attack.plugin) if self.registry is not None else None
        if plugin is None:
            from engine.model.errors import PluginError

            raise PluginError(f"no attack plugin registered for key {plan.attack.plugin!r}")
        return plugin

    async def execute(
        self,
        plan: ExecutionPlan,
        *,
        chain: dict | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> ExecutionResult:
        execution_id = uuid4().hex
        started_at = datetime.now(timezone.utc)
        execution = ObservedExecution(
            execution_id=execution_id,
            target_id=plan.attack.target.target_id,
            attack_id=plan.attack.attack_id,
            plan_id=plan.plan_id,
            started_at=started_at,
            status=ExecutionStatus.RUNNING,
        )
        execution.policy_capture = plan.attack.policy.capture
        execution.record(
            EvidenceEvent.now(
                execution_id,
                EventTypes.EXECUTION_STARTED,
                {
                    "attack_id": plan.attack.attack_id,
                    "target_id": plan.attack.target.target_id,
                    "plugin": plan.attack.plugin,
                    "attack_type": plan.attack.attack_type.value,
                    "replay_hash": plan.replay_hash,
                    "provenance": self.environment.adapter.provenance.value,
                },
            )
        )
        for step in plan.steps:
            execution.record(
                EvidenceEvent.now(
                    execution_id,
                    EventTypes.PLAN_STEP,
                    {"index": step.index, "kind": step.kind, "description": step.description},
                )
            )

        loop = asyncio.get_running_loop()
        clock = AttackClock(deadline=loop.time() + plan.attack.policy.overall_timeout_s, cancel_event=cancel_event or asyncio.Event())
        context = self.environment.build_context(
            execution,
            clock,
            TurnBudget(max=plan.attack.policy.max_turns),
            per_turn_timeout_s=plan.attack.policy.per_turn_timeout_s,
            max_retries=plan.attack.policy.max_retries,
            retry_backoff_s=plan.attack.policy.retry_backoff_s,
            max_artifacts=plan.attack.policy.max_artifacts,
        )
        context.audit_event("execution.started", f"target={plan.attack.target.target_id} plugin={plan.attack.plugin}")

        plugin = self._plugin(plan)
        status: ExecutionStatus | None = None
        error: Exception | None = None
        try:
            await await_guarded(
                plugin.run(plan.attack, context, chain=chain or {}),
                clock,
                timeout_s=plan.attack.policy.overall_timeout_s,
            )
        except AttackTimeout as exc:
            status = ExecutionStatus.TIMED_OUT
            error = exc
            execution.record(
                EvidenceEvent.now(
                    execution_id,
                    EventTypes.TIMEOUT,
                    {"reason": str(exc), "deadline_seconds": plan.attack.policy.overall_timeout_s, "provenance": self.environment.adapter.provenance.value},
                )
            )
        except AttackCancelled as exc:
            status = ExecutionStatus.CANCELLED
            error = exc
            execution.record(
                EvidenceEvent.now(
                    execution_id,
                    EventTypes.CANCELLATION,
                    {"reason": str(exc), "provenance": self.environment.adapter.provenance.value},
                )
            )
        except (TargetError, EngineError) as exc:
            status = ExecutionStatus.INDETERMINATE
            error = exc
            execution.record(
                EvidenceEvent.now(
                    execution_id,
                    EventTypes.ERROR,
                    {"code": getattr(exc, "code", "EXECUTION_ERROR"), "message": str(exc), "provenance": self.environment.adapter.provenance.value},
                )
            )
        except asyncio.TimeoutError as exc:
            status = ExecutionStatus.TIMED_OUT
            error = exc
            execution.record(
                EvidenceEvent.now(
                    execution_id,
                    EventTypes.TIMEOUT,
                    {"reason": str(exc), "provenance": self.environment.adapter.provenance.value},
                )
            )
        except Exception as exc:  # noqa: BLE001
            status = ExecutionStatus.INDETERMINATE
            error = exc
            execution.record(
                EvidenceEvent.now(
                    execution_id,
                    EventTypes.ERROR,
                    {"code": "UNEXPECTED", "message": f"{type(exc).__name__}: {exc}", "provenance": self.environment.adapter.provenance.value},
                )
            )

        observation: AttackObservation | None = None
        if status is None:
            try:
                observation = plugin.evaluate(plan.attack, context)
            except Exception:  # noqa: BLE001
                observation = AttackObservation(
                    outcome=AttackOutcome.INDETERMINATE,
                    reason="evaluation failed; no conclusion drawn",
                )
            status = {
                AttackOutcome.SUCCESS: ExecutionStatus.SUCCESS,
                AttackOutcome.FAILURE: ExecutionStatus.FAILURE,
                AttackOutcome.INDETERMINATE: ExecutionStatus.INDETERMINATE,
            }[observation.outcome]
            outcome = observation.outcome
            outcome_reason = observation.reason
            event_id = context.emit(
                EventTypes.ATTACK_RESULT,
                {
                    "outcome": outcome.value,
                    "reason": outcome_reason,
                    "evidence_event_ids": list(observation.evidence_event_ids),
                    "matched_indicators": list(observation.matched_indicators),
                    **dict(observation.data),
                },
            )
            observation = AttackObservation(
                outcome=observation.outcome,
                reason=observation.reason,
                evidence_event_ids=observation.evidence_event_ids + (event_id,),
                matched_indicators=observation.matched_indicators,
                data=observation.data,
            )
        else:
            outcome = AttackOutcome.INDETERMINATE
            outcome_reason = f"execution did not complete: {status.value}" + (f" ({error})" if error else "")

        context.audit_event("execution.finished", f"status={status.value} outcome={outcome.value}")
        execution.finish(
            status,
            {
                "status": status.value,
                "outcome": outcome.value,
                "events_total": len(execution.events) + 1,
                "provenance": self.environment.adapter.provenance.value,
            },
        )

        validation = validate_evidence_chain(execution)
        return ExecutionResult(
            execution=execution,
            plan=plan,
            outcome=outcome,
            outcome_reason=outcome_reason,
            observation=observation,
            validation=validation,
            replay_hash=plan.replay_hash,
        )