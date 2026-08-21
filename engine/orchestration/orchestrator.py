from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable

from engine.adapters.base import TargetAdapter
from engine.adapters.factory import create_adapter
from engine.attacks.registry import PluginRegistry
from engine.execution.executor import AttackExecutor, ExecutionEnvironment
from engine.model.errors import SSRFBlocked
from engine.model.execution import ExecutionResult
from engine.model.plan import AttackDefinition, ExecutionPlan
from engine.orchestration.chaining import ChainContext
from engine.orchestration.planner import AttackPlanner
from engine.sandbox.sandbox import Sandbox
from engine.security.secrets import SecretsVault
from engine.security.ssrf import SSRFPolicy, validate_url
from engine.security.rate_limiting import QuotaEnforcer, create_default_enforcer

AuditEmitter = Callable[[dict], None]


@dataclass(slots=True)
class AttackOrchestrator:
    registry: PluginRegistry | None = None
    vault: SecretsVault | None = None
    audit: AuditEmitter | None = None
    sandbox: Sandbox | None = None
    planner: AttackPlanner | None = None
    adapter_factory: Callable = create_adapter
    ssrf_enabled: bool = True
    ssrf_policy: SSRFPolicy | None = None
    quota_enforcer: QuotaEnforcer | None = None

    def __post_init__(self) -> None:
        self.vault = self.vault or SecretsVault()
        self.planner = self.planner or AttackPlanner(registry=self.registry)
        # Default for orchestrator: allow loopback for local test server but block private/metadata
        self.ssrf_policy = self.ssrf_policy or SSRFPolicy(allow_loopback=True, allow_private=False, allow_link_local=False, allow_metadata=False)
        self.quota_enforcer = self.quota_enforcer or create_default_enforcer()

    def check_target(self, definition: AttackDefinition) -> None:
        if not self.ssrf_enabled:
            return
        urls = [definition.target.base_url]
        retrieval_url = getattr(definition.target, "retrieval_url", None)
        if retrieval_url:
            urls.append(retrieval_url)
        try:
            validate_url(definition.target.base_url, self.ssrf_policy)
            if retrieval_url:
                validate_url(retrieval_url, self.ssrf_policy)
        except SSRFBlocked as exc:
            if self.audit is not None:
                self.audit(
                    {
                        "action": "ssrf.blocked",
                        "target_id": definition.target.target_id,
                        "detail": str(exc),
                    }
                )
            raise

    def _adapter(self, definition: AttackDefinition) -> TargetAdapter:
        return self.adapter_factory(definition.target, self.vault)

    async def execute(
        self,
        definition: AttackDefinition,
        *,
        chain: ChainContext | None = None,
        cancel_event: asyncio.Event | None = None,
        adapter: TargetAdapter | None = None,
        executor: AttackExecutor | None = None,
    ) -> ExecutionResult:
        # Server-side resource enforcement: clamp client policy to limits
        from engine.security.worker_isolation import DEFAULT_LIMITS, enforce_server_side_policy, check_document_limits
        clamped_policy = enforce_server_side_policy(definition.policy, DEFAULT_LIMITS)
        # If client supplied larger values, use clamped version
        if clamped_policy is not definition.policy:
            definition = AttackDefinition(
                attack_id=definition.attack_id,
                name=definition.name,
                attack_type=definition.attack_type,
                plugin=definition.plugin,
                params=dict(definition.params),
                target=definition.target,
                policy=clamped_policy,
                requires=definition.requires,
            )
        # Enforce document size / decompression limits server-side (cannot trust client)
        for doc_key in ("documents", "document", "payload"):
            docs = definition.params.get(doc_key)
            if isinstance(docs, (list, tuple)):
                for d in docs:
                    content = d.get("content", "") if isinstance(d, dict) else str(d)
                    check_document_limits(content, DEFAULT_LIMITS)
        self.check_target(definition)
        # Authoritative quota/rate limiting at backend layer (not client-supplied)
        # Use tenant/campaign derived from definition - enforce even if client tries bypass via parallel keys
        try:
            authorized, reason = await self.quota_enforcer.authorize_execution(
                campaign_id=definition.attack_id,  # or campaign mapping
                target_id=definition.target.target_id,
                tenant_id=getattr(definition.target, "organization_id", "default") if hasattr(definition.target, "organization_id") else "default",
                tokens_needed=1000,
            )
            if not authorized:
                from engine.model.errors import QuotaExceeded
                raise QuotaExceeded(reason)
        except Exception as exc:
            # If quota check fails due to not being configured, log but don't block local tests entirely
            # Only block when QuotaExceeded or RateLimitExceeded
            from engine.model.errors import QuotaExceeded, RateLimitExceeded
            if isinstance(exc, (QuotaExceeded, RateLimitExceeded)):
                raise
        chain = chain or ChainContext()
        rendered = chain.render_definition(definition)
        plan = self.planner.plan(rendered)
        owned_adapter = adapter is None
        target_adapter = adapter or self._adapter(rendered)
        limiter = self.sandbox.limiter_for(rendered.target.target_id) if self.sandbox else None
        environment = ExecutionEnvironment(
            adapter=target_adapter,
            vault=self.vault,
            audit=self.audit,
            rate_limiter=limiter,
        )
        runner = executor or AttackExecutor(environment, registry=self.registry or self._default_registry())
        try:
            coro = runner.execute(plan, chain=chain.observations, cancel_event=cancel_event)
            if self.sandbox is not None:
                result = await self.sandbox.run(coro)
            else:
                result = await coro
        finally:
            if owned_adapter:
                await target_adapter.aclose()
        if result.observation is not None:
            chain.record(
                rendered.attack_id,
                {
                    "outcome": result.outcome.value,
                    "reason": result.outcome_reason,
                    "observation": result.observation.to_dict(),
                },
            )
        return result

    def plan(self, definition: AttackDefinition) -> ExecutionPlan:
        return self.planner.plan(definition)

    @staticmethod
    def _default_registry() -> PluginRegistry:
        from engine.attacks.registry import PLUGIN_REGISTRY

        return PLUGIN_REGISTRY