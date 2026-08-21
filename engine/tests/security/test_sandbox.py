from __future__ import annotations

import asyncio
import time

from engine.model.attack import AttackPolicy, AttackType
from engine.model.plan import AttackDefinition
from engine.orchestration.orchestrator import AttackOrchestrator
from engine.sandbox.ratelimit import RateLimiter, TokenBucket
from engine.sandbox.sandbox import Sandbox
from engine.tests.probe_plugins import ConcurrencyProbePlugin


def definition(target, plugin, **params) -> AttackDefinition:
    return AttackDefinition(
        attack_id=f"sandbox-{plugin}",
        name=plugin,
        attack_type=AttackType.CUSTOM,
        plugin=plugin,
        params=params,
        target=target,
        policy=AttackPolicy(),
    )


def test_token_bucket_math():
    bucket = TokenBucket(rate=10.0, capacity=1.0)
    assert bucket.try_take()
    assert not bucket.try_take()


def test_token_bucket_refills():
    bucket = TokenBucket(rate=100.0, capacity=1.0)
    bucket.try_take()
    time.sleep(0.05)
    assert bucket.try_take()


async def test_rate_limiter_throttles():
    limiter = RateLimiter(rate_rps=20.0)
    started = time.monotonic()
    for _ in range(30):
        await limiter.acquire("t")
    elapsed = time.monotonic() - started
    assert elapsed >= 0.3


async def test_sandbox_limits_concurrency(openai_target, vault, register_probe_plugins):
    ConcurrencyProbePlugin.max_seen = 0
    sandbox = Sandbox(max_concurrency=1)
    orch = AttackOrchestrator(vault=vault, sandbox=sandbox)
    results = await asyncio.gather(*[orch.execute(definition(openai_target, "probe.concurrency")) for _ in range(3)])
    assert ConcurrencyProbePlugin.max_seen == 1
    assert len(results) == 3


async def test_sandbox_allows_higher_concurrency(openai_target, vault, register_probe_plugins):
    ConcurrencyProbePlugin.max_seen = 0
    sandbox = Sandbox(max_concurrency=3)
    orch = AttackOrchestrator(vault=vault, sandbox=sandbox)
    await asyncio.gather(*[orch.execute(definition(openai_target, "probe.concurrency")) for _ in range(3)])
    assert ConcurrencyProbePlugin.max_seen >= 2


async def test_sandbox_isolates_instances(openai_target, vault, register_probe_plugins):
    ConcurrencyProbePlugin.max_seen = 0
    sandbox_a = Sandbox(max_concurrency=1)
    sandbox_b = Sandbox(max_concurrency=1)
    orch_a = AttackOrchestrator(vault=vault, sandbox=sandbox_a)
    orch_b = AttackOrchestrator(vault=vault, sandbox=sandbox_b)
    await asyncio.gather(
        orch_a.execute(definition(openai_target, "probe.concurrency")),
        orch_b.execute(definition(openai_target, "probe.concurrency")),
    )
    assert ConcurrencyProbePlugin.max_seen >= 2