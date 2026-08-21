from __future__ import annotations

import asyncio
import time

from engine.attacks.base import AttackPlugin
from engine.execution.context import AttackContext
from engine.model.attack import AttackType, Message, Payload
from engine.model.plan import AttackDefinition


class LifecycleProbePlugin(AttackPlugin):
    key = "probe.lifecycle"
    attack_type = AttackType.CUSTOM.value

    def build_payload(self, params):
        return Payload(messages=(Message(role="user", content="probe"),))

    async def run(self, definition, ctx, chain=None):
        ctx.emit("probe_status", {"status": ctx.execution.status.value})
        await ctx.chat(list(self.build_payload(definition.params).messages))


class TurnBudgetBurnerPlugin(AttackPlugin):
    key = "probe.turn_budget"
    attack_type = AttackType.CUSTOM.value

    def build_payload(self, params):
        return Payload(messages=(Message(role="user", content="burn turns"),))

    async def run(self, definition, ctx, chain=None):
        for i in range(200):
            await ctx.chat([Message(role="user", content=f"turn {i}")])


class ErrorPlugin(AttackPlugin):
    key = "probe.error"
    attack_type = AttackType.CUSTOM.value

    def build_payload(self, params):
        return Payload(messages=(Message(role="user", content="boom"),))

    async def run(self, definition, ctx, chain=None):
        raise RuntimeError("probe boom")


class ArtifactFloodPlugin(AttackPlugin):
    key = "probe.artifact_flood"
    attack_type = AttackType.CUSTOM.value

    def build_payload(self, params):
        return Payload(messages=(Message(role="user", content="flood"),))

    async def run(self, definition, ctx, chain=None):
        for i in range(200):
            ctx.add_artifact(f"artifact-{i}", "text", "x" * 64)


class ConcurrencyProbePlugin(AttackPlugin):
    key = "probe.concurrency"
    attack_type = AttackType.CUSTOM.value
    active = 0
    max_seen = 0

    def build_payload(self, params):
        return Payload(messages=(Message(role="user", content="concurrency"),))

    async def run(self, definition, ctx, chain=None):
        ConcurrencyProbePlugin.active += 1
        ConcurrencyProbePlugin.max_seen = max(ConcurrencyProbePlugin.max_seen, ConcurrencyProbePlugin.active)
        ctx.emit("probe_concurrency", {"active": ConcurrencyProbePlugin.active, "max_seen": ConcurrencyProbePlugin.max_seen})
        await asyncio.sleep(0.2)
        ConcurrencyProbePlugin.active -= 1


class StallingPlugin(AttackPlugin):
    key = "probe.stall"
    attack_type = AttackType.CUSTOM.value

    def build_payload(self, params):
        return Payload(messages=(Message(role="user", content="stall"),))

    async def run(self, definition, ctx, chain=None):
        started = time.monotonic()
        while time.monotonic() - started < 10:
            ctx.clock.raise_if_stopped()
            await asyncio.sleep(0.01)


ALL_PROBES = [
    LifecycleProbePlugin(),
    TurnBudgetBurnerPlugin(),
    ErrorPlugin(),
    ArtifactFloodPlugin(),
    ConcurrencyProbePlugin(),
    StallingPlugin(),
]


def register_probes() -> None:
    from engine.attacks.registry import PLUGIN_REGISTRY

    for probe in ALL_PROBES:
        PLUGIN_REGISTRY._plugins[probe.key] = probe


def unregister_probes() -> None:
    from engine.attacks.registry import PLUGIN_REGISTRY

    for probe in ALL_PROBES:
        PLUGIN_REGISTRY._plugins.pop(probe.key, None)