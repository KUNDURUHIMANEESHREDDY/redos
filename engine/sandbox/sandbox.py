from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from engine.sandbox.ratelimit import ConcurrencyGate, RateLimiter, TokenBucket


@dataclass
class Sandbox:
    max_concurrency: int = 4
    rate_limit_rps: float | None = None

    def __post_init__(self) -> None:
        self._gate = ConcurrencyGate(self.max_concurrency)
        self._limiter = RateLimiter(self.rate_limit_rps) if self.rate_limit_rps else None

    def limiter_for(self, target_id: str) -> RateLimiter | None:
        return self._limiter

    async def run(self, coro):
        return await self._gate.run(coro)

    def acquire(self) -> "SandboxLease":
        return SandboxLease(self._gate)


@dataclass(slots=True)
class SandboxLease:
    gate: ConcurrencyGate

    async def run(self, coro):
        async with self.gate.semaphore:
            return await coro

    def release(self) -> None:
        self.gate.semaphore.release()


__all__ = ["ConcurrencyGate", "RateLimiter", "Sandbox", "SandboxLease", "TokenBucket"]