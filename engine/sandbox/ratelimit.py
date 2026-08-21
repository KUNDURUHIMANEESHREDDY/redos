from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass(slots=True)
class TokenBucket:
    rate: float
    capacity: float
    tokens: float = field(init=False)
    updated_at: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        self.tokens = self.capacity

    def try_take(self, n: float = 1.0) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated_at) * self.rate)
        self.updated_at = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


class RateLimiter:
    def __init__(self, rate_rps: float) -> None:
        self.rate = rate_rps
        self.buckets: dict[str, TokenBucket] = {}

    def _bucket(self, key: str) -> TokenBucket:
        bucket = self.buckets.get(key)
        if bucket is None:
            bucket = TokenBucket(rate=self.rate, capacity=max(self.rate, 1.0))
            self.buckets[key] = bucket
        return bucket

    async def acquire(self, key: str = "default", n: float = 1.0) -> None:
        bucket = self._bucket(key)
        while not bucket.try_take(n):
            await asyncio.sleep(0.05)


class ConcurrencyGate:
    def __init__(self, max_concurrency: int) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.max_concurrency = max_concurrency

    async def run(self, coro):
        async with self.semaphore:
            return await coro