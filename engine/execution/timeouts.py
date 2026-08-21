from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4

from engine.model.attack import CapturePolicy, DocumentChunk, Message, ModelReply, ToolCall, ToolResult


@dataclass(slots=True)
class TurnBudget:
    used: int = 0
    max: int = 10

    def acquire(self) -> bool:
        if self.used >= self.max:
            return False
        self.used += 1
        return True


@dataclass(slots=True)
class AttackClock:
    deadline: float
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)

    def remaining(self) -> float:
        return self.deadline - asyncio.get_running_loop().time()

    def expired(self) -> bool:
        return asyncio.get_running_loop().time() >= self.deadline

    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def raise_if_stopped(self) -> None:
        from engine.model.errors import AttackCancelled, AttackTimeout

        if self.cancelled():
            raise AttackCancelled("attack was cancelled")
        if self.expired():
            raise AttackTimeout("attack deadline exceeded")


async def await_guarded(awaitable, clock: AttackClock, timeout_s: float | None = None):
    from engine.model.errors import AttackCancelled, AttackTimeout

    task = asyncio.ensure_future(awaitable)
    cancel_waiter = asyncio.ensure_future(clock.cancel_event.wait())
    loop = asyncio.get_running_loop()
    timeout_handle = None
    if timeout_s is not None:
        timeout_handle = loop.call_later(timeout_s, cancel_waiter.cancel)
    try:
        done, pending = await asyncio.wait({task, cancel_waiter}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        if timeout_handle is not None:
            timeout_handle.cancel()
    if task in done:
        for p in pending:
            p.cancel()
        return await task
    for p in pending:
        p.cancel()
    task.cancel()
    try:
        await task
    except BaseException:
        pass
    if clock.cancelled():
        raise AttackCancelled("attack was cancelled")
    raise AttackTimeout("operation exceeded its timeout")


@dataclass(slots=True)
class ArtifactRecord:
    artifact_id: str
    name: str
    kind: str
    content: str
    created_at: datetime

    def digest(self) -> str:
        return hashlib.sha256(f"{self.artifact_id}:{self.name}:{self.content}".encode("utf-8")).hexdigest()