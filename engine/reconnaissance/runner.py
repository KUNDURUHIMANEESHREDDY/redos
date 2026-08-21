from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from engine.adapters.base import TargetAdapter
from engine.adapters.factory import create_adapter
from engine.model.attack import Message, TargetKind
from engine.model.errors import EngineError, UnsupportedOperation
from engine.reconnaissance.profile import TargetProfile
from engine.security.secrets import SecretsVault
from engine.security.ssrf import SSRFPolicy, validate_url
from engine.targets.config import RAGTargetConfig, TargetConfig

ReconListener = Callable[[dict], None]

BENIGN_PROBE = "Hello, are you there?"
BENIGN_QUERY = "meeting notes"


@dataclass(slots=True)
class ReconnaissanceRunner:
    vault: SecretsVault | None = None
    ssrf_enabled: bool = True
    ssrf_policy: SSRFPolicy | None = None
    adapter_factory: Callable = create_adapter
    listener: ReconListener | None = None

    def __post_init__(self) -> None:
        self.vault = self.vault or SecretsVault()
        self.ssrf_policy = self.ssrf_policy or SSRFPolicy()

    def _check(self, url: str) -> None:
        if self.ssrf_enabled:
            validate_url(url, self.ssrf_policy)

    def _emit(self, probe: str, detail: str, ok: bool, data: dict[str, Any] | None = None) -> None:
        if self.listener is not None:
            self.listener(
                {
                    "probe": probe,
                    "detail": detail,
                    "ok": ok,
                    **({"data": data} if data else {}),
                }
            )

    async def _probe_tools(self, adapter: TargetAdapter, target: TargetConfig, profile: TargetProfile) -> None:
        try:
            tools = await adapter.list_tools()
            profile.tools = list(tools)
            profile.tool_capability = bool(tools)
            self._emit("list_tools", f"discovered {len(tools)} tool(s)", True, {"tools": [t.name for t in tools]})
        except UnsupportedOperation:
            self._emit("list_tools", "adapter does not expose a tool listing", False)
        except EngineError as exc:
            self._emit("list_tools", f"tool listing failed: {exc}", False)

    async def _probe_chat(self, adapter: TargetAdapter, target: TargetConfig, profile: TargetProfile) -> None:
        try:
            reply = await adapter.chat([Message(role="user", content=BENIGN_PROBE)], timeout=10.0)
            profile.chat_observed = True
            sample = reply.content.strip()
            profile.chat_sample.append(sample[:200])
            self._emit("chat", "target responded to benign probe", True, {"sample": sample[:200]})
        except EngineError as exc:
            self._emit("chat", f"chat probe failed: {exc}", False)

    async def _probe_retrieval(self, adapter: TargetAdapter, target: TargetConfig, profile: TargetProfile) -> None:
        if not profile.retrieval_supported:
            return
        try:
            chunks = await adapter.retrieve(BENIGN_QUERY, top_k=3, timeout=10.0)
            for chunk in chunks:
                profile.retrieval_sample.append(chunk.text[:200])
            self._emit("retrieve", f"retrieved {len(chunks)} document(s)", True, {"queries": [BENIGN_QUERY]})
        except EngineError as exc:
            profile.retrieval_supported = False
            self._emit("retrieve", f"retrieval probe failed: {exc}", False)

    async def run(self, target: TargetConfig) -> TargetProfile:
        self._check(target.base_url)
        retrieval_url = getattr(target, "retrieval_url", None)
        if retrieval_url:
            self._check(retrieval_url)
        profile = TargetProfile(target_id=target.target_id, adapter_kind=target.kind.value, model=target.model)
        profile.tool_capability = bool(target.extra.get("tool_invoke_url")) or target.kind in (TargetKind.AGENT,)
        profile.retrieval_supported = isinstance(target, RAGTargetConfig) and bool(target.retrieval_url)
        adapter = self.adapter_factory(target, self.vault)
        try:
            await self._probe_tools(adapter, target, profile)
            await self._probe_chat(adapter, target, profile)
            await self._probe_retrieval(adapter, target, profile)
        finally:
            await adapter.aclose()
        return profile