from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from engine.adapters.factory import create_adapter
from engine.attack_surface.model import AttackSurface, SurfaceFact
from engine.discovery.probes import derive_permissions, probe_authentication, probe_delegation, probe_document_ingestion, probe_memory
from engine.model.errors import EngineError
from engine.reconnaissance.runner import ReconnaissanceRunner
from engine.security.secrets import SecretsVault
from engine.security.ssrf import SSRFPolicy, validate_url
from engine.targets.config import RAGTargetConfig, TargetConfig

DiscoveryListener = Callable[[dict], None]


@dataclass(slots=True)
class AttackSurfaceDiscovery:
    vault: SecretsVault | None = None
    ssrf_enabled: bool = True
    ssrf_policy: SSRFPolicy | None = None
    adapter_factory: Callable = create_adapter
    listener: DiscoveryListener | None = None
    probe_document_ingestion: bool = True
    probe_memory: bool = True
    probe_delegation: bool = True
    probe_authentication: bool = True

    def __post_init__(self) -> None:
        self.vault = self.vault or SecretsVault()
        self.ssrf_policy = self.ssrf_policy or SSRFPolicy()

    def _emit(self, event: dict) -> None:
        if self.listener is not None:
            self.listener(event)

    def _emit_probe(self, probe: str, detail: str, ok: bool, data: dict[str, Any] | None = None) -> None:
        self._emit({"probe": probe, "detail": detail, "ok": ok, **({"data": data} if data else {})})

    async def discover(self, target: TargetConfig) -> AttackSurface:
        recon = ReconnaissanceRunner(vault=self.vault, ssrf_enabled=self.ssrf_enabled, ssrf_policy=self.ssrf_policy, adapter_factory=self.adapter_factory, listener=self._emit)
        profile = await recon.run(target)
        surface = AttackSurface.from_profile(profile)

        adapter = self.adapter_factory(target, self.vault)
        try:
            if self.probe_document_ingestion:
                fact = await probe_document_ingestion(adapter)
                surface.add_fact(fact)
                surface.document_ingestion = fact.value
                self._emit_probe("document_ingestion", fact.observation, fact.value is True, {"category": fact.category})
            if self.probe_memory:
                fact = await probe_memory(adapter)
                surface.add_fact(fact)
                surface.memory = fact.value
                self._emit_probe("memory", fact.observation, fact.value is True, {"category": fact.category})
            if self.probe_delegation:
                fact = await probe_delegation(adapter, surface)
                surface.add_fact(fact)
                if fact.value is True or fact.value is False:
                    surface.agent_delegation = fact.value
                self._emit_probe("delegation", fact.observation, fact.value is True, {"category": fact.category})
        finally:
            await adapter.aclose()

        if self.probe_authentication:
            fact = await probe_authentication(target, adapter)
            surface.add_fact(fact)
            surface.authentication = dict(fact.value) if isinstance(fact.value, dict) else {}
            self._emit_probe("authentication", fact.observation, fact.value is True, {"category": fact.category})

        if surface.retrieval_supported:
            retrieval_url = getattr(target, "retrieval_url", None)
            if retrieval_url:
                if self.ssrf_enabled:
                    validate_url(retrieval_url, self.ssrf_policy)
                surface.rag_sources = [retrieval_url]
                surface.add_fact(
                    SurfaceFact(
                        category="rag_source",
                        observation="target exposes a retrieval endpoint",
                        value=retrieval_url,
                        evidence_refs=("retrieve",),
                        confidence=0.9,
                    )
                )

        if surface.agent_delegation:
            surface.add_fact(
                SurfaceFact(
                    category="agent_delegation",
                    observation="adapter kind indicates an agent that may delegate work to tools",
                    value=True,
                    evidence_refs=("adapter_kind",),
                    confidence=0.7,
                )
            )

        perm_fact = derive_permissions(surface)
        if perm_fact is not None:
            surface.add_fact(perm_fact)
            surface.permissions = perm_fact.value

        surface.notes.update({"discovery_probes": [f.category for f in surface.facts]})
        return surface

    async def enrich(self, surface: AttackSurface, observations: Mapping[str, Any]) -> AttackSurface:
        tool_families_with_evidence = sorted({key.split(".", 1)[0] for key, record in observations.items() if record.tool_evidence})
        retrieval_evidence_families = sorted({key.split(".", 1)[0] for key, record in observations.items() if record.retrieval_evidence})
        if tool_families_with_evidence:
            surface.facts[:] = [f for f in surface.facts if f.category != "permission"]
            surface.add_fact(
                SurfaceFact(
                    "permission",
                    f"tool execution observed in families: {', '.join(tool_families_with_evidence)}",
                    {family: "tool execution observed" for family in tool_families_with_evidence},
                    evidence_refs=("tool_result",),
                    confidence=0.7,
                )
            )
            surface.permissions = {family: "tool execution observed" for family in tool_families_with_evidence}
        if retrieval_evidence_families:
            surface.add_fact(
                SurfaceFact(
                    "rag_source",
                    f"retrieval evidence observed in families: {', '.join(retrieval_evidence_families)}",
                    retrieval_evidence_families,
                    evidence_refs=("retrieval",),
                    confidence=0.7,
                )
            )
        return surface