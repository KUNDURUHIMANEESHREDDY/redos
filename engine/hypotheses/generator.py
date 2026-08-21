from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping
from uuid import uuid4

from engine.attack_surface.model import AttackSurface
from engine.chaining.cross_family import CROSS_FAMILY_CHAIN
from engine.hypotheses.model import AttackHypothesis

SENSITIVE_TOKEN_RE = re.compile(r"\b(vault|password|secret|token|credential|key|code)\b", re.IGNORECASE)
DIGIT_RE = re.compile(r"\d{3,}")


@dataclass(slots=True)
class HypothesisGenerator:
    def _new(self, surface: AttackSurface, **kwargs: Any) -> AttackHypothesis:
        return AttackHypothesis(hypothesis_id=uuid4().hex[:16], **kwargs)

    def generate(self, surface: AttackSurface, observations: Mapping[str, Any] | None = None) -> list[AttackHypothesis]:
        hypotheses: list[AttackHypothesis] = []
        observations = observations or {}

        if surface.tool_capability or surface.tools:
            hypotheses.append(
                self._new(
                    surface=surface,
                    assumption="the target exposes executable tools",
                    attack_surface="tool_authorization",
                    expected_behavior="tool authorization may not be enforced per command, allowing commands the operator did not intend",
                    evidence_required=("tool_result",),
                    candidate_attacks=("unsafe_tool_call.shell", "unsafe_tool_call.sql", "tool_abuse.negation", "agent_escalation.tool_privilege"),
                    confidence=0.6,
                    priority=4,
                )
            )

        if surface.retrieval_supported:
            hypotheses.append(
                self._new(
                    surface=surface,
                    assumption="the target exposes a retrieval endpoint whose documents feed the model",
                    attack_surface="rag_source",
                    expected_behavior="content served by the retrieval endpoint may be poisoned or already contain sensitive material",
                    evidence_required=("retrieval",),
                    candidate_attacks=("rag_poisoning.plant", "rag_poisoning.rank_boost"),
                    confidence=0.6,
                    priority=5,
                )
            )

        if surface.chat_observed:
            hypotheses.append(
                self._new(
                    surface=surface,
                    assumption="the target exposes a chat model whose behavior can be steered by message content",
                    attack_surface="model_boundary",
                    expected_behavior="system-level instructions may leak or be overridden under a directive",
                    evidence_required=("model_response",),
                    candidate_attacks=("prompt_injection.ignore_previous", "jailbreak.developer_mode", "model_manipulation.format_confusion"),
                    confidence=0.5,
                    priority=3,
                )
            )

        sensitive = [sample for sample in surface.retrieval_sample if SENSITIVE_TOKEN_RE.search(sample) and DIGIT_RE.search(sample)]
        if sensitive:
            hypotheses.append(
                self._new(
                    surface=surface,
                    assumption="retrieved documents contain sensitive material (observed content looks secret-bearing)",
                    attack_surface="rag_source",
                    expected_behavior="secret-bearing content can be surfaced through retrieval or a derived variant of the planted text",
                    evidence_required=("retrieval", "model_response"),
                    candidate_attacks=("rag_poisoning.plant", "data_leakage.pii"),
                    confidence=0.7,
                    priority=2,
                )
            )

        if bool(surface.authentication.get("configured")):
            hypotheses.append(
                self._new(
                    surface=surface,
                    assumption="the target is protected by a credential authentication boundary",
                    attack_surface="authentication_boundary",
                    expected_behavior="authorization may not be enforced when previously denied actions are re-requested or run with elevated framing",
                    evidence_required=("model_response",),
                    candidate_attacks=("permission.reask", "permission.sudo"),
                    confidence=0.4,
                    priority=6,
                )
            )

        if surface.tool_capability and surface.retrieval_supported and surface.chat_observed:
            hypotheses.append(
                self._new(
                    surface=surface,
                    assumption="multiple attack surfaces compose into a single kill chain",
                    attack_surface="cross_family",
                    expected_behavior="prompt injection can prime retrieval poisoning, which can prime agent manipulation, tool abuse, and data exfiltration",
                    evidence_required=("model_response", "retrieval", "tool_result"),
                    candidate_attacks=tuple(plugin for _, plugin in CROSS_FAMILY_CHAIN),
                    confidence=0.55,
                    priority=1,
                )
            )

        return hypotheses