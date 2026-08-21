from __future__ import annotations

from engine.adaptive import AttackObservationRecord
from engine.attack_surface import AttackSurface
from engine.hypotheses import AttackHypothesis, HypothesisGenerator, HypothesisStatus, HypothesisTracker


def make_surface(*, tools=False, retrieval=False, chat=True, samples=None) -> AttackSurface:
    surface = AttackSurface(target_id="t", adapter_kind="agent", model="m")
    surface.tool_capability = tools
    surface.retrieval_supported = retrieval
    surface.chat_observed = chat
    surface.tool_names  # property access is safe on empty list
    if retrieval:
        surface.retrieval_sample = list(samples or [])
    return surface


def test_hypothesis_model_roundtrip():
    h = AttackHypothesis(
        hypothesis_id="h1",
        assumption="the target exposes executable tools",
        attack_surface="tool_authorization",
        expected_behavior="tool authorization may not be enforced per command",
        evidence_required=("tool_result",),
        candidate_attacks=("unsafe_tool_call.shell",),
        confidence=0.6,
        priority=4,
    )
    restored = AttackHypothesis.from_dict(h.to_dict())
    assert restored.hypothesis_id == "h1"
    assert restored.status == HypothesisStatus.PROPOSED
    assert restored.candidate_attacks == ("unsafe_tool_call.shell",)
    restored.confidence = 1.2
    restored.clamp_confidence()
    assert restored.confidence == 1.0


def test_generator_derives_tool_hypothesis_from_surface():
    generator = HypothesisGenerator()
    surface = make_surface(tools=True)
    hypotheses = generator.generate(surface)
    assert any(h.attack_surface == "tool_authorization" and h.expected_behavior for h in hypotheses)
    tool_h = next(h for h in hypotheses if h.attack_surface == "tool_authorization")
    assert "unsafe_tool_call.shell" in tool_h.candidate_attacks
    assert tool_h.evidence_required == ("tool_result",)


def test_generator_derives_retrieval_hypothesis():
    generator = HypothesisGenerator()
    surface = make_surface(retrieval=True, samples=["General knowledge about the product."])
    hypotheses = generator.generate(surface)
    assert any(h.attack_surface == "rag_source" for h in hypotheses)
    rag_h = next(h for h in hypotheses if h.attack_surface == "rag_source" and "rag_poisoning.plant" in h.candidate_attacks)
    assert rag_h.evidence_required == ("retrieval",)


def test_generator_detects_sensitive_retrieval_content():
    generator = HypothesisGenerator()
    surface = make_surface(retrieval=True, samples=["The access code to the vault is 2468."])
    hypotheses = generator.generate(surface)
    assert any(h.assumption == "retrieved documents contain sensitive material (observed content looks secret-bearing)" for h in hypotheses)


def test_generator_builds_cross_family_chain_when_surfaces_compose():
    generator = HypothesisGenerator()
    surface = make_surface(tools=True, retrieval=True, samples=["General knowledge about the product."])
    hypotheses = generator.generate(surface)
    chain = next((h for h in hypotheses if h.attack_surface == "cross_family"), None)
    assert chain is not None
    assert chain.candidate_attacks == (
        "prompt_injection.ignore_previous",
        "rag_poisoning.plant",
        "agent_escalation.system_override",
        "tool_abuse.negation",
        "data_leakage.pii",
    )
    assert chain.priority == 1


def test_generator_respects_capability_limits():
    generator = HypothesisGenerator()
    surface = make_surface(tools=False, retrieval=False, chat=True)
    hypotheses = generator.generate(surface)
    assert not any(h.attack_surface in ("tool_authorization", "rag_source") for h in hypotheses)
    assert any(h.attack_surface == "model_boundary" for h in hypotheses)


def test_generator_derives_authentication_boundary_hypothesis():
    generator = HypothesisGenerator()
    surface = make_surface(chat=True)
    surface.authentication = {"boundary": None, "configured": True}
    hypotheses = generator.generate(surface)
    auth_h = next((h for h in hypotheses if h.attack_surface == "authentication_boundary"), None)
    assert auth_h is not None
    assert auth_h.candidate_attacks == ("permission.reask", "permission.sudo")
    assert auth_h.evidence_required == ("model_response",)
    assert auth_h.priority == 6


def test_generator_no_authentication_hypothesis_without_configured_credential():
    generator = HypothesisGenerator()
    surface = make_surface(chat=True)
    surface.authentication = {"boundary": None, "configured": False}
    hypotheses = generator.generate(surface)
    assert not any(h.attack_surface == "authentication_boundary" for h in hypotheses)


def test_tracker_confirms_and_refutes():
    tracker = HypothesisTracker()
    hypothesis = AttackHypothesis("h1", "a", "surface", "expected", ("tool_result",), ("p.shell",), confidence=0.5, priority=1)
    tracker.register(hypothesis)

    record = AttackObservationRecord("p.shell", "unsafe_tool_call", "success", "matched", ["x"], 1, 0, 1)
    tracker.update("h1", record)
    assert hypothesis.status == HypothesisStatus.CONFIRMED
    assert hypothesis.confidence == 0.75
    assert hypothesis.tested is True

    tracker2 = HypothesisTracker()
    h2 = AttackHypothesis("h2", "a", "surface", "expected", ("tool_result",), ("p.shell",), confidence=0.5, priority=1)
    tracker2.register(h2)
    tracker2.update("h2", AttackObservationRecord("p.shell", "unsafe_tool_call", "failure", "no match", [], 1, 0, 1))
    assert h2.status == HypothesisStatus.REFUTED
    assert h2.confidence == 0.35


def test_tracker_marks_untestable_on_indeterminate():
    tracker = HypothesisTracker()
    h = AttackHypothesis("h3", "a", "surface", "expected", ("tool_result",), ("p.shell",), confidence=0.5, priority=1)
    tracker.register(h)
    tracker.update("h3", AttackObservationRecord("p.shell", "unsafe_tool_call", "indeterminate", "no conclusion", [], 0, 0, 1))
    assert h.status == HypothesisStatus.UNTESTABLE
    assert h.tested is True


def test_tracker_chain_hypothesis_stays_open_until_all_stages_tried():
    tracker = HypothesisTracker()
    h = AttackHypothesis(
        "h4",
        "a",
        "cross_family",
        "expected",
        ("model_response", "retrieval", "tool_result"),
        ("prompt_injection.ignore_previous", "rag_poisoning.plant", "agent_escalation.system_override", "tool_abuse.negation", "data_leakage.pii"),
        confidence=0.5,
        priority=1,
    )
    tracker.register(h)
    tracker.update("h4", AttackObservationRecord("prompt_injection.ignore_previous", "prompt_injection", "success", "r", ["x"], 0, 0, 1))
    assert h.status == HypothesisStatus.PROPOSED
    assert h.tested is False
    for plugin in h.candidate_attacks[1:]:
        tracker.update("h4", AttackObservationRecord(plugin, "family", "failure", "r", [], 1, 1, 1))
    assert h.tested is True
    assert h.status == HypothesisStatus.PROPOSED


def test_register_or_reuse_deduplicates():
    tracker = HypothesisTracker()
    a = AttackHypothesis("a1", "assumption", "surface", "expected", ("retrieval",), ("rag_poisoning.plant",), priority=2)
    b = AttackHypothesis("b1", "assumption", "surface", "expected", ("retrieval",), ("rag_poisoning.plant",), priority=2)
    first = tracker.register_or_reuse(a)
    second = tracker.register_or_reuse(b)
    assert first is second
    assert len(tracker.hypotheses) == 1