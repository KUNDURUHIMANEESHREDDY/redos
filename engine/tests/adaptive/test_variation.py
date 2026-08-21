from __future__ import annotations

from engine.adaptive import EvidenceVariationGenerator, VariationSpec
from engine.attack_surface import AttackSurface
from engine.payloads import PAYLOAD_CATALOG


def surface(*, samples=None, chat=None, tools=None) -> AttackSurface:
    surface = AttackSurface(target_id="t", adapter_kind="rag", model="m")
    surface.retrieval_supported = bool(samples)
    surface.retrieval_sample = list(samples or [])
    surface.chat_sample = list(chat or [])
    if tools:
        surface.tool_names  # property, safe
    return surface


def test_variation_derives_plant_from_observed_retrieval_content():
    generator = EvidenceVariationGenerator()
    spec = generator.generate("rag_poisoning.plant", surface(samples=["The access code to the vault is 2468."]))
    assert spec is not None
    assert spec.plugin == "rag_poisoning.plant"
    assert spec.param == "plant"
    assert spec.text == "access code to the vault is 2468"
    assert "retrieval_sample" in spec.derived_from
    assert spec.text != spec.base_text
    assert spec.text not in {PAYLOAD_CATALOG["rag.plant"]().indicators[0]}


def test_variation_prefers_most_recent_observed_fragment():
    generator = EvidenceVariationGenerator()
    spec = generator.generate("rag_poisoning.plant", surface(samples=["General knowledge about the product.", "The access code to the vault is 2468."]))
    assert spec is not None
    assert spec.text == "access code to the vault is 2468"


def test_variation_derives_prompt_injection_from_observed_reply():
    generator = EvidenceVariationGenerator()
    spec = generator.generate("prompt_injection.ignore_previous", surface(chat=["I cannot help with that."]))
    assert spec is not None
    assert spec.param == "secret"
    assert "chat_sample" in spec.derived_from
    assert spec.text == "system prompt verbatim"


def test_variation_none_without_evidence():
    generator = EvidenceVariationGenerator()
    assert generator.generate("rag_poisoning.plant", surface()) is None
    assert generator.generate("rag_poisoning.rank_boost", surface()) is None
    assert generator.generate("prompt_injection.ignore_previous", surface()) is None
    assert generator.generate("unsafe_tool_call.shell", surface()) is None


def test_variation_rank_boost_derived_from_observed_fragment():
    generator = EvidenceVariationGenerator()
    spec = generator.generate("rag_poisoning.rank_boost", surface(samples=["The access code to the vault is 2468."]))
    assert spec is not None
    assert spec.param == "plant"
    assert "retrieval_sample" in spec.derived_from
    assert spec.text != spec.base_text
    assert "access code to the vault is 2468" in spec.text
    assert "void" in spec.text and "disclose" in spec.text


def test_variation_unknown_plugin_none():
    generator = EvidenceVariationGenerator()
    assert generator.generate("unknown.plugin", surface(samples=["x"])) is None


def test_variation_serialization_roundtrip():
    spec = VariationSpec("rag_poisoning.plant", "plant", "access code to the vault is 2468", "retrieval_sample[-1]", "novel", "The access code to the vault is 2468.")
    restored = VariationSpec.from_dict(spec.to_dict())
    assert restored == spec


def test_variation_is_reproducible():
    generator = EvidenceVariationGenerator()
    first = generator.generate("rag_poisoning.plant", surface(samples=["The access code to the vault is 2468."]))
    second = generator.generate("rag_poisoning.plant", surface(samples=["The access code to the vault is 2468."]))
    assert first == second