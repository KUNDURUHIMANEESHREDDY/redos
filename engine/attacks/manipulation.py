from __future__ import annotations

from typing import Any, Mapping

from engine.attacks.base import AttackPlugin
from engine.attacks.registry import attack_plugin
from engine.model.attack import AttackType, Payload
from engine.payloads import (
    model_manipulation_format_confusion,
    model_manipulation_repetition_bias,
    model_manipulation_token_smuggling,
)


@attack_plugin
class TokenSmugglingPlugin(AttackPlugin):
    key = "model_manipulation.token_smuggling"
    attack_type = AttackType.MODEL_MANIPULATION.value

    def build_payload(self, params: Mapping[str, Any]) -> Payload:
        return model_manipulation_token_smuggling()


@attack_plugin
class RepetitionBiasPlugin(AttackPlugin):
    key = "model_manipulation.repetition_bias"
    attack_type = AttackType.MODEL_MANIPULATION.value

    def build_payload(self, params: Mapping[str, Any]) -> Payload:
        return model_manipulation_repetition_bias()


@attack_plugin
class FormatConfusionPlugin(AttackPlugin):
    key = "model_manipulation.format_confusion"
    attack_type = AttackType.MODEL_MANIPULATION.value

    def build_payload(self, params: Mapping[str, Any]) -> Payload:
        return model_manipulation_format_confusion()