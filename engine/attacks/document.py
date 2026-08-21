from __future__ import annotations

from typing import Any, Mapping

from engine.attacks.base import AttackPlugin
from engine.attacks.registry import attack_plugin
from engine.model.attack import AttackType, Payload
from engine.payloads import malicious_document_inline, malicious_document_url


@attack_plugin
class MaliciousDocumentInlinePlugin(AttackPlugin):
    key = "malicious_document.inline"
    attack_type = AttackType.MALICIOUS_DOCUMENT.value

    def build_payload(self, params: Mapping[str, Any]) -> Payload:
        return malicious_document_inline()


@attack_plugin
class MaliciousDocumentURLPlugin(AttackPlugin):
    key = "malicious_document.url"
    attack_type = AttackType.MALICIOUS_DOCUMENT.value

    def default_params(self) -> dict[str, Any]:
        return {"url": "https://attacker.example/payload.txt"}

    def build_payload(self, params: Mapping[str, Any]) -> Payload:
        return malicious_document_url(url=str(params.get("url", "https://attacker.example/payload.txt")))