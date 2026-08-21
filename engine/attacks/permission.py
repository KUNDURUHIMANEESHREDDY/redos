from __future__ import annotations

from typing import Any, Mapping

from engine.attacks.base import AttackPlugin
from engine.attacks.registry import attack_plugin
from engine.model.attack import AttackType, Payload
from engine.payloads import permission_reask, permission_sudo_probe


@attack_plugin
class PermissionReaskPlugin(AttackPlugin):
    key = "permission.reask"
    attack_type = AttackType.PERMISSION.value

    def build_payload(self, params: Mapping[str, Any]) -> Payload:
        return permission_reask()


@attack_plugin
class PermissionSudoProbePlugin(AttackPlugin):
    key = "permission.sudo"
    attack_type = AttackType.PERMISSION.value

    def build_payload(self, params: Mapping[str, Any]) -> Payload:
        return permission_sudo_probe()