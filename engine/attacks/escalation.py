from __future__ import annotations

from typing import Any, Mapping

from engine.attacks.base import AttackPlugin
from engine.attacks.registry import attack_plugin
from engine.model.attack import AttackType, Payload
from engine.payloads import agent_escalation_system_override, agent_escalation_tool_privilege


@attack_plugin
class AgentEscalationSystemOverridePlugin(AttackPlugin):
    key = "agent_escalation.system_override"
    attack_type = AttackType.AGENT_ESCALATION.value

    def build_payload(self, params: Mapping[str, Any]) -> Payload:
        return agent_escalation_system_override()


@attack_plugin
class AgentEscalationToolPrivilegePlugin(AttackPlugin):
    key = "agent_escalation.tool_privilege"
    attack_type = AttackType.AGENT_ESCALATION.value

    def build_payload(self, params: Mapping[str, Any]) -> Payload:
        return agent_escalation_tool_privilege()