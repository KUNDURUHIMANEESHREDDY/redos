from __future__ import annotations

import pytest

from engine.model.attack import AttackPolicy, AttackType
from engine.model.plan import AttackDefinition
from engine.orchestration.orchestrator import AttackOrchestrator
from engine.security.secrets import SecretsVault, redact_mapping, redact_text


def definition(target, plugin, **params) -> AttackDefinition:
    return AttackDefinition(
        attack_id="secret-a",
        name="secret isolation",
        attack_type=AttackType.PROMPT_INJECTION,
        plugin=plugin,
        params=params,
        target=target,
        policy=AttackPolicy(),
    )


async def test_api_key_never_leaks_into_evidence(auth_target, vault):
    vault.register("test_api_key", "super-secret-key-12345")
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(auth_target, "data_leakage.probe"))
    blob = result.to_json()
    assert "super-secret-key-12345" not in blob
    assert "Bearer super" not in blob


async def test_secret_values_redacted_from_evidence(vault):
    vault.register("probe_key", "redactme-9876")
    orch = AttackOrchestrator(vault=vault)
    from engine.model.attack import TargetKind
    from engine.targets.config import TargetConfig

    target = TargetConfig(
        target_id="t-secret",
        kind=TargetKind.OPENAI_COMPATIBLE,
        base_url="http://127.0.0.1:1",
        model="m",
        api_key_ref="probe_key",
    )
    result = await orch.execute(definition(target, "data_leakage.probe"))
    assert "redactme-9876" not in result.to_json()


def test_redact_text_removes_bearer_and_header_values():
    text = "Authorization: Bearer sk-live-abc123, X-Api-Key: k-456, api_key=secret42"
    redacted = redact_text(text)
    assert "sk-live-abc123" not in redacted
    assert "k-456" not in redacted
    assert "secret42" not in redacted


def test_redact_mapping_keys_and_values():
    out = redact_mapping({"Authorization": "Bearer tok", "api_key": "v", "messages": ["tok"]}, ("tok",))
    assert out["Authorization"] == "***REDACTED***"
    assert out["api_key"] == "***REDACTED***"
    assert out["messages"] == ["***REDACTED***"]


def test_vault_never_stores_in_definition(auth_target):
    assert auth_target.api_key_ref == "test_api_key"
    assert "super-secret" not in auth_target.to_dict().get("headers", {})


def test_vault_requires_missing_secret(vault):
    from engine.model.errors import MissingSecret

    with pytest.raises(MissingSecret):
        vault.get("does_not_exist", required=True)


def test_vault_env_resolution(monkeypatch):
    monkeypatch.setenv("REDOS_CI_KEY", "env-value-42")
    vault = SecretsVault()
    assert vault.get("CI_KEY") == "env-value-42"