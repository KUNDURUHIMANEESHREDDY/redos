from __future__ import annotations

import pytest

from engine.model.attack import AttackPolicy, AttackType, TargetKind
from engine.model.errors import SSRFBlocked
from engine.model.plan import AttackDefinition
from engine.orchestration.orchestrator import AttackOrchestrator
from engine.security.ssrf import SSRFPolicy, classify_ip, validate_url
from engine.targets.config import TargetConfig

BLOCKED_URLS = [
    "http://169.254.169.254/latest/meta-data",
    "http://10.0.0.5/",
    "http://192.168.1.10/",
    "http://172.16.5.5/",
    "http://100.64.0.1/",
    "file:///etc/passwd",
    "ftp://example.com/file",
]

ALLOWED_URLS = [
    "https://api.openai.com/v1/chat/completions",
    "https://example.com/",
]


def test_ssrf_classification():
    assert classify_ip(__import__("ipaddress").ip_address("169.254.169.254")) == "metadata"
    assert classify_ip(__import__("ipaddress").ip_address("10.1.2.3")) == "private"
    assert classify_ip(__import__("ipaddress").ip_address("127.0.0.1")) == "loopback"
    assert classify_ip(__import__("ipaddress").ip_address("8.8.8.8")) == "public"


@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_ssrf_blocks(url):
    with pytest.raises(SSRFBlocked):
        validate_url(url, SSRFPolicy())


@pytest.mark.parametrize("url", ALLOWED_URLS)
def test_ssrf_allows(url):
    assert validate_url(url, SSRFPolicy()) == url


def test_ssrf_blocks_private_when_loopback_allowed():
    policy = SSRFPolicy(allow_loopback=True, allow_private=False)
    assert validate_url("http://127.0.0.1/", policy) == "http://127.0.0.1/"
    with pytest.raises(SSRFBlocked):
        validate_url("http://10.0.0.5/", policy)


def test_ssrf_allowlist_overrides():
    policy = SSRFPolicy(allowed_hosts=("10.0.0.5",))
    assert validate_url("http://10.0.0.5/", policy) == "http://10.0.0.5/"


def test_ssrf_metadata_hostname_blocked():
    with pytest.raises(SSRFBlocked):
        validate_url("http://metadata.google.internal/", SSRFPolicy())


def test_ssrf_default_blocks_non_http():
    with pytest.raises(SSRFBlocked):
        validate_url("gopher://internal/", SSRFPolicy())


def test_ssrf_policy_allows_loopback_disable():
    policy = SSRFPolicy(allow_loopback=False)
    with pytest.raises(SSRFBlocked):
        validate_url("http://127.0.0.1/", policy)


async def test_orchestrator_blocks_metadata_target(vault):
    audits = []
    orch = AttackOrchestrator(vault=vault, audit=lambda e: audits.append(e))
    target = TargetConfig(
        target_id="evil",
        kind=TargetKind.OPENAI_COMPATIBLE,
        base_url="http://169.254.169.254/latest/meta-data",
        model="m",
    )
    definition = AttackDefinition(
        attack_id="ssrf-a",
        name="ssrf",
        attack_type=AttackType.PROMPT_INJECTION,
        plugin="data_leakage.probe",
        params={},
        target=target,
        policy=AttackPolicy(),
    )
    with pytest.raises(SSRFBlocked):
        await orch.execute(definition)
    assert any(a["action"] == "ssrf.blocked" for a in audits)


async def test_orchestrator_blocks_private_target(vault):
    orch = AttackOrchestrator(vault=vault)
    target = TargetConfig(
        target_id="internal",
        kind=TargetKind.OPENAI_COMPATIBLE,
        base_url="http://10.0.0.1/chat/completions",
        model="m",
    )
    definition = AttackDefinition(
        attack_id="ssrf-b",
        name="ssrf",
        attack_type=AttackType.PROMPT_INJECTION,
        plugin="data_leakage.probe",
        params={},
        target=target,
        policy=AttackPolicy(),
    )
    with pytest.raises(SSRFBlocked):
        await orch.execute(definition)


async def test_orchestrator_allows_loopback_targets(openai_target, vault):
    # Loopback blocked by default - orchestrator must allow it explicitly for local test server
    orch = AttackOrchestrator(vault=vault, ssrf_policy=SSRFPolicy(allow_loopback=True))
    definition = AttackDefinition(
        attack_id="ssrf-c",
        name="ssrf",
        attack_type=AttackType.PROMPT_INJECTION,
        plugin="data_leakage.probe",
        params={},
        target=openai_target,
        policy=AttackPolicy(),
    )
    result = await orch.execute(definition)
    assert result.execution.status.value in ("success", "failure", "indeterminate")


async def test_orchestrator_ssrf_can_be_disabled(vault):
    orch = AttackOrchestrator(vault=vault, ssrf_enabled=False)
    target = TargetConfig(
        target_id="disabled",
        kind=TargetKind.OPENAI_COMPATIBLE,
        base_url="http://192.168.1.1/chat/completions",
        model="m",
    )
    definition = AttackDefinition(
        attack_id="ssrf-d",
        name="ssrf",
        attack_type=AttackType.PROMPT_INJECTION,
        plugin="data_leakage.probe",
        params={},
        target=target,
        policy=AttackPolicy(),
    )
    result = await orch.execute(definition)
    assert result.execution.status.value == "indeterminate"