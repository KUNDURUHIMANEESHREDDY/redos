# PROVENANCE MODEL

How the engine proves that every `ExecutionResult` carries real, observed evidence and nothing fabricated.

## 1. Provenance values

| Value | Source | Reachable from production paths? |
|---|---|---|
| `live` | Any adapter created by `create_adapter` (`openai_compatible`, `anthropic_compatible`, `local_model`, `custom_http`, `agent`, `rag`) — real HTTP I/O | Yes |
| `mock` | Test doubles only (`FakeAdapter` in `engine/tests/`; `StaticResponseAdapter` removed from the codebase) | **No** — `create_adapter` never returns a mock adapter |

Every evidence event that can carry observed data (`model_request`, `model_response`, `model_interaction`, `tool_call`, `tool_result`, `retrieval`, `artifact`, `attack_result`, `execution_started`, `execution_finished`) records `provenance` = the adapter's provenance at the time of observation.

## 2. Evidence chain

For a given execution:

```
execution_id
 ├─ execution_started   (target_id, attack_id, plugin, replay_hash, provenance)
 ├─ plan_step           (planner steps)
 ├─ attack_payload      (what was sent — redacted per CapturePolicy)
 ├─ model_request       (prompt as sent, provenance)
 ├─ model_response      (reply as received, provenance)
 ├─ tool_call/result    (tool name, arguments, result output, provenance)
 ├─ retrieval           (query, retrieved chunks, provenance)
 ├─ artifact            (id, name, digest, content-if-permitted)
 ├─ attack_result       (outcome + evidence_event_ids)
 └─ execution_finished  (status, outcome, event count)
```

`validate_evidence_chain(execution)` checks:

1. `execution_id`, `target_id`, `attack_id` present.
2. `started_at`/`finished_at` present (finalized).
3. Status is finalized (`success|failure|timed_out|cancelled|indeterminate`).
4. At least one evidence event exists.
5. Every request/response/tool/retrieval event has `provenance == "live"`.
6. Timestamps are monotonic.
7. Artifacts carry digests.

Any violation → `EvidenceChainValidation.valid == false` → `FindingsGateway.submit` raises `MockEvidenceRejected` (code `MOCK_EVIDENCE_REJECTED`). MOCK evidence therefore cannot reach production finding storage either by construction (mocks unreachable from `create_adapter`/`AttackOrchestrator`) or by gate (rejection at the storage boundary).

## 3. Secret isolation

- Secrets are referenced by `api_key_ref` (never stored inline in `TargetConfig`).
- `SecretsVault` resolves refs from environment (`REDOS_<REF>`) or an explicit store.
- `CaptureEnforcer` redacts Authorization/API-key-style headers and known secret values from every recorded event (`redact_text`/`redact_mapping`).
- Raw credentials never appear in `ObservedExecution` or `ExecutionResult` (verified by `engine/tests/provenance/test_secrets.py`).

## 4. SSRF isolation

Targets are validated by `SSRFPolicy` before execution (default policy):

- blocked: non-HTTP(S) schemes, RFC1918 private ranges, link-local (`169.254.0.0/16`, incl. the metadata IP `169.254.169.254`), unresolvable hosts;
- allowed by default: loopback (local models), public hosts;
- `allowed_hosts` is an explicit per-policy allowlist.

Violations raise `SSRFBlocked` (code `SSRF_BLOCKED`) and are emitted as `audit` events (`ssrf.blocked`) — the attack never reaches the adapter.

## 5. Sandbox isolation

- `Sandbox` gates concurrency (`max_concurrency`) per execution.
- `RateLimiter` (token bucket) throttles calls per target (`rate_limit_rps`).
- `AttackPolicy` enforces `max_turns`, `max_retries`, and `max_artifacts` budgets — resource exhaustion cannot be triggered by a payload.

## 6. Hard proof (chain of evidence)

`engine/tests/provenance/test_chain_of_evidence.py` walks a real run and asserts, for every event: same `execution_id`, `provenance == "live"`, monotonic timestamps, and that `validation.valid` and the gateway-produced `FindingRecord` all derive from the same `execution_id` — zero fabricated data by construction and by assertion.