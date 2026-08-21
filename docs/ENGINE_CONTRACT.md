# ENGINE CONTRACT

Frozen contract between the Attack & Execution Engine (Agent 1) and its consumers (Agent 2 severity/findings, Agent 3 presentation). This document is canonical. Changes require updating the contract tests in `engine/tests/engine_integration/test_agent2_contract.py`.

## Core pipeline

```
AttackDefinition
      ↓
AttackPlanner
      ↓
AttackExecutor
      ↓
TargetAdapter
      ↓
ObservedExecution
      ↓
EvidenceEvents
      ↓
ExecutionResult
```

Every `ExecutionResult` must trace back to a real target through real HTTP execution. There is no code path that produces a `FindingRecord` from anything other than a validated `ExecutionResult`.

## 1. AttackDefinition

| Field | Type | Notes |
|---|---|---|
| `attack_id` | str (uuid4 hex) | unique per definition |
| `name` | str | human label |
| `attack_type` | enum | `prompt_injection`, `jailbreak`, `data_leakage`, `tool_abuse`, `malicious_document`, `rag_poisoning`, `agent_escalation`, `permission`, `unsafe_tool_call`, `model_manipulation`, `custom` |
| `plugin` | str | registered plugin key |
| `params` | dict | resolved by planner (defaults merged) |
| `target` | TargetConfig | target_id, kind, base_url, model, api_key_ref, headers, extra |
| `policy` | AttackPolicy | see below |
| `requires` | tuple[str] | chain prerequisites (attack_ids) |

`AttackDefinition.replay_hash()` = sha256 over canonicalized (attack_type, plugin, params, target.fingerprint(), policy, requires). Same attack + same target configuration ⇒ same hash.

## 2. AttackPolicy

| Field | Default | Meaning |
|---|---|---|
| `overall_timeout_s` | 120.0 | global deadline for the whole execution |
| `per_turn_timeout_s` | 60.0 | per model/tool/retrieval call |
| `max_turns` | 10 | turn budget (resource exhaustion control) |
| `capture` | CapturePolicy | what evidence is permitted |
| `max_concurrency` | 1 | execution isolation limit |
| `rate_limit_rps` | None | target rate limit |
| `max_retries` | 2 | transient failures (unreachable/timeout) |
| `retry_backoff_s` | 0.2 | linear backoff base |
| `max_artifacts` | 100 | artifact budget |

## 3. Execution schema (JSON, contract shape)

```json
{
  "execution_id": "...",
  "target_id": "...",
  "attack_id": "...",
  "started_at": "...",
  "finished_at": "...",
  "status": "success",
  "events": [],
  "tool_calls": [],
  "model_interactions": [],
  "retrieval_events": [],
  "artifacts": []
}
```

- `execution_id` is unique per execution (uuid4 hex).
- `status` is the lifecycle state; see EXECUTION_LIFECYCLE.md.
- `events` is the ordered evidence stream. `tool_calls`, `model_interactions`, `retrieval_events`, `artifacts` are derived views over `events`.

## 4. EvidenceEvent

| Field | Type |
|---|---|
| `event_id` | str (uuid4 hex), unique |
| `execution_id` | str |
| `type` | one of the EventTypes below |
| `timestamp` | ISO-8601 UTC |
| `data` | dict (redacted; always carries `provenance`) |

EventTypes: `execution_started`, `execution_finished`, `plan_step`, `model_request`, `model_response`, `model_interaction`, `tool_call`, `tool_result`, `retrieval`, `attack_payload`, `attack_result`, `artifact`, `timeout`, `cancellation`, `error`, `audit`.

## 5. ExecutionResult

```json
{
  "execution": { ...execution schema... },
  "plan": { "plan_id": "...", "attack": {...}, "steps": [...], "replay_hash": "...", "created_at": "..." },
  "outcome": "success|failure|indeterminate",
  "outcome_reason": "string",
  "observation": { "outcome": "...", "reason": "...", "evidence_event_ids": [...], "matched_indicators": [...] },
  "validation": { "valid": true, "violations": [] },
  "replay_hash": "..."
}
```

- `outcome` is derived solely from observed evidence (indicator matches, tool results, retrieval contents). The engine never fabricates outcomes.
- `validation.valid` is computed by the provenance guard over the evidence chain.

## 6. FindingRecord (Agent 1 → Agent 2 boundary)

```json
{
  "finding_id": "...",
  "execution_id": "...",
  "target_id": "...",
  "attack_id": "...",
  "outcome": "success|failure|indeterminate",
  "outcome_reason": "string",
  "validation_valid": true,
  "stored_at": "ISO-8601 UTC",
  "severity": null
}
```

- Produced only via `FindingsGateway.submit(result)`.
- `FindingsGateway` re-validates the evidence chain and raises `MockEvidenceRejected` if any event provenance is not `live`, the execution is not finalized, or required fields/order are missing. MOCK evidence cannot reach finding storage by construction and by gate.
- `severity` is owned by Agent 2. The engine passes it through unmodified and never computes it.

## 7. ReplayManifest

```json
{
  "replay_hash": "...",
  "definition": { ...AttackDefinition.to_dict()... },
  "target_fingerprint": "...",
  "created_at": "..."
}
```

`definition_from_manifest` reconstructs the `AttackDefinition`; `replay_attack` re-executes it against the same target configuration with a new `execution_id` and an identical `replay_hash`.

## 8. Error model

| Error | Code |
|---|---|
| `ConfigurationError` | CONFIGURATION_ERROR |
| `SSRFBlocked` | SSRF_BLOCKED |
| `MissingSecret` | MISSING_SECRET |
| `PluginError` | PLUGIN_ERROR |
| `TargetUnreachable` | TARGET_UNREACHABLE |
| `TargetAuthError` | TARGET_AUTH_ERROR |
| `TargetProtocolError` | TARGET_PROTOCOL_ERROR |
| `TargetTimeout` | TARGET_TIMEOUT |
| `AttackTimeout` | ATTACK_TIMEOUT |
| `AttackCancelled` | ATTACK_CANCELLED |
| `PayloadError` | PAYLOAD_ERROR |
| `UnsupportedOperation` | UNSUPPORTED_OPERATION |
| `MockEvidenceRejected` | MOCK_EVIDENCE_REJECTED |
| `ReplayMismatch` | REPLAY_MISMATCH |

Errors are recorded as `error` evidence events with their stable `code`; they never fabricate results.

## 9. Hard rules (non-negotiable)

1. No hardcoded vulnerabilities, fabricated model responses, synthetic success, or placeholder data in production paths.
2. Mocks are isolated to tests (`engine/tests/`) and cannot be reached through `create_adapter` or `AttackOrchestrator`.
3. Every security finding traces to real target → real execution → real observation → real evidence.
4. Every important object has an ID: `target_id`, `attack_id`, `plan_id`, `execution_id`, `event_id`, `finding_id`, `regression_test_id`.
5. Security-relevant operations emit `audit` events.
6. Capture of model inputs/outputs/tools/retrieval is governed by `CapturePolicy`; secrets are redacted before evidence is recorded.