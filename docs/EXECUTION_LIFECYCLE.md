# EXECUTION LIFECYCLE

Canonical state machine for every attack execution.

## States

```
PENDING ──► RUNNING ──► SUCCESS
                │
                ├────────► FAILURE
                ├────────► TIMED_OUT
                ├────────► CANCELLED
                └────────► INDETERMINATE
```

| State | Meaning |
|---|---|
| `pending` | Execution created, not yet started. `ObservedExecution.status` default. |
| `running` | Plugin run in progress; evidence events being recorded. |
| `success` | Execution completed to evaluation; attack outcome `success` (indicators matched in real model output / tool results / retrieved docs). |
| `failure` | Execution completed to evaluation; attack outcome `failure` (executed for real, no indicator matched). |
| `timed_out` | Global deadline, per-turn timeout, or turn budget exhausted. A `timeout` evidence event is recorded with the reason. Outcome is `indeterminate`. |
| `cancelled` | Cancellation requested via the orchestrator cancel event. A `cancellation` evidence event is recorded. Outcome is `indeterminate`. |
| `indeterminate` | Execution did not complete or evaluation could not conclude (e.g., target unreachable, protocol error, evaluation failure). `error` evidence events carry the stable error code. |

## Transition rules

1. `PENDING → RUNNING` happens inside `AttackExecutor.execute` before any target interaction.
2. `RUNNING → SUCCESS | FAILURE` only after `plugin.evaluate` runs against collected evidence. The mapping is:
   - outcome `success` → `success`
   - outcome `failure` → `failure`
   - outcome `indeterminate` → `indeterminate`
3. Timeout paths always produce a `timeout` event; cancellation paths always produce a `cancellation` event; both record `outcome=indeterminate`.
4. The status in the execution schema JSON is the lowercase enum value above.

## Verification (tests)

`engine/tests/engine_integration/test_lifecycle.py` proves each state:

- `pending`: default state of a freshly constructed `ObservedExecution`.
- `running`: observed mid-flight by a probe plugin that records `ctx.execution.status` during execution.
- `success` / `failure`: real runs against the local HTTP target with and without indicator matches.
- `timed_out`: global deadline and per-turn timeout against a slow endpoint; turn-budget exhaustion via an unbounded loop plugin.
- `cancelled`: cancel event fired mid-run against a slow endpoint.
- `indeterminate`: unreachable target and unexpected plugin error.

## Guarantees

- Every final state is recorded in `execution_finished` evidence with the number of events collected.
- The provenance guard only accepts finalized states (`is_final()`); `pending`/`running` executions are rejected by `FindingsGateway`.
- Distinguishability: `success` vs `failure` is about the attack outcome; `timed_out`/`cancelled`/`indeterminate` are about execution integrity. Error details live in `error`/`timeout`/`cancellation` events with stable codes.