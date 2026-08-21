# Experiment Engine

The experiment engine is the operational core of the Attack Intelligence layer.
It turns hypotheses into concrete, executed attacks and back into updated
hypotheses. This document is the contract for `engine/experiment/` and the
`IntelligenceRunner`.

## Roles

| Component                        | Responsibility                                                    |
| -------------------------------- | ----------------------------------------------------------------- |
| `IntelligenceRunner`             | The observe/hypothesize/select/execute/learn loop (budgeted)      |
| `AttackSurfaceDiscovery`         | Probe the target and build an `AttackSurface` (`engine/discovery/`) |
| `HypothesisGenerator`            | Derive candidate hypotheses from the surface and observations      |
| `ExperimentSelector`             | Choose the next experiment to run (scored selection)              |
| `HypothesisTracker`              | Update hypothesis confidence/status from execution evidence       |
| `CampaignIntelligence`           | Log decisions and outcomes; summarize tested/succeeded/failed     |

## Experiment lifecycle

An `Experiment` (`engine/experiment/model.py`) is the next attack to run:

```
Experiment
├── experiment_id
├── hypothesis_id        the hypothesis this experiment tests
├── plugin               registered plugin id
├── attack_type          AttackType
├── params               concrete parameters (defaults + variation override)
├── expected_information_gain
├── exploitability
├── potential_impact
├── cost_estimate        turns (1 per standard execution)
├── reasoning            why this experiment was selected
├── variation            optional novel VariationSpec (evidence-derived)
└── depends_on           index of the prior experiment it chains from
```

Execution is always delegated to `AttackOrchestrator.execute(definition)`. The
definition's `attack_id` is `<plugin>:exp-<index>`, so the provenance chain is
reconstructible:

```
hypothesis_id -> experiment_id -> attack_id -> execution_id -> evidence events
```

## Selection scoring

`score_candidate` (`engine/experiment/scoring.py`) computes:

```
total = 0.30 * information_gain
      + 0.25 * exploitability
      + 0.20 * potential_impact
      + 0.15 * prior_evidence
      + 0.10 * coverage_gap
```

- information_gain: 0.5 for an untried family, 0.3 for a new plugin in a tried
  family, 0.6 for a novel variation, 0.1 for a re-run.
- exploitability: tool/agent families score higher when the surface shows
  permissive tool behavior; retrieval families score higher when retrieval
  samples were observed.
- potential impact: fixed family severity map (`data_leakage` highest).

Cross-family hypotheses take precedence: their stages run in fixed order
(prompt injection, rag poisoning, agent manipulation, tool abuse, data
exfiltration), each gated by the dependency graph, because composing surfaces
is treated as the highest-value experiment when the surface supports it.

## Novel variations

When a plugin has been tried exactly once, the selector asks
`EvidenceVariationGenerator` for a variation. Variations are built from
evidence observed on the current target — the most recent retrieval fragment,
an observed assistant reply — and are guaranteed to differ from the payload
catalog defaults (`variation.text != variation.base_text`). Supported today:

- `rag_poisoning.plant` — plant text re-derived from the most recent observed
  retrieval fragment.
- `rag_poisoning.rank_boost` — rank-boost directive re-anchored to an observed
  document fragment while preserving the catalog indicators.
- `prompt_injection.ignore_previous` — injection anchored to an observed
  assistant reply.
- `unsafe_tool_call.shell` — command targeted at the first tool advertised on
  the target.

A plugin is re-executed with a variation at most once; after that it is not
offered again, so the loop cannot spin on the same attack.

## Budgets

`IntelligenceRunner` reuses `CampaignBudget` (no new model): `max_attacks`
caps the number of experiments, `max_duration_s` the wall-clock time, and
`max_turns_total`/`max_cost` the turn/cost estimates. Stop reasons follow the
campaign convention: budget exhausted / duration exhausted / cancellation /
all hypotheses explored.

## Evidence and findings

- Every experiment records `execution_id`, execution status, outcome,
  matched indicators, tool/retrieval evidence counts, turns, event count, and
  the adapter provenance (`live`).
- Successful experiments are submitted through the existing `FindingsGateway`;
  the gateway validates provenance and rejects mock evidence.
- The report's `unexplored` section lists plugins, families, and untested
  hypotheses that remain, computed from the coverage tracker — so the operator
  sees exactly what was not attempted.

## Test coverage

- `engine/tests/experiment/` — selector ordering, capability gating,
  variation-once semantics, scoring monotonicity, determinism.
- `engine/tests/hypothesis/` — hypothesis model, generation rules, tracker
  confirm/refute/untestable, chain-hypothesis lifecycle.
- `engine/tests/discovery/` — surface derivation from real targets, SSRF
  enforcement, honest unknowns, serialization, enrichment.
- `engine/tests/adaptive/` — variation generation and the end-to-end
  hard-requirement test: a previously unexecuted variation derived from
  observed target evidence is executed against the live target and its complete
  provenance chain is preserved.

All tests run against the real httpx-backed `ChatHandler`; there are no mock
executions, fabricated findings, or test-only code paths.