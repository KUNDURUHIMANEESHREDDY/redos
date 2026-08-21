# Campaign Engine

The campaign engine runs structured, adaptive red-team operations against a
target. A campaign performs reconnaissance, then repeatedly selects and
executes an attack, observes the outcome, learns from it, and uses that
knowledge to pick the next attack. It stops when budgets are exhausted, all
eligible techniques are attempted, or cancellation is requested.

The engine builds on the existing Attack & Execution Engine (see
`ENGINE_CONTRACT.md`, `EXECUTION_LIFECYCLE.md`, `PROVENANCE_MODEL.md`). It does
not introduce new attack models, adapters, or APIs: every step is executed by
`AttackOrchestrator` against the registered `PLUGIN_REGISTRY`, and findings are
submitted through the existing `FindingsGateway`.

## Lifecycle

```
Campaign -> Reconnaissance -> Attack Selection -> Attack -> Observe
     ^                              |                                |
     +---------------------- Mutate / Learn <-----------------------+
```

Each loop iteration produces one `CampaignStep`:

| Field            | Meaning                                                            |
| ---------------- | ------------------------------------------------------------------ |
| `index`          | 0-based step number                                                |
| `plugin`         | registered plugin id, e.g. `unsafe_tool_call.shell`                |
| `attack_type`    | `AttackType` of the executed definition                            |
| `params`         | parameters of the executed definition                               |
| `execution_id`   | execution id from the orchestrator                                  |
| `outcome`        | success / failure / indeterminate                                  |
| `turns_used`     | number of model interactions in the execution                       |
| `tool_evidence`  | count of `tool_result` events                                       |
| `retrieval_evidence` | count of `retrieval` events                                     |
| `indicator_count`| matched indicators in the observation                               |
| `reasoning`      | why this attack was selected (selection-time rationale)            |
| `depends_on`     | index of the step this step builds on, or `None`                   |

Campaign statuses: `pending`, `running`, `paused`, `completed`, `cancelled`,
`stopped`, `failed`. The terminal stop reasons are recorded in
`Campaign.stopped_reason`:

| Reason                              | Condition                                  |
| ----------------------------------- | ------------------------------------------ |
| attack budget exhausted             | `max_attacks` steps executed               |
| turn budget exhausted               | `max_turns_total` model interactions used  |
| cost budget exhausted               | `estimated_cost() >= max_cost`             |
| duration budget exhausted           | wall time exceeded `max_duration_s`        |
| cancellation requested              | `runner.cancel()` called                   |
| all eligible techniques attempted   | strategy returned no next candidate        |

`paused` is a cooperative state: `CampaignRunner.pause()`/`resume()` gate the
loop between steps via an `asyncio.Event`. While paused the campaign status
remains `running` and no new step begins.

## Budgets

`CampaignBudget` caps a campaign:

- `max_attacks`: maximum number of executed steps.
- `max_turns_total`: maximum sum of `turns_used` across steps.
- `max_duration_s`: wall-clock limit; `0.0` means no step can start.
- `cost_per_turn` / `max_cost`: monetary budget.

Cost accounting is an **estimate**: `CampaignStep.estimated_cost =
turns_used * cost_per_turn`. The engine cannot observe real token billing from
the target, so `estimated_cost()` is documented as an estimate, not a billing
record.

## Reconnaissance

`ReconnaissanceRunner` probes the target before any attack:

| Probe          | Capability recorded                                        |
| -------------- | ---------------------------------------------------------- |
| `list_tools`   | `tools` (ToolSpec list) and `tool_capability`              |
| `chat`         | `chat_observed`, `chat_sample`                             |
| `retrieve`     | `retrieval_supported`, `retrieval_sample` (RAG targets)    |

All URLs used by the runner (base URL, retrieval URL, tool invoke URL) pass
through the SSRF validator (`validate_url`) before use; blocked URLs raise
`SSRFBlocked`. `TargetProfile` is serializable (`to_dict` /
`profile_from_dict`) so recon results can be stored and replayed.

## Strategies

Strategies implement the `SelectionStrategy` protocol
(`select(state, coverage, profile, rng, step_index) -> AttackCandidate | None`).

### Observation-driven (default, `observation_driven`)

Deterministic ladder that reacts to observed outcomes:

1. No observations yet -> `data_leakage.probe` (baseline).
2. Tools available, tool family untried -> `unsafe_tool_call.shell`
   (`depends_on=0`, links to probe).
3. Tool execution observed but no indicator satisfied -> `unsafe_tool_call.sql`
   (`depends_on=last step`), the first adaptive escalation.
4. Retrieval endpoint confirmed -> `rag_poisoning.plant`.
5. Otherwise `prompt_injection.ignore_previous`, then `jailbreak.developer_mode`,
   then `tool_abuse.negation` (if tools), then a fixed expansion list
   (`malicious_document.inline`, `model_manipulation.format_confusion`,
   `permission.sudo`, `agent_escalation.system_override`).
6. Nothing left -> `None` (campaign completes).

Every candidate carries `reasoning` text describing which observation drove the
choice; steps record `depends_on` so the attack chain is auditable.

### Coverage-driven (`coverage_driven`)

Minimizes uncovered families: selects from least-covered families first,
shuffling with the seeded RNG (`random.Random(config.seed)`) for tie-breaks.
Used by the runner for parallel batch execution.

## Dependency Graph

`DependencyGraph` maps plugin families to target capabilities:

- `rag_poisoning` requires `retrieval`.
- `unsafe_tool_call`, `tool_abuse`, `agent_escalation` require `tools`.

`graph.satisfied(plugin, profile)` gates candidate eligibility; capability
families never execute against targets that lack them.

## Replay

`CampaignConfig.replay_hash()` derives a deterministic hash from the campaign
id, target id/kind/base_url/retrieval_url/tool_invoke_url, strategy, seed, and
budget. `build_campaign_manifest` / `verify_campaign_manifest` /
`config_from_manifest` / `replay_campaign` serialize and restore a campaign;
any drift raises `ReplayMismatch` (e.g. a different seed fails verification).

## Evidence

`Campaign.evidence` aggregates:

- `findings`: findings submitted via `FindingsGateway` for successful attacks,
  with provenance validated against the target.
- `links`: attack chain edges (`from`/`to` plugin ids from `depends_on`).
- `profile`: serialized `TargetProfile` from recon.

`CampaignEvidenceAggregator.aggregate` merges evidence for parallel batches.
`EffectivenessScore` (`coverage/scoring.py`) scores each execution: success
with indicators scores highest, tool evidence floors a failure at 0.4,
retrieval evidence at 0.5, indeterminate at 0.0.

## Fuzzing

- `SeedManager` deduplicates seed texts per plugin via SHA-256 digest and
  tracks usage.
- `ContextualMutator` builds context-aware seeds from the target profile
  (tool names, retrieval sample) and the last observation; variants come from
  the existing `MutationPipeline`.
- `AdaptiveFuzzer.run(target)` executes mutant variants through the
  orchestrator, honoring `max_runs` and `max_depth`, and returns `FuzzRun`
  records (variant id, mutation recipe, mutated text, outcome, execution id).

## Concurrency

`CampaignRunner(strategy=..., concurrency=N)` executes batches of up to `N`
steps concurrently. Parallel batches use the coverage-driven strategy (which
does not depend on step-to-step observation order); the observation-driven
strategy is strictly sequential because each selection depends on the previous
outcome.

## Honest limits

- Cost is estimated from turns, never claimed as real billing.
- Recon probes may fail (e.g. `UnsupportedOperation` for adapters without
  `list_tools`/`retrieve`); capabilities are then recorded as absent, and the
  dependency graph prevents attacks that would silently no-op.
- A campaign only records findings for executions whose outcome was
  `success`; failures and indeterminate results are recorded as steps with
  their evidence counts, not as findings.