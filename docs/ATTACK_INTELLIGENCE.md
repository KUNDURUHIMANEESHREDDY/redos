# Attack Intelligence

The Attack Intelligence layer turns the campaign engine from a system that
executes a predefined strategy into one that *discovers* attack strategies from
the target itself. It observes, forms hypotheses about the attack surface,
selects experiments to test those hypotheses, and learns from the evidence.

It is a pure extension of the Attack & Execution Engine (`ENGINE_CONTRACT.md`,
`EXECUTION_LIFECYCLE.md`, `PROVENANCE_MODEL.md`) and the Campaign Engine
(`CAMPAIGN_ENGINE.md`). It introduces no new attack plugins, adapters, or
execution contracts: every experiment is executed by `AttackOrchestrator`
against the registered plugin registry.

## Loop

```
Observe -> Hypothesis Generation -> Experiment Selection -> Attack
    ^                                                        |
    +------------ Evidence -> Hypothesis Update <------------+
```

`IntelligenceRunner` (`engine/experiment/runner.py`) drives the loop:

1. **Discover** the attack surface (`AttackSurfaceDiscovery`).
2. **Generate hypotheses** from the surface and observations.
3. **Select an experiment** (`ExperimentSelector`) — the next attack that
   maximizes expected information gain subject to cost, impact, previous
   evidence, and coverage gaps.
4. **Execute** it through the orchestrator (real network traffic, live
   provenance).
5. **Learn** — the evidence updates the hypothesis confidence/status and the
   campaign intelligence log.
6. **Repeat** until hypotheses are exhausted or a budget limit is hit.

## Attack surface

`AttackSurface` (`engine/attack_surface/model.py`) is the model of what the
target exposes. Every field is derived from real probes or real execution
evidence; unobservable surfaces are recorded as `None`/`False` with a fact that
states exactly what was and was not observed — never fabricated.

| Surface            | Derived from                                                        |
| ------------------ | ------------------------------------------------------------------- |
| tools              | `list_tools` probe (names, descriptions, parameter schemas)          |
| tool_parameters    | tool schemas from `list_tools`                                      |
| permissions        | tool results from executed attacks (`tool_result` events)           |
| rag_sources        | retrieval endpoint URL + retrieved document fragments (`retrieval`)  |
| document_ingestion | chat probe with a marker document (honest `None` if not reflected)   |
| memory             | chat probe (honest `False`/`None` if not observable)                 |
| external_apis      | not assumed; only recorded when evidence appears                     |
| agent_delegation   | behavioral probe: the target is asked to delegate a task to an      |
|                    | advertised tool; observed only if the reply contains tool calls      |
| model_boundary     | chat replies (refusals, directive handling)                          |
| authentication     | credential configuration (`configured` flag); boundary behavior is   |
|                    | explicitly unverified rather than guessed                            |

`AttackSurface.from_profile` converts a reconnaissance `TargetProfile` into a
surface; `AttackSurfaceDiscovery` (`engine/discovery/runner.py`) runs the
probes and `enrich` folds prior execution evidence back in (e.g. observed
retrieval fragments that were not visible during initial recon).

## Hypotheses

`AttackHypothesis` (`engine/hypotheses/model.py`):

```
AttackHypothesis
├── hypothesis_id
├── assumption              e.g. "the target exposes executable tools"
├── attack_surface          e.g. "tool_authorization"
├── expected_behavior       what the attack should reveal if the assumption holds
├── evidence_required       tokens that must appear in evidence to test it
├── confidence
├── priority
└── candidate_attacks       registered plugin ids that can test it
```

`HypothesisGenerator` (`engine/hypotheses/generator.py`) derives hypotheses
from the surface, e.g.:

- tools exposed -> "tool authorization may not be enforced per command" with
  `unsafe_tool_call.*`, `tool_abuse.*`, `agent_escalation.tool_privilege`.
- retrieval endpoint -> "retrieval documents may be poisoned or already
  sensitive" with `rag_poisoning.*`.
- sensitive-looking retrieval content -> "secret-bearing content can be
  surfaced" (evidence-derived, only appears after the content is observed).
- tools + retrieval + chat -> a cross-family kill chain (see below).
- credential configured on the target -> "authorization may not be enforced
  for re-requested or elevated-framing actions" with `permission.reask`,
  `permission.sudo` — generated only when the authentication probe records
  `configured: True`, never on unauthenticated targets.

`HypothesisTracker` (`engine/hypotheses/tracker.py`) updates confidence on
evidence: success with required evidence confirms, failure with required
evidence refutes, indeterminate marks untestable. Cross-family hypotheses stay
open until every stage has been attempted.

## Experiment selection

`ExperimentSelector` (`engine/experiment/selection.py`) scores candidate
attacks (`engine/experiment/scoring.py`) on:

- expected information gain (higher for untried families and novel variations)
- exploitability (higher when the surface shows permissive tool behavior)
- potential impact (family severity)
- previous evidence (tried families carry prior-experience credit)
- coverage gaps (untried families)

Cross-family chains are executed in stage order
(prompt injection -> rag poisoning -> agent manipulation -> tool abuse -> data
exfiltration, `engine/chaining/cross_family.py`), gated by the dependency
graph so a stage is never attempted against a surface that lacks the required
capability. Tried plugins are re-attempted at most once with an
evidence-derived variation.

## Novel attack mutation

`EvidenceVariationGenerator` (`engine/adaptive/variation.py`) produces
variations that are *not* in the static payload catalog, assembled from
evidence observed on the current target: the plant text for `rag_poisoning.plant`
is re-derived from the most recently observed retrieval fragment; prompt
injection wording is anchored to an observed assistant reply. The variation
records its source (`derived_from`) and base text so the novelty is auditable.

## Campaign intelligence

`CampaignIntelligence` (`engine/intelligence/campaign_intel.py`) keeps the
decision log: what was tested, what succeeded, what failed, what remains
unexplored, and why each experiment was selected. The `IntelligenceReport`
exposes the surface, hypotheses, experiments, findings, and summary.

## Honest limits

- Surfaces that cannot be observed are reported as unknown with a fact stating
  exactly what was probed, not guessed.
- A variation's outcome is whatever the real execution produces; hypotheses
  are confirmed or refuted by actual evidence, never by assumption.
- Findings are submitted through the existing `FindingsGateway` only for
  executions whose outcome was success, and provenance is validated.
- Cost accounting follows the campaign engine convention: turns-based
  estimate, never claimed as real billing.