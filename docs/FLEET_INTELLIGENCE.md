# Fleet Intelligence (Agent 2)

This document describes the implemented fleet intelligence layers
(`engine/fleet/`) that sit above the attack engine: posture, change
detection, correlation, regression intelligence, assurance, analytics, risk
graph, digital twin, and knowledge base. All layers consume real records
(findings, executions, surfaces, audit events) produced by the engine and
reuse existing machinery; none of them fabricate evidence.

## Layers

| Layer | Module | Input | Output |
|-------|--------|-------|--------|
| Posture | `engine/fleet/posture.py` | finding records (+ coverage, gate compliance, response/remediation times) | 0-10 posture snapshot |
| Change detection | `engine/fleet/change.py` | two `TargetSnapshot`s | `ChangeReport` diff |
| Correlation | `engine/fleet/correlation.py` | finding records | `CorrelationCluster`s by plugin |
| Regression intelligence | `engine/fleet/regression_intel.py` | replay baselines + runs | diff lists, `RegressionTrend` |
| Assurance | `engine/fleet/assurance.py` | finding records + executions (+ audits) | `AssuranceReport` |
| Analytics | `engine/fleet/analytics.py` | executions + findings + audits | `FleetMetrics` |
| Risk graph | `engine/fleet/risk_graph.py` | finding records | target/plugin/finding risk nodes |
| Digital twin | `engine/fleet/twin.py` | snapshot + findings | simulated posture predictions |
| Knowledge base | `engine/fleet/knowledge.py` | finding records | `KnowledgeLesson`s |

## Posture scoring

`PostureEngine.score` is deterministic:

```
burden = 4*CRITICAL + 2*HIGH + 1*MEDIUM + 0.5*LOW      (severity read from the
                                                        record's severity field)
finding_component = max(0, 10 - 0.5*burden)
factor_component = 2*coverage + 2*gate_compliance
                 + 0.5*clamp(1 - response_hours/24)
                 + 0.5*clamp(1 - remediation_hours/72)  (0.5 when unknown)
score = clamp(0.6*finding_component + factor_component, 0, 10)
```

The engine never assigns severity; unclassified findings carry no weight.
Zero findings with full coverage and gate compliance score 10.0.

## Change analysis (v1 -> v2)

`ChangeDetector.diff` compares two `TargetSnapshot`s of the same target:
finding identity across scans is the plugin that produced the finding (raw
finding ids are per-submission and are not used as issue identity),
facts are compared by category, plugin outcomes by plugin name. The report
lists added/resolved findings, changed/added/removed facts, and changed
plugin outcomes; `observed_change` is True iff any difference was observed.

The acceptance test (`engine/tests/fleet/test_change_analysis.py`) scans a
real emulated agent target twice — tools enabled, then tools disabled — and
verifies, from real executions:

- the `tool` and `tool_parameters` facts disappear from the surface
  (probe records nothing when the tool list is empty, so they are *removed*
  categories, not changed values);
- the `unsafe_tool_call.shell` finding resolves while
  `prompt_injection.ignore_previous` persists;
- the shell plugin outcome flips success -> failure;
- `RegressionIntelligence` flags the replay regression and classifies it as
  `regressed` (clean before, regressed now).

`RegressionTrend` classifies each (target, plugin) key into four buckets:
`introduced` (absent before, regressed now), `regressed` (clean before,
regressed now), `resolved` (regressed before, clean or absent now), and
`persisted` (regressed at both points).

## Regression intelligence

`RegressionIntelligence` is a registry of `RegressionCase` baselines keyed by
(target, plugin). `evaluate` delegates to the existing replay machinery
(`replay_attack` + `compare_regression`) and returns the difference list;
`trend` classifies state changes between assessment points. It does not
re-implement replay.

### Engine fix recorded during validation

`compare_regression` previously compared a replayed result's `replay_hash`
against `case.manifest.replay_hash`. The planner merges plugin default
params into the plan (`AttackPlanner.plan`), so an executed result's hash is
plan-level and legitimately differs from the raw-definition manifest hash —
`compare_regression` could never pass for any plugin with default params
(e.g. `data_leakage.probe`). It now compares the replayed result against the
recorded baseline hash (both plan-level); definition-to-manifest consistency
remains enforced by `replay_attack`/`verify_manifest`.
(`engine/orchestration/replay.py`)

## Assurance

`AssuranceEngine.assure` re-validates each finding's execution with the
engine's own `validate_evidence_chain` (mock evidence is rejected), counts
replayable executions (replay hash + at least one model interaction), and
reports retention compliance. With audit events, it also reports gate
compliance. Missing executions produce explicit violations.

## Correlation, analytics, risk graph, twin, knowledge base

- `CorrelationEngine` groups findings by plugin across targets; a cluster's
  spread (distinct targets) is the signal for downstream layers.
- `FleetAnalytics` computes measured numbers only: scan coverage, scan
  success rate, findings by severity, critical findings unaddressed
  (CRITICAL + HIGH), gate blocking rate.
- `RiskGraph` builds target/plugin/finding nodes with severity-weighted risk
  and neighbor links; it is a finding-derived risk summary, not a full
  attack graph (which the codebase does not implement).
- `TargetTwin` mirrors the latest snapshot and findings and predicts posture
  under hypothetical changes; predictions are explicitly labeled
  `simulated`.
- `KnowledgeBase` ingests only findings that reached the gateway and serves
  lessons (plugin, outcome, reason, source finding) with occurrence counts.
  It never modifies the engine's hypothesis pipeline; consumers opt in.

## Tests

- `engine/tests/fleet/test_fleet_layers.py` — layer behavior and failure
  paths (22 tests).
- `engine/tests/fleet/test_change_analysis.py` — v1 -> v2 acceptance test
  against a real mutable emulator (3 tests).
- Full suite: `python -m pytest engine/tests -q`.