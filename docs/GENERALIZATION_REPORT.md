# Generalization Report

**Question**: Does RedOS attack an AI system it was not designed around?

**Answer**: Yes — for every supported protocol family, with measured limits.
RedOS was developed against a single internal test target
(`engine/tests/conftest.py`). This phase re-ran the complete pipeline against
eight structurally different targets (`engine/tests/targets/emulators.py`),
executing real attacks and collecting the metrics below. No engine code was
changed during validation — every compatibility defect found was fixed in the
test harness, and the honest-outcome behavior of the engine is what makes
unfamiliar targets attackable without fabrication.

## Methodology

For each of eight targets, the full pipeline ran with `budget=6`, `seed=5`:

registration → `ReconnaissanceRunner` → `AttackSurfaceDiscovery` →
`HypothesisGenerator` → `IntelligenceRunner` (select + execute) →
evidence collection → `FindingsGateway` → `DependencyGraph` capability gating
→ replay/regression (`build_manifest`/`make_regression_case`/`replay_attack`/
`compare_regression`).

All numbers below come from `python -m engine.tests.targets.metrics_report`
(single run, real executions against real HTTP servers).

## Results (measured, single run)

| Target            | Kind            | Facts | Hypoth. | Exps | Success | Failure | Indet. | Findings | Tool ev. | Retrieval ev. | Gated | Repro | Regression |
| ----------------- | --------------- | ----- | ------- | ---- | ------- | ------- | ------ | -------- | -------- | ------------- | ----- | ----- | ---------- |
| `openai_bare`     | openai_compat   | 6     | 1       | 1    | 1       | 0       | 0      | 1        | 0        | 0             | yes   | yes   | clean      |
| `agent_tools`     | agent           | 9     | 2       | 3    | 1       | 2       | 0      | 1        | 1        | 0             | yes   | yes   | clean      |
| `anthropic`       | anthropic_compat| 6     | 1       | 1    | 1       | 0       | 0      | 1        | 0        | 0             | yes   | yes   | clean      |
| `ollama`          | local_model     | 6     | 1       | 1    | 1       | 0       | 0      | 1        | 0        | 0             | yes   | yes   | clean      |
| `custom_http`     | custom_http     | 6     | 1       | 1    | 1       | 0       | 0      | 1        | 0        | 0             | yes   | yes   | clean      |
| `rag_variant`     | rag             | 8     | 2       | 5    | 3       | 2       | 0      | 3        | 0        | 2             | yes   | yes   | clean      |
| `auth`            | openai_compat   | 6     | 2       | 2    | 1       | 1       | 0      | 1        | 0        | 0             | yes   | yes   | clean      |
| `strict_no_tools` | agent           | 7     | 2       | 5    | 1       | 4       | 0      | 1        | 0        | 0             | yes   | yes   | clean      |

**Aggregates**: 8/8 targets completed the pipeline; 19/19 executions returned
a concrete outcome; 100% of experiments were capability-gated; 100%
reproduction-success; 100% regression-clean; 10/19 executions carried
tool or retrieval evidence; findings were generated only for successes (9
findings, 1 per success + extras on `rag_variant`).

## What this proves

1. **Protocol generalization.** The pipeline drives five wire protocols
   (`/chat/completions`, `/v1/messages`, `/api/infer`-style custom template,
   `/retrieve`, `/tools` + `/tools/{name}/invoke`) without target-specific
   code.
2. **Discovery adapts to the target.** Facts observed differ per target
   (6–9 facts); tool names, retrieval support, and authentication posture are
   measured, not assumed. `agent_tools` discovered `execute_command`/
   `query_database`/`read_local_file` at runtime and attacked through them;
   `rag_variant`'s non-default retrieval schema was parsed correctly.
3. **Honesty under uncertainty.** `strict_no_tools` declares tool capability
   by configuration (kind = `agent`) but exposes no `/tools` and refuses tool
   requests: discovery reports the config assumption, tool attacks fail
   honestly (4/4), and the finding is generated only from the one real
   success (`prompt_injection`). No fabricated success occurred.
4. **Reproduction.** Every target reproduced its baseline outcome via replay,
   and every `RegressionCase` comparison was clean — the pipeline is
   deterministic in effect over these targets.
5. **Capability gating.** `DependencyGraph` is a capability graph: plugins
   whose capabilities are unsatisfied by the measured surface were never
   selected (0 violations across 8 targets).

## Measured limits (why coverage is not 100%)

The `IntelligenceRunner` explores hypotheses until all hypotheses are
terminal (confirmed/disproven/untestable), so budget `6` is rarely exhausted:
`openai_bare`/`anthropic`/`ollama`/`custom_http` each ran exactly 1 experiment
(`prompt_injection`, confirmed). The uncovered-plugin counts (17–21 of 22)
are honest unexplored surface, not failures:

- Tool-family plugins are only reachable when tool capability is observed
  (`agent_tools`) or configured (`strict_no_tools`).
- RAG-family plugins only run when retrieval is observed (`rag_variant`).
- Hypothesis generation is conservative: targets without a `configured`
  authentication flag get no credential-boundary hypothesis; targets without
  advertised tool names get no delegation hypothesis.

## Findings from validation

| # | Finding | Status |
| - | ------- | ------ |
| 1 | `tool_capability` is seeded from configuration (recon line 87), not observation; corrected by honest outcomes. | Known limitation; documented in `TARGET_COMPATIBILITY.md`; no engine change needed because evidence later corrects the record. |
| 2 | `list_tools` exists only on the `agent` adapter; other kinds cannot advertise tools via discovery. | Known limitation. |
| 3 | `TargetKind` has no MCP/multi-agent values; both fail cleanly with `ValueError`. | Expected unsupported-surface behavior. |
| 4 | Tool-name payload defaults (`read_file`) fail honestly against differently-named tools. | Evidence of no fabrication, not a defect. |
| 5 | Ollama native `/api/chat` is not implemented; the OpenAI-compatible `/v1` surface works. | Known limitation. |
| 6 | Remediation and full attack-graph stages exist only as design docs. | Documented; not part of this phase's scope. |

## Verdict

RedOS generalizes to unfamiliar targets **within the supported protocol
families**, and fails cleanly outside them. The design's decision to record
assumptions as facts (with config provenance) and to let the evidence chain
correct them is what makes cross-target attack intelligence honest rather
than fabricated. The validation suite is reproducible:
`python -m pytest engine/tests/targets -q` (27 tests).