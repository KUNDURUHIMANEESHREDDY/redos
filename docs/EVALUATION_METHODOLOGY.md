# RedOS Security Effectiveness Evaluation Methodology

## Overview

This document describes the formal methodology for evaluating RedOS's security effectiveness. The framework measures how well RedOS discovers real vulnerabilities in AI systems compared to static attack scripts.

## Core Philosophy

> **The question our test suite cannot answer: "How effective is RedOS at finding real vulnerabilities?"**

Traditional tests verify software correctness (does the code run without errors?). This framework answers the security question: **Does RedOS actually find real vulnerabilities in real systems?**

## Evaluation Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BENCHMARK TARGETS                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ Prompt   │ │ Jailbreak│ │ Data     │ │ Tool     │ ...  │
│  │ Injection│ │          │ │ Leakage  │ │ Abuse    │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
│  Ground Truth: Known vulnerabilities with indicators       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    EVALUATION ENGINE                        │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │ Static Strategy │    │ Adaptive Intel  │                │
│  │ (Fixed attacks) │    │ (Intelligence)  │                │
│  └─────────────────┘    └─────────────────┘                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      METRICS & REPORTS                      │
│  Precision, Recall, F1, FPR, FNR, Coverage, Efficiency     │
└─────────────────────────────────────────────────────────────┘
```

## Benchmark Targets

Each benchmark target is a real (or simulated) AI system with **known ground-truth vulnerabilities**.

### Target Definition

Each target defines:
- **Target Configuration**: System type, model, configuration
- **Ground Truth**: Known vulnerabilities with indicators
- **Expected Results**: Which attacks should succeed/fail

### Target Categories

| Category | Target ID | Vulnerabilities | Description |
|----------|-----------|-----------------|-------------|
| Prompt Injection | `benchmark-prompt-injection-v1` | `prompt_injection.ignore_previous`, `prompt_injection.indirect` | LLM with extractable system prompt |
| Jailbreak | `benchmark-jailbreak-v1` | `jailbreak.role_play`, `jailbreak.developer_mode` | LLM vulnerable to role-play |
| Data Leakage | `benchmark-data-leakage-v1` | `leakage.probe`, `leakage.pii` | LLM leaking system prompt/PII |
| Tool Abuse | `benchmark-tool-abuse-v1` | `tool.abuse_overload`, `tool.abuse_negation` | Agent with vulnerable tools |
| Malicious Document | `benchmark-malicious-document-v1` | `document.inline`, `document.url` | RAG with malicious docs |
| RAG Poisoning | `benchmark-rag-poisoning-v1` | `rag.plant`, `rag.rank_boost` | RAG vulnerable to poisoning |
| Agent Escalation | `benchmark-agent-escalation-v1` | `escalation.system_override`, `escalation.tool_privilege` | Agent with excessive power |
| Excessive Permissions | `benchmark-permissions-v1` | `permission.reask`, `permission.sudo` | Agent with permission bypass |
| Unsafe Tool Calls | `benchmark-unsafe-tool-calls-v1` | `tool.unsafe_shell`, `tool.unsafe_sql` | Agent with dangerous tools |
| Model Manipulation | `benchmark-model-manipulation-v1` | `manipulation.token_smuggling`, `manipulation.repetition_bias` | LLM with filter bypass |

### Ground Truth Format

Each vulnerability in ground truth defines:
```python
{
    "exists": True,                          # Vulnerability exists
    "attack_vector": "direct_injection",     # How it's exploited
    "indicators": ["system prompt", "..."],  # Expected evidence
    "cvss": 5.3,                             # CVSS score
    "impact": "System prompt disclosure"     # Impact description
}
```

## Evaluation Process

### 1. Target Preparation
- Deploy or configure target system
- Verify ground-truth vulnerabilities exist
- Record baseline state

### 2. RedOS Execution
Run RedOS against target with two strategies:

#### Static Strategy (Baseline)
- Run predefined attack list (all known vulnerabilities)
- No adaptation based on results
- Represents "collection of static attack scripts"

#### Adaptive Intelligence (RedOS)
- Phase 1: Reconnaissance (recon attacks)
- Phase 2: Intelligence-driven adaptation
- Phase 3: Targeted follow-up attacks
- Uses change detection, correlation, intelligence

### 3. Evidence Collection
For each attack execution:
- Record all model interactions
- Capture tool calls and results
- Track evidence events
- Measure execution time, tokens, cost

### 4. Ground Truth Comparison
For each attack:
- **Ground Truth**: Does vulnerability exist? (from target definition)
- **RedOS Result**: Did RedOS find it? (SUCCESS/FAILURE/INDETERMINATE)
- **Evidence Match**: Do observed indicators match expected?

## Metrics Definitions

### Primary Effectiveness Metrics

| Metric | Formula | Meaning |
|--------|---------|---------|
| **Precision** | TP / (TP + FP) | Of reported vulnerabilities, how many are real? |
| **Recall** | TP / (TP + FN) | Of real vulnerabilities, how many found? |
| **F1 Score** | 2×P×R/(P+R) | Harmonic mean of precision/recall |
| **False Positive Rate** | FP / (FP + TN) | Benign cases flagged as vulnerable |
| **False Negative Rate** | FN / (FN + TP) | Real vulnerabilities missed |

Where:
- **TP** (True Positive): Vulnerability exists AND RedOS finds it
- **FP** (False Positive): No vulnerability but RedOS reports one
- **FN** (False Negative): Vulnerability exists but RedOS misses it
- **TN** (True Negative): No vulnerability and RedOS correctly reports none

### Coverage Metrics

| Metric | Description |
|--------|-------------|
| **Attack Coverage** | Vulnerabilities found / Total vulnerabilities in target |
| **Tool Coverage** | Tool abuse vectors tested / Total tool vectors |
| **RAG Coverage** | RAG attack vectors tested / Total RAG vectors |
| **Permission Coverage** | Permission attacks tested / Total permission vectors |

### Intelligence Metrics

| Metric | Description |
|--------|-------------|
| **Hypothesis Precision** | Of generated hypotheses, how many are correct? |
| **Experiment Efficiency** | Findings per attack attempt |
| **Novel Attack Rate** | New attack vectors discovered vs historical |
| **Duplicate Attack Rate** | Repeated attack attempts / Total attempts |

### Quality Metrics

| Metric | Description |
|--------|-------------|
| **Evidence Completeness** | % of findings with expected evidence |
| **Reproduction Success** | % of findings reproducible on re-run |
| **Regression Detection Rate** | Previously fixed vulns detected as regressed |

### Efficiency Metrics

| Metric | Description |
|--------|-------------|
| **Execution Cost** | Total compute/API cost |
| **Token Usage** | Total tokens consumed |
| **Time to Finding** | Time from start to first finding |
| **Experiment Efficiency** | Findings per attack attempt |

## Experimental Design

### Static vs Adaptive Comparison

Each target is tested with two strategies:

| Aspect | Static Strategy | Adaptive Intelligence |
|--------|-----------------|----------------------|
| Attack Selection | Fixed predefined list | Intelligence-guided |
| Adaptation | None | Results-driven |
| Reconnaissance | None | Dedicated phase |
| Follow-up Attacks | None | Intelligence-driven |

### Experimental Controls

1. **Same Target**: Same target instance, same state
2. **Same Attacks**: Same attack pool available to both
2. **Randomized Order**: Attack order randomized per strategy
3. **Multiple Runs**: Each strategy run 3x per target
4. **Blind Evaluation**: Ground truth evaluation automated

### Statistical Rigor

- **Runs per Strategy**: 3 (minimum)
- **Confidence Interval**: 95%
- **Statistical Test**: Paired t-test (same targets)
- **Effect Size**: Cohen's d for F1 improvement

## Execution Protocol

### Prerequisites
1. RedOS deployed and configured
2. Benchmark targets deployed and accessible
3. Ground truth verified for each target
4. Monitoring/telemetry enabled

### Execution Steps

```bash
# 1. Verify targets
python -m benchmarks.framework.runner --verify-targets

# 2. Run all benchmarks
python -m benchmarks.framework.runner --all-targets

# 3. Run comparisons
python -m benchmarks.framework.runner --compare-strategies

# 4. Generate reports
python -m benchmarks.framework.runner --generate-reports
```

### Output Artifacts

```
reports/benchmark-results/
├── run_20240115_143022/
│   ├── results.json          # Raw results
│   ├── comparisons.json      # Strategy comparisons
│   ├── report.json           # Structured report
│   └── REPORT.md             # Human-readable summary
```

## Reporting

### Required Outputs

1. **EVALUATION_METHODOLOGY.md** - This document
2. **SECURITY_EFFECTIVENESS.md** - Results and analysis
3. **reports/benchmark-results/** - Raw data and reports

### Key Questions Answered

The framework must conclusively answer:

> **Does RedOS actually work better than a collection of static attack scripts?**

Answer format:
> "Adaptive intelligence outperforms static scripts in **X%** of targets. 
> Mean F1 improvement: **X.XX**. 
> Recall improvement: **+X.XX**. 
> Novel attack discovery rate: **X%**."
> 
> **Evidence**: [Link to benchmark results]

### Acceptance Criteria

The framework is complete when:

- [ ] All 10 benchmark targets defined with ground truth
- [ ] Evaluation engine runs RedOS against all targets
- [ ] All 17 metrics calculated and reported
- [ ] Static vs adaptive comparison completed
- [ ] Documentation generated (3 markdown files)
- [ ] Benchmark results reproducible
- [ ] Main question answered with evidence

## Integrity Requirements

**CRITICAL**: 
- ❌ No fabricated ground truth
- ❌ No fabricated benchmark results
- ❌ No cherry-picked targets
- ✅ Every metric from actual executed benchmark
- ✅ Ground truth verified before benchmark
- ✅ Blind evaluation (automated ground truth matching)
- ✅ Reproducible execution

---

*This methodology ensures RedOS's security effectiveness is measured rigorously, transparently, and reproducibly.*