# Security Analysis Platform - Architecture Overview

## Core Philosophy

**Agent 1 says: "Here is what happened."**
**Agent 2 determines: "What does this mean?"**

The Security Analysis Platform owns the brain of the security testing system. It converts real execution evidence into trustworthy, machine-verifiable findings through a deterministic analysis pipeline.

## System Boundaries

```
ExecutionResult → Evidence → Analysis Pipeline → Finding → Attack Graph → Remediation → Regression Test
```

Every conclusion must be traceable back to actual evidence. No fabricated findings are accepted.

## Component Architecture

### 1. Evidence Ingestion (`security/evidence/`)
- **EvidenceIngestionBoundary**: Strict validation boundary - rejects invalid/mock evidence
- **EvidenceNormalizer**: Converts raw evidence to normalized form per evidence type
- **Evidence Types**: network_traffic, log_entry, file_system, memory_dump, process_trace, api_call, user_action, configuration, vulnerability_scan, custom
- **Status Pipeline**: RAW → VALIDATED → NORMALIZED → CORRELATED → ARCHIVED

### 2. Analysis Pipeline (`security/analysis/`)
**7-Stage Deterministic Pipeline:**
1. **Evidence Validation** - Verify evidence integrity and completeness
2. **Behavior Extraction** - Match against known attack patterns
3. **Security Rules** - Apply vulnerability detection rules
4. **Impact Analysis** - Assess confidentiality, integrity, availability impact
5. **Exploitability Analysis** - Evaluate attack vector, complexity, privileges, user interaction
6. **Risk Calculation** - CVSS v3.1 base, temporal, environmental scores
7. **Finding Generation** - Create findings with evidence references

### 3. Finding Model (`security/models/finding.py`)
**Finding Lifecycle:** NEW → CONFIRMED → REMEDIATED → REGRESSION_TESTED → FIXED
**Failure States:** FALSE_POSITIVE, WONT_FIX, DUPLICATE

**Every Finding Contains:**
- finding_id, execution_id, target_id, attack_id
- vulnerability_type, severity, confidence, impact, exploitability
- evidence_ids (references to actual evidence)
- attack_path, root_cause, remediation, reproduction, regression_tests

### 4. Severity Calculation (`security/severity/`)
**CVSS v3.1 Implementation:**
- Base metrics: AV, AC, PR, UI, S, C, I, A
- Temporal metrics: E, RL, RC
- Environmental metrics: CR, IR, AR, modified base metrics
- **Severity is NEVER fabricated from attack names alone**

### 5. Attack Graph (`security/attack_graph/`)
- Built from actual findings and evidence
- Nodes: vulnerabilities + attack steps with MITRE ATT&CK techniques
- Edges: chains_to, leads_to, exploits, related_to
- Critical path detection using NetworkX

### 6. Remediation (`security/remediation/`)
- Template-based remediation tied to vulnerability type
- Root cause analysis tied to evidence
- Verification steps for each remediation action

### 7. Regression System (`security/regression/`)
- Finding → Reproduction Case → Regression Test → Re-execute → Compare
- Cross-execution comparison for regression detection
- Independent test execution

### 8. Policies & Baselines
- Security policy definitions (OWASP Top 10, PCI DSS, Zero Critical)
- Baseline creation with rolling windows
- Regression detection with configurable thresholds

## Data Flow Integrity

```
Real ExecutionResult
       ↓
Real Evidence (validated at ingestion boundary)
       ↓
Analysis Pipeline (each stage produces auditable output)
       ↓
Severity Assessment (CVSS with evidence references)
       ↓
Finding (with evidence_ids, attack_path, root_cause, remediation)
       ↓
Attack Graph (built from actual events)
       ↓
Remediation (tied to root cause & evidence)
       ↓
Regression Test (independent execution & comparison)
```

## Key Guarantees

1. **Evidence Provenance**: Every finding references actual evidence IDs
2. **Reproducibility**: Every finding includes reproduction steps
3. **Explainable Severity**: CVSS calculation with full rationale
4. **Deduplication**: Automatic duplicate detection per execution
5. **Correlation**: Shared evidence detection across findings
6. **Traceability**: Complete chain from execution → evidence → finding → remediation → regression test
7. **No Fabrication**: Mock/invalid evidence rejected at ingestion boundary