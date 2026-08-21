# Knowledge Base Architecture

## Overview

The Knowledge Base is RedOS's long-term security memory. It continuously extracts, structures, and stores security knowledge from findings, evidence, remediations, regressions, and campaigns. This enables RedOS to learn from the target's own history and improve over time.

## Knowledge Types

| Type | Description | Source |
|------|-------------|--------|
| ATTACK_PATTERN | Reusable attack sequences with MITRE mapping | Findings, attack graphs |
| VULNERABILITY_PATTERN | Root cause patterns, trigger conditions, exploit signatures | Findings, root causes |
| REMEDIATION_PATTERN | Verified fix patterns with code examples | Remediation actions |
| REGRESSION_PATTERN | Regression triggers, detection rules, prevention | Regression runs |
| TARGET_PROFILE | Target-specific risk profile, common vulns, velocity | Historical findings |
| CAMPAIGN_STRATEGY | Optimized attack strategies per target type | Campaign results |
| EVIDENCE_LINEAGE | Full traceability from evidence → finding → remediation → regression | All modules |
| MODEL_COMPARISON | Version-to-version vulnerability delta | Model version comparisons |
| TARGET_COMPARISON | Cross-target vulnerability sharing | Multi-target analysis |

## Knowledge Entry

Base entry with full traceability:

```python
KnowledgeEntry:
  - entry_id: UUID
  - knowledge_type: ATTACK_PATTERN | VULNERABILITY_PATTERN | REMEDIATION_PATTERN | REGRESSION_PATTERN | TARGET_PROFILE | CAMPAIGN_STRATEGY | EVIDENCE_LINEAGE | MODEL_COMPARISON | TARGET_COMPARISON
  - title: str
  - description: str
  - content: dict
  - status: DRAFT | VERIFIED | DEPRECATED | ARCHIVED
  - confidence: float (0-1)
  - source: str (system | analyst | auto-extracted)
  - tags: list[str]
  - mitre_techniques: list[str]
  - mitre_tactics: list[str]
  - vulnerability_types: list[str]
  - affected_targets: list[UUID]
  - evidence_ids: list[UUID]
  - finding_ids: list[UUID]
  - related_entries: list[UUID]
```

## Pattern Extraction

### Automatic Extraction from Findings

When a finding is created, the system automatically extracts:

1. **Vulnerability Pattern**
   - Root cause pattern
   - Trigger conditions
   - Exploit signatures
   - Detection signatures
   - Remediation patterns
   - False positive patterns

2. **Remediation Pattern** (if remediation exists)
   - Verified fix steps
   - Code examples (before/after)
   - Configuration changes
   - Verification steps
   - Effectiveness estimate

3. **Attack Pattern** (from attack graph)
   - Attack vector
   - Prerequisites
   - Step-by-step execution
   - MITRE ATT&CK mapping
   - Indicators of compromise
   - Countermeasures

### Regression Pattern Extraction

When a regression is detected (fixed → vulnerable):

```python
RegressionPattern:
  - regression_triggers: [system_prompt_change, tool_permission_change, model_change]
  - detection_patterns: [attack_id, signatures]
  - recurrence_rate: float
  - typical_time_to_regression: int (days)
  - prevention_strategies: [monitor_prompts, validate_permissions]
  - detection_rules: [regression_test_rules]
```

## Knowledge Base Operations

### Search & Query

```python
KnowledgeEntrySearch:
  - query: str (full-text)
  - knowledge_types: list[KnowledgeType]
  - statuses: list[str]
  - tags: list[str]
  - mitre_techniques: list[str]
  - vulnerability_types: list[str]
  - target_ids: list[UUID]
  - min_confidence: float
  - date_from/to: datetime
  - limit/offset
```

### Pattern Retrieval by Type

```python
# Get attack patterns for SQL injection
patterns = kb.search_attack_patterns(vulnerability_type="sql_injection", mitre_technique="T1190")

# Get remediation for XSS
patterns = kb.search_remediation_patterns(vulnerability_type="xss")

# Get regression patterns for path traversal
patterns = kb.search_regression_patterns(vulnerability_type="path_traversal")
```

## Target Profiles

Each target accumulates a profile over time:

```python
TargetProfile:
  - target_id: UUID
  - target_type: str
  - attack_surface_summary: {total_findings, by_type, attack_vectors}
  - common_vulnerabilities: list[str] (top 5)
  - common_attack_vectors: list[str] (top 5)
  - risk_profile: CRITICAL | HIGH | MEDIUM | LOW
  - defense_posture: {remediation_velocity, regression_rate}
  - historical_regressions: int
  - remediation_velocity: float (0-1)
  - attack_success_rate: float
```

### Profile Computation

Updated after each scan:
- Vulnerability frequency by type
- Attack vector frequency
- Remediation velocity (fixed/total)
- Regression rate (regressions/total)
- Attack success rate (regressions/total runs)

## Campaign Strategies

Pre-built, learned attack strategies per target type:

```python
CampaignStrategy:
  - name: str
  - target_types: list[str]  # ["llm_model", "rag_system", "tool_chain"]
  - attack_vectors: list[str]
  - phases: [
      {"name": "recon", "vectors": ["prompt_injection", "tool_discovery"]},
      {"name": "exploitation", "vectors": ["sql_injection", "command_injection"]},
      {"name": "persistence", "vectors": ["prompt_injection", "rag_poisoning"]}
    ]
  - success_rate: float
  - avg_findings_per_run: float
  - avg_critical_findings: float
  - recommended_targets: list[str]
  - prerequisites: list[str]
  - estimated_duration: int (minutes)
  - success_criteria: list[str]
```

### Strategy Selection

```python
best_strategy = kb.get_best_strategy_for_target(target_id)
# Returns strategy with highest success_rate for target type
```

## Evidence Lineage

Full traceability from raw evidence to final intelligence:

```python
EvidenceLineage:
  - evidence_id: UUID
  - finding_id: UUID
  - finding_correlations: list[UUID]
  - attack_paths: list[UUID]
  - remediation_actions: list[UUID]
  - regression_tests: list[UUID]
  - attack_graph_nodes: list[UUID]
  - severity_assessments: list[UUID]
  - root_causes: list[UUID]
```

### Lineage Queries

```python
# Given evidence, find everything it touched
lineage = kb.get_evidence_lineage(evidence_id)
# Returns: finding, correlations, attack paths, remediations, regression tests, graph nodes, severity assessments, root causes

# Given finding, find all evidence
evidence = kb.get_evidence_for_finding(finding_id)

# Given attack path, find all evidence
evidence = kb.get_evidence_for_attack_path(path_id)
```

## Model Version Comparisons

Track vulnerability evolution across model versions:

```python
ModelVersionComparison:
  - target_id: UUID
  - version_a: str
  - version_b: str
  - scan_a_id: UUID
  - scan_b_id: UUID
  - new_vulnerabilities: list[UUID]
  - fixed_vulnerabilities: list[UUID]
  - regressions: list[UUID]
  - changed_attack_surface: list[str]
  - risk_delta: float
  - posture_changed: bool
  - change_summary: str
```

### Comparison Report

```
Version 1.0 → 2.0
─────────────────
NEW vulnerabilities: 3 (SQLi in search, XSS in chat, Path traversal in upload)
FIXED vulnerabilities: 2 (Command injection in exec, SSRF in fetch)
REGRESSIONS: 1 (Path traversal in download - was fixed in 1.1)
CHANGED attack surface: +3 vectors, -1 vector
RISK DELTA: +4.2
POSTURE CHANGED: MEDIUM → HIGH
```

## Target Comparisons

Cross-target vulnerability analysis:

```python
TargetComparison:
  - target_a_id: UUID
  - target_b_id: UUID
  - posture_a: str
  - posture_b: str
  - risk_delta: float
  - shared_vulnerabilities: list[UUID]
  - unique_to_a: list[UUID]
  - unique_to_b: list[UUID]
```

## Campaign Strategies

Learned, optimized attack strategies per target type:

| Target Type | Strategy | Vectors | Phases |
|-------------|----------|---------|--------|
| LLM_MODEL | Prompt Injection First | prompt_injection, jailbreak, system_prompt_leak | recon → injection → extraction |
| RAG_SYSTEM | RAG Poisoning First | rag_poisoning, document_injection, retrieval_manipulation | inject → retrieve → exploit |
| TOOL_CHAIN | Tool Chain Exploitation | tool_permission_escalation, tool_chaining, data_exfiltration | discover → chain → exfiltrate |
| API_ENDPOINT | API Abuse | injection, auth_bypass, rate_limit_bypass | enumerate → inject → escalate |

## Intelligence Reports

Structured reports for analysts:

```python
IntelligenceReport:
  - target_id: UUID
  - intelligence_type: REGRESSION_ANALYSIS | ATTACK_COVERAGE | RISK_TREND | EVIDENCE_LINEAGE | MODEL_COMPARISON | TARGET_COMPARISON | REMEDIATION_VERIFICATION
  - priority: CRITICAL | HIGH | MEDIUM | LOW
  - title: str
  - summary: str
  - findings: list[UUID]
  - correlations: list[UUID]
  - regressions: list[UUID]
  - recommendations: list[str]
  - evidence: dict
```

### Report Generation

Automated after:
- Regression detected → REGRESSION_ANALYSIS
- Attack coverage computed → ATTACK_COVERAGE
- Risk trend analyzed → RISK_TREND
- Evidence lineage traced → EVIDENCE_LINEAGE
- Model versions compared → MODEL_COMPARISON
- Targets compared → TARGET_COMPARISON
- Remediation verified → REMEDIATION_VERIFICATION

## API Endpoints

```
# Knowledge Entries
POST   /api/v1/knowledge/entries                    # Create entry
GET    /api/v1/knowledge/entries                    # Search entries
GET    /api/v1/knowledge/entries/{entry_id}         # Get entry
PATCH  /api/v1/knowledge/entries/{entry_id}         # Update entry
POST   /api/v1/knowledge/entries/{entry_id}/verify  # Verify entry

# Patterns
POST   /api/v1/knowledge/patterns/attack            # Create attack pattern
POST   /api/v1/knowledge/patterns/vulnerability     # Create vuln pattern
POST   /api/v1/knowledge/patterns/remediation       # Create remediation pattern
POST   /api/v1/knowledge/patterns/regression        # Create regression pattern
GET    /api/v1/knowledge/patterns/attack            # Search attack patterns
GET    /api/v1/knowledge/patterns/vulnerability     # Search vuln patterns
GET    /api/v1/knowledge/patterns/remediation       # Search remediation patterns
GET    /api/v1/knowledge/patterns/regression        # Search regression patterns

# Target Profiles
POST   /api/v1/knowledge/target-profiles            # Create/update profile
GET    /api/v1/knowledge/target-profiles/{target_id}

# Campaign Strategies
POST   /api/v1/knowledge/campaign-strategies        # Create strategy
GET    /api/v1/knowledge/campaign-strategies        # List strategies
GET    /api/v1/knowledge/campaign-strategies/best-for-target/{target_id}

# Intelligence
POST   /api/v1/knowledge/intelligence/reports       # Create report
GET    /api/v1/knowledge/intelligence/reports       # List reports

# Evidence Lineage
POST   /api/v1/knowledge/evidence-lineage           # Create lineage
GET    /api/v1/knowledge/evidence-lineage/{evidence_id}

# Comparisons
POST   /api/v1/knowledge/compare/versions           # Model version comparison
POST   /api/v1/knowledge/compare/targets            # Target comparison

# Extraction
POST   /api/v1/knowledge/extract/from-finding/{finding_id}
POST   /api/v1/knowledge/extract/regression/{finding_id}
```

## Extraction Pipeline

### From Finding
1. Extract vulnerability pattern
2. Extract remediation pattern (if remediation exists)
3. Extract attack pattern (from attack graph)
4. Create evidence lineage
5. Link to existing patterns (or create new)

### From Regression
1. Detect regression type (REGRESSION/FIXED/CHANGED)
2. Analyze why changed (change events between executions)
3. Identify affected attack vectors
4. Generate recommended reruns
5. Create regression pattern
6. Link to original finding

## Knowledge Evolution

### Verification Workflow
```
DRAFT → (analyst review) → VERIFIED → (time passes) → DEPRECATED → ARCHIVED
```

### Confidence Scoring
- Auto-extracted: 0.7-0.8
- Analyst verified: 0.9-1.0
- Multi-source corroborated: 0.95-1.0

### Pattern Maturation
```
DRAFT (1-2 instances) → VERIFIED (3+ instances, analyst confirmed) → 
CANONICAL (10+ instances, high confidence, cross-target validated)
```

## Integration Points

### From Findings
- Finding created → Extract patterns
- Finding remediated → Extract remediation pattern
- Finding regressed → Extract regression pattern

### From Regression
- Regression detected → Extract regression pattern
- Regression fixed → Update pattern recurrence rate
- Regression pattern updated → Update detection rules

### From Campaigns
- Campaign executed → Update strategy success rate
- New attack vector found → Add to strategy
- New target type → Create new strategy

### From Change Detection
- Assumption broken → Create knowledge entry
- Attack surface changed → Update target profile
- New attack vector → Add to campaign strategies

## Acceptance Criteria

Given Target v1 → Target v2:
1. Findings from v1 create knowledge entries
2. Findings from v2 create/update knowledge entries
3. Model comparison shows: NEW, FIXED, REGRESSIONS
3. Target comparison shows shared/unique vulnerabilities
4. Evidence lineage traces from raw evidence to intelligence
4. Regression patterns predict v2 regressions
5. Campaign strategy recommends optimal attacks for v2
5. Knowledge base query returns relevant patterns for v2 findings