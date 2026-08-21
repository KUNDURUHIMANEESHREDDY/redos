# Severity Model Specification

## Overview

Severity is calculated using **CVSS v3.1** exclusively. Severity is NEVER fabricated from attack names alone - it must be derived from actual evidence and measurable metrics.

## CVSS v3.1 Implementation

### Base Metrics (Required)

| Metric | Values | Description |
|--------|--------|-------------|
| Attack Vector (AV) | NETWORK, ADJACENT, LOCAL, PHYSICAL | How the vulnerability is exploited |
| Attack Complexity (AC) | LOW, HIGH | Conditions beyond attacker's control |
| Privileges Required (PR) | NONE, LOW, HIGH | Access level needed |
| User Interaction (UI) | NONE, REQUIRED | User participation needed |
| Scope (S) | UNCHANGED, CHANGED | Impact beyond vulnerable component |
| Confidentiality (C) | NONE, LOW, HIGH | Data disclosure impact |
| Integrity (I) | NONE, LOW, HIGH | Data modification impact |
| Availability (A) | NONE, LOW, HIGH | Service disruption impact |

### Temporal Metrics (Optional)

| Metric | Values | Description |
|--------|--------|-------------|
| Exploit Code Maturity (E) | UNPROVEN, PROOF_OF_CONCEPT, FUNCTIONAL, HIGH, NOT_DEFINED | Exploit availability |
| Remediation Level (RL) | OFFICIAL_FIX, TEMPORARY_FIX, WORKAROUND, UNAVAILABLE, NOT_DEFINED | Fix availability |
| Report Confidence (RC) | UNKNOWN, REASONABLE, CONFIRMED, NOT_DEFINED | Confidence in existence |

### Environmental Metrics (Optional)

| Metric | Values | Description |
|--------|--------|-------------|
| Confidentiality Requirement (CR) | NONE, LOW, HIGH, NOT_DEFINED | Asset value for confidentiality |
| Integrity Requirement (IR) | NONE, LOW, HIGH, NOT_DEFINED | Asset value for integrity |
| Availability Requirement (AR) | NONE, LOW, HIGH, NOT_DEFINED | Asset value for availability |
| Modified Base Metrics | Same as base | Organization-specific modifications |

## Score Calculation

### Base Score Formula

```
ISS = 1 - ((1-C) × (1-I) × (1-A))

If Scope = UNCHANGED:
  Impact = 6.42 × ISS
Else:
  Impact = 7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)¹⁵

Exploitability = 8.22 × AV × AC × PR × UI

If Impact ≤ 0: Base = 0
Else if Scope = UNCHANGED: Base = min(10, Impact + Exploitability)
Else: Base = min(10, 1.08 × (Impact + Exploitability))

Round to 1 decimal
```

### Temporal Score
```
Temporal = Base × E × RL × RC
```

### Environmental Score
```
Modified Base calculated with modified metrics
Environmental = Modified Base × (CR + IR + AR) / 3
(× 1.08 if Modified Scope = CHANGED)
```

### Final Score Priority
```
Environmental > Temporal > Base
```

## Severity Levels

| Score Range | Severity |
|-------------|----------|
| 9.0 - 10.0 | CRITICAL |
| 7.0 - 8.9 | HIGH |
| 4.0 - 6.9 | MEDIUM |
| 0.1 - 3.9 | LOW |
| 0.0 | INFO |

## Finding-to-CVSS Mapping

The `SeverityCalculationService.map_finding_to_cvss()` maps finding attributes:

| Finding Attribute | CVSS Metric | Mapping |
|-------------------|-------------|---------|
| exploitability HIGH/CRITICAL | AC | LOW |
| exploitability MEDIUM/LOW/NONE | AC | HIGH |
| (default) | AV | NETWORK |
| (default) | PR | NONE |
| (default) | UI | NONE |
| (default) | S | UNCHANGED |
| impact → CRITICAL/HIGH | C,I,A | HIGH |
| impact MEDIUM/LOW | C,I,A | LOW |
| impact NONE | C,I,A | NONE |
| exploitability → ECRITICAL/HIGH | E | HIGH |
| exploitability MEDIUM | E | FUNCTIONAL |
| exploitability LOW | E | PROOF_OF_CONCEPT |
| exploitability NONE | E | UNPROVEN |
| confidence HIGH/VERY_HIGH | RC | CONFIRMED |
| confidence MEDIUM | RC | REASONABLE |
| confidence LOW | RC | UNKNOWN |

## Evidence-Based Assessment

**Every severity assessment MUST include:**
- `evidence_ids`: List of evidence UUIDs supporting the assessment
- `rationale`: Human-readable explanation
- `cvss_vector`: Full CVSS vector string
- `base_score`, `temporal_score`, `environmental_score`

## Severity Rules

Pre-defined rules for vulnerability types:
- SQL Injection: min 7.0, max 10.0 (HIGH/CRITICAL)
- XSS: min 4.0, max 6.9 (MEDIUM)
- Command Injection: min 9.0, max 10.0 (CRITICAL)
- Custom rules can be created via API

## API Operations

### Assess Severity
```
POST /api/v1/severity/assess
{"finding_id": "uuid", "evidence_ids": ["uuid1"]}
```

### Get Assessment
```
GET /api/v1/severity/assessment/{assessment_id}
```

### List Assessments for Finding
```
GET /api/v1/severity/assessments/{finding_id}
```

### Create Severity Rule
```
POST /api/v1/severity/rules
{
  "name": "Custom Rule",
  "vulnerability_type": "custom_type",
  "cvss_vector": {...},
  "min_score": 5.0,
  "max_score": 8.0
}
```

### Evaluate Rules for Finding
```
POST /api/v1/severity/evaluate/{finding_id}
```

## Validation Rules

1. Base metrics are REQUIRED for all assessments
2. Evidence IDs must reference valid evidence
3. CVSS vector string must be valid per spec
4. Score ranges: 0.0 - 10.0
5. Temporal/Environmental scores optional but preferred
5. Rationale must explain the assessment

## Anti-Fabrication Guarantees

1. **No string-based severity**: Attack name strings never determine severity
2. **Evidence required**: Every assessment references evidence IDs
3. **Rationale required**: Human-readable justification
4. **CVSS standard**: Calculation follows FIRST.org specification
5. **Audit trail**: All assessments stored with timestamps