# Continuous Assurance Engine

## Overview

The Continuous Assurance Engine provides ongoing verification that security posture is maintained over time. It moves beyond point-in-time assessments to continuous validation.

## Assurance Metrics

| Metric | Description | Threshold | Assurance Level |
|--------|-------------|-----------|-----------------|
| Finding Verification Rate | % findings verified as fixed | ≥0.8 | HIGH |
| Regression Pass Rate | % regression tests passing | ≥0.9 | HIGH |
| Evidence Completeness | % evidence normalized | ≥0.7 | MEDIUM |
| Attack Coverage | % attack vectors tested | ≥0.6 | MEDIUM |
| Remediation Completeness | % findings remediated | ≥0.8 | HIGH |

## Assurance Levels

| Level | Criteria |
|-------|----------|
| HIGH | All metrics ≥ threshold |
| MEDIUM | Most metrics ≥ threshold, no critical gaps |
| LOW | Some metrics below threshold |
| UNKNOWN | Insufficient data |

## Continuous Assurance Flow

```
Target + Findings + Evidence + Regression Tests
         ↓
Continuous Assurance Engine
         ↓
┌─────────────────────────────────────┐
│  Assurance Metrics                  │
│  - Finding verification rate        │
│  - Regression pass rate             │
│  - Evidence completeness            │
│  - Attack coverage                  │
│  - Remediation completeness         │
└─────────────────────────────────────┘
         ↓
   Overall Assurance Level
   (HIGH / MEDIUM / LOW / UNKNOWN)
         ↓
   Policy Verification (optional)
```

## Assurance Policies

Policies define required assurance levels per target type:

| Target Type | Minimum Assurance | Required Metrics |
|-------------|-------------------|------------------|
| LLM_MODEL | HIGH | All |
| RAG_SYSTEM | HIGH | All |
| TOOL_CHAIN | MEDIUM | Verification, Regression, Evidence |
| API_ENDPOINT | MEDIUM | Verification, Regression, Attack Coverage |
| PROMPT_TEMPLATE | LOW | Verification, Evidence |

## Continuous Assurance Flow

```
Change Detected
       ↓
Affected Security Properties Identified
       ↓
Relevant Regression Tests Selected
       ↓
Targeted Campaign Launched
       ↓
Results Compared
       ↓
Posture Updated
       ↓
Assurance Recomputed
```

## Assurance Verification

Verification runs against policies:
1. **Findings Verified** - Status FIXED/VERIFIED
2. **Regression Tests Passing** - Result "fixed"
3. **Evidence Complete** - Normalized evidence for findings
4. **Attack Coverage** - From attack coverage analytics
5. **Remediation Complete** - Status FIXED/VERIFIED/REMEDIATED

## API Endpoints

```
POST   /api/v1/assurance/compute
{
  "target_id": "uuid"
}

GET    /api/v1/assurance/targets/{id}
GET    /api/v1/assurance/targets/{id}/history?days=30

POST   /api/v1/assurance/policies
GET    /api/v1/assurance/policies

POST   /api/v1/assurance/verify
{
  "target_id": "uuid",
  "policy_id": "uuid"
}

GET    /api/v1/assurance/targets/{id}/verifications
```

## Assurance Verification Flow

```
Policy Selected
       ↓
For each finding in target:
  - Check status matches required state
  - Check regression tests pass
  - Check evidence complete
       ↓
Verification Result:
  - VERIFIED: All checks pass
  - FAILED: Some checks fail
       ↓
Update Assurance Level
```

## Acceptance Criteria

Given Target v1 → Target v2:
1. Assurance recomputed after each scan
2. Policy verification runs automatically after changes
3. Assurance history tracked over time
4. Metrics traceable to evidence/findings
5. Alerting when assurance drops below policy threshold