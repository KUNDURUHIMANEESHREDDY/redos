# Security Posture Engine

## Overview

The Security Posture Engine continuously calculates and tracks the security posture of AI system targets. It moves beyond isolated findings to provide a holistic, time-series view of security risk.

## Core Concepts

### Target
A Target represents an AI system component with a versioned configuration:
- **Models** - LLMs, embedding models, classifiers
- **Prompts** - System prompts, prompt templates, few-shot examples
- **Tools** - Shell, database, API, file system, custom functions
- **Permissions** - Tool permissions, data access, network access
- **RAG** - Vector indexes, retrieval configurations, chunking strategies
- **Documents** - Knowledge base documents, training data
- **Agents** - Agent configurations, chain structures, handoff logic
- **APIs** - External API integrations, webhook endpoints
- **Dependencies** - Third-party libraries, model weights, frameworks

### Posture Snapshot
A point-in-time assessment containing:
- **Overall Score** (0-100): Weighted risk score
- **Posture Level**: CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
- **Metrics**: Critical findings, high findings, average risk score, evidence count
- **Derived Metrics**: Attack coverage, remediation rate, regression rate, unresolved risk

### Risk History
Time-series of posture snapshots enabling:
- Trend analysis (improving/stable/deteriorating)
- Risk velocity (rate of change)
- Baseline comparisons
- Change impact assessment

## API Endpoints

### Target Management
```
POST   /api/v1/posture/targets              # Register new target
GET    /api/v1/posture/targets              # List targets (filter by type/status)
GET    /api/v1/posture/targets/{id}         # Get target details
POST   /api/v1/posture/targets/{id}/versions # Update target version/config
```

### Posture Computation
```
POST   /api/v1/posture/targets/{id}/compute-posture  # Trigger posture computation
GET    /api/v1/posture/targets/{id}/posture          # Get latest posture snapshot
```

### Risk History
```
GET    /api/v1/posture/targets/{id}/risk-history?days=30
```

### Baseline Comparison
```
POST   /api/v1/posture/targets/{id}/compare
{
  "baseline_snapshot_id": "uuid"
}
```

## Posture Calculation

### Metrics
| Metric | Weight | Thresholds |
|--------|--------|------------|
| Critical Findings | 10x | C:≥5, H:≥3, M:≥1, L:≥0 |
| High Findings | 5x | C:≥10, H:≥5, M:≥2, L:≥0 |
| Average Risk Score | 2x | C:≥8, H:≥6, M:≥4, L:≥2 |

### Posture Levels
| Score Range | Level |
|-------------|-------|
| ≥70 | CRITICAL |
| 40-69 | HIGH |
| 20-39 | MEDIUM |
| 5-19 | LOW |
| 0-4 | MINIMAL |

## Version Tracking

Every target maintains a version history with configuration snapshots:
```
Target v1 → Target v2 → Target v3
  └── config snapshot
  └── change summary
  └── posture impact
```

## Acceptance Criteria

Given Target v1 and Target v2 (with changes), the posture engine:
1. Computes posture for both versions
2. Compares snapshots
3. Reports: NEW vulnerabilities, FIXED vulnerabilities, CHANGED risk, CHANGED attack surface