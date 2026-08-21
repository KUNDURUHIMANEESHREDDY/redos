# Digital Twin Architecture

## Overview

The Digital Twin is a continuously updated, live representation of an AI system's security architecture. It mirrors the target system's components, their relationships, configurations, and security state in real-time.

## Architecture

```
AI System Digital Twin
├── Components
│   ├── Models
│   │   ├── Versions
│   │   ├── Parameters
│   │   └── Fine-tuning history
│   ├── Prompts
│   │   ├── System prompts
│   │   ├── Prompt templates
│   │   └── Few-shot examples
│   ├── Tools
│   │   ├── Definitions
│   │   ├── Permissions
│   │   └── Capabilities
│   ├── Permissions
│   │   ├── Tool permissions
│   │   ├── Data access
│   │   └── Network access
│   ├── RAG
│   │   ├── Indexes
│   │   ├── Embedding models
│   │   ├── Chunking strategies
│   │   └── Retrieval configs
│   ├── Documents
│   │   ├── Knowledge base
│   │   ├── Training data
│   │   └── Classification
│   ├── Memory
│   │   ├── Conversation history
│   │   ├── Working memory
│   │   └── Long-term memory
│   ├── Agents
│   │   ├── Configurations
│   │   ├── Chain structures
│   │   └── Handoff logic
│   ├── APIs
│   │   ├── External integrations
│   │   ├── Webhook endpoints
│   │   └── Authentication
│   └── Dependencies
│       ├── Library versions
│       ├── Model weights
│       └── Framework versions
├── Edges (Relationships)
│   ├── uses_tool
│   ├── queries
│   ├── indexes
│   ├── reads/writes
│   ├── requires_permission
│   ├── calls
│   └── delegates_to
└── Metadata
    ├── Version history
    ├── Change log
    ├── Security impact assessments
    └── Assumption violations
```

## Component Model

Each component in the twin has:

```python
TwinComponent:
  - component_id: UUID
  - component_type: MODEL | PROMPT | TOOL | PERMISSION | RAG | DOCUMENT | MEMORY | AGENT | API | DEPENDENCY
  - name: str
  - version: str
  - description: str
  - status: ACTIVE | DEPRECATED | TESTING | DISABLED
  - configuration: dict
  - metadata: dict
  - parent_id: UUID (for hierarchy)
  - dependencies: list[UUID]
  - dependents: list[UUID]
  - risk_score: float (0-10)
  - last_scanned: datetime
```

## Edge Model

```python
TwinEdge:
  - edge_id: UUID
  - source_id: UUID
  - target_id: UUID
  - relationship: uses_tool | queries | indexes | reads | writes | requires_permission | calls | delegates_to
  - weight: float
  - evidence_ids: list[UUID]
```

## Synchronization

### Full Sync
Complete rebuild from target configuration:
1. Delete all existing components/edges
2. Rebuild from target configuration
3. Create new snapshot
4. Increment major version

### Incremental Sync
Detect and apply only changes:
1. Compare current vs new components
2. Detect: added, modified, removed
3. Generate ComponentChange records
4. Assess security impact of each change
5. Update assumption validity
5. Create new snapshot
6. Increment minor version

## Change Detection

Changes are categorized:
- **added**: New component appeared
- **modified**: Version/configuration changed
- **removed**: Component no longer exists

Each change generates a `ComponentChange` with:
- before/after state
- diff
- security impact assessment
- affected assumption analysis

## Security Impact Assessment

Changes to high-risk components automatically trigger:
- Assumption violation checks
- Finding correlation updates
- Regression test recommendations
- Risk propagation alerts

### Risk Scoring
- Model: Base 2-4 (provider, fine-tuning)
- Prompt: 1-5 (injection risk, override attempts)
- Tool: 2-10 (permissions, shell access, DB write)
- Permission: 1-6 (write/delete/admin)
- RAG: 1-5 (external access, public docs)
- Document: 1-6 (sensitivity, classification)
- Agent: 2-7 (autonomy, delegation)
- API: 1-4 (auth, public access)

## Assumption Tracking

The twin tracks security assumptions and their validity:

| Assumption | Components That Affect It |
|------------|--------------------------|
| Model cannot execute arbitrary code | MODEL, PROMPT |
| System prompt prevents harmful outputs | PROMPT, POLICY |
| Tools have restricted permissions | TOOL, PERMISSION |
| RAG index contains only approved documents | RAG, DOCUMENT |
| Agent follows configured policies | AGENT, POLICY |
| Dependencies are vetted | DEPENDENCY |

When a relevant component changes, the assumption is marked potentially invalid and an `AssumptionImpact` is recorded.

## API Endpoints

```
POST   /api/v1/digital-twin/twins                 # Create twin
GET    /api/v1/digital-twin/twins/{twin_id}       # Get twin
POST   /api/v1/digital-twin/twins/sync            # Sync twin
GET    /api/v1/digital-twin/twins/{twin_id}/snapshots
GET    /api/v1/digital-twin/twins/{twin_id}/changes
GET    /api/v1/digital-twin/twins/{twin_id}/assumptions
POST   /api/v1/digital-twin/twins/compare         # Compare two twins
```

## Snapshot Versioning

Each sync creates a `TwinSnapshot`:
- Full component/edge state
- Version number (major.minor)
- Timestamp

Enables:
- Point-in-time queries
- Rollback capability
- Change timeline reconstruction
- Compliance auditing

## Integration Points

### With Risk Graph
- Twin components → Risk graph nodes
- Twin edges → Risk graph edges
- Component risk scores → Node risk scores
- Change events → Risk propagation triggers

### With Change Detection
- Twin sync triggers change detection
- Detected changes update twin
- Assumption impacts feed back to change detector

### With Knowledge Base
- Component patterns → Knowledge entries
- Remediation patterns from twin components
- Regression patterns from version comparisons

### With Assurance
- Component verification status
- Configuration compliance checks
- Evidence completeness per component

## Acceptance Criteria

Given Target v1 and Target v2:
1. Digital twin for v1 exists and is synced
2. After v2 deployment, incremental sync detects changes
3. Changes categorized (added/modified/removed)
4. Security impact assessed per change
5. Assumption violations identified
6. New snapshot created (v1.1)
7. Comparison v1 vs v2 shows:
   - Added components
   - Modified components (with diffs)
   - Removed components
   - Security impact summary
   - Assumption violations
   - Recommended regression tests