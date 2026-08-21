# Attack Graph Specification

## Overview

The Attack Graph is constructed from **actual observed events** - findings and evidence from real executions. It represents the attack surface as a directed graph with nodes and edges.

## Graph Structure

### Nodes (AttackNode)

```python
class AttackNode:
    node_id: UUID
    finding_id: UUID | None      # Links to finding if vulnerability node
    type: str                    # "vulnerability" | "attack_step"
    label: str                   # Vulnerability type or step description
    description: str
    metadata: dict               # technique, tactic for attack steps
    risk_score: float            # From finding risk_score
```

**Node Types:**
- `vulnerability`: Represents a finding (linked via finding_id)
- `attack_step`: Represents a step in an attack path

### Edges (AttackEdge)

```python
class AttackEdge:
    edge_id: UUID
    source_id: UUID              # Source node
    target_id: UUID              # Target node
    relationship: str            # "chains_to" | "leads_to" | "exploits" | "related_to"
    weight: float                # Edge weight for path algorithms
    evidence_ids: list[UUID]     # Evidence supporting this relationship
    metadata: dict
```

**Relationship Types:**
| Relationship | Description | Weight |
|--------------|-------------|--------|
| `chains_to` | Vulnerability A enables B | 0.7 |
| `leads_to` | Attack step sequence | 1.0 |
| `exploits` | Step exploits vulnerability | 1.0 |
| `related_to` | Shared evidence | 0.3 |

### Graph Metadata

```python
class AttackGraph:
    graph_id: UUID
    execution_id: UUID
    target_id: str
    nodes: list[AttackNode]
    edges: list[AttackEdge]
    entry_points: list[UUID]       # Attack step nodes with no incoming edges
    critical_paths: list[list[UUID]]  # Critical paths as node sequences
    created_at: datetime
    updated_at: datetime
```

## Construction Algorithm

### 1. Build Vulnerability Nodes
For each finding in the execution:
- Create vulnerability node with finding metadata
- If finding has attack_path, add attack step nodes

### 2. Add Attack Path Edges
For each finding's attack_path:
- Create edges between sequential steps (leads_to)
- Connect final step to vulnerability node (exploits)
- Edge evidence_ids = step.evidence_ids

### 3. Infer Cross-Finding Edges
For each pair of vulnerability nodes:
- **chains_to**: If vulnerability A enables B (predefined chain rules)
- **related_to**: If findings share evidence IDs

**Chain Rules:**
```
SQL_INJECTION → COMMAND_INJECTION, PATH_TRAVERSAL
XSS → CSRF, OPEN_REDIRECT
BROKEN_AUTH → BROKEN_ACCESS_CONTROL, SENSITIVE_DATA_EXPOSURE
```

### 4. Critical Path Detection
Using NetworkX shortest path algorithm:
- Entry nodes = attack_step type nodes
- Target nodes = vulnerability type nodes
- Weight = edge.weight
- Paths from entry to vulnerability = critical paths

## Evidence Traceability

**Every edge references evidence:**
- `leads_to` edges: step.evidence_ids
- `exploits` edges: finding.evidence_ids
- `chains_to` edges: union of finding evidence
- `related_to` edges: shared evidence IDs

## API Operations

### Build Graph
```
POST /api/v1/attack-graph/build
{"execution_id": "uuid", "target_id": "api.example.com"}
```

### Get Graph
```
GET /api/v1/attack-graph/{graph_id}
GET /api/v1/attack-graph/execution/{execution_id}
```

### Export Graph
```
GET /api/v1/attack-graph/{graph_id}/export?format=json|graphml
```

## Validation Rules

1. Graph must have at least one node
2. All edges must reference valid node IDs
3. Evidence IDs on edges must exist
4. Critical paths must be valid paths in the graph
5. Entry points must be actual entry nodes (no incoming edges)

## GraphML Export

Supports GraphML export for visualization tools:
- Nodes include all metadata
- Edges include relationship type and weight
- Compatible with Gephi, Cytoscape, yEd

## Anti-Fabrication Guarantees

1. **Built from actual findings only** - No theoretical nodes
2. **Evidence-backed edges** - Every relationship has evidence IDs
3. **Chain rules are explicit** - Predefined, auditable
4. **Critical paths computed** - Not manually created
5. **Execution-scoped** - Graph tied to specific execution