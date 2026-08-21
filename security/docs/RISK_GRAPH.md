# Risk Graph Architecture

## Overview

The Risk Graph is a dynamic, queryable graph representation of an AI system's attack surface. It combines target architecture, observed executions, findings, permissions, and attack paths into a unified, queryable graph where risk propagates through edges.

## Graph Structure

### Nodes (GraphNode)

```python
GraphNode:
  - node_id: UUID
  - graph_id: UUID
  - node_type: MODEL | PROMPT | TOOL | PERMISSION | RAG_INDEX | DOCUMENT | MEMORY | AGENT | API | DATA_STORE | ENTRY_POINT | VULNERABILITY | ATTACK_STEP
  - label: str
  - description: str
  - target_id: Optional[UUID]
  - finding_id: Optional[UUID]
  - execution_id: Optional[UUID]
  - risk_level: CRITICAL | HIGH | MEDIUM | LOW | INFO
  - risk_score: float (0-10)
  - metadata: dict
  - properties: dict
```

### Edges (GraphEdge)

```python
GraphEdge:
  - edge_id: UUID
  - graph_id: UUID
  - source_id: UUID
  - target_id: UUID
  - edge_type: CALLS | ACCESSES | CONTAINS | FLOWS_TO | DEPENDS_ON | EXPLOITS | CHAINS_TO | LEADS_TO | RELATED_TO | PERMITS | READS | WRITES
  - weight: float
  - evidence_ids: list[UUID]
  - finding_ids: list[UUID]
```

### Graph Metadata

```python
RiskGraph:
  - graph_id: UUID
  - target_id: UUID
  - name: str
  - description: str
  - nodes: list[GraphNode]
  - edges: list[GraphEdge]
  - entry_points: list[UUID]
  - critical_paths: list[list[UUID]]
  - risk_score: float
```

## Node Types

| Type | Description | Risk Base |
|------|-------------|-----------|
| MODEL | LLM/embedding model | 2-4 |
| PROMPT | System prompt, templates | 1-5 |
| TOOL | Shell, DB, API, custom | 2-10 |
| PERMISSION | Access control rule | 1-6 |
| RAG_INDEX | Vector index, retrieval config | 1-5 |
| DOCUMENT | Knowledge base doc | 1-6 |
| MEMORY | Conversation/working memory | 1-3 |
| AGENT | Agent configuration | 2-7 |
| API | External API integration | 1-4 |
| DATA_STORE | Database, file store | 1-5 |
| ENTRY_POINT | User-facing interface | 1-3 |
| VULNERABILITY | Security finding | 4-10 |
| ATTACK_STEP | Execution trace step | 1-3 |

## Edge Types

| Type | Description | Weight |
|------|-------------|--------|
| CALLS | Component calls another | 0.8 |
| ACCESSES | Component accesses resource | 0.9 |
| CONTAINS | Parent contains child | 1.0 |
| FLOWS_TO | Data flows to | 0.7 |
| DEPENDS_ON | Dependency relationship | 0.6 |
| EXPLOITS | Finding exploits component | 1.0 |
| CHAINS_TO | Vuln chains to another | 0.8 |
| LEADS_TO | Attack step sequence | 0.8 |
| RELATED_TO | Shared evidence/correlation | 0.3 |
| PERMITS | Permission grants access | 1.0 |
| READS | Component reads data | 0.8 |
| WRITES | Component writes data | 0.9 |

## Graph Construction

The graph is built by combining:

1. **Static Architecture** - Target configuration, tool definitions, permissions
2. **Dynamic Executions** - Observed tool calls, data flows, agent interactions
3. **Findings** - Vulnerabilities with evidence and risk scores
4. **Attack Paths** - Multi-step exploit chains from attack_graph
5. **Permissions** - Access control relationships
6. **Change History** - Configuration changes as nodes

### Construction Pipeline

```
Target Configuration
       ↓
Add Component Nodes (Model, Tools, Prompts, RAG, Docs, Agents, APIs, Permissions)
       ↓
Add Finding Nodes (from findings collection)
       ↓
Add Change History Nodes (from change_detection)
       ↓
Add Edges from Attack Graph (exploits, chains_to, leads_to)
       ↓
Add Permission Edges (tool → permission → resource)
       ↓
Add Data Flow Edges (agent → tool → RAG → docs → DB)
       ↓
Compute Risk Scores (propagate through graph)
       ↓
Find Critical Paths (entry point → vulnerability)
       ↓
Identify Entry Points
```

## Risk Computation

### Node Risk Scoring

Base risk per node type:
- VULNERABILITY: Finding risk_score (CVSS-based)
- TOOL: 2-10 (based on permissions)
- PERMISSION: 1-6 (write/delete/admin = higher)
- MODEL: 2-4 (provider, fine-tuning)
- DOCUMENT: 1-6 (sensitivity)
- RAG_INDEX: 1-5 (external access)
- AGENT: 2-7 (autonomy)
- API: 1-4 (auth)

### Risk Propagation

Risk flows through edges:
```
Risk(node) = max(base_risk, max(neighbor_risk * edge_weight) for all incoming edges)
```

Algorithm:
1. Initialize all nodes with base risk
2. Topological sort (or iterative relaxation for cycles)
3. Propagate risk along edges weighted by edge.weight
4. Iterate until convergence

### Entry Points

Nodes with no incoming edges or type ENTRY_POINT:
- API endpoints
- User-facing interfaces
- Public APIs
- Webhooks

### Critical Paths

Paths from entry points to vulnerabilities:
1. Identify all entry point nodes
2. Identify all vulnerability nodes
3. For each entry→vuln pair, find shortest path
4. Weight by edge weights
5. Rank by cumulative risk score

## Risk Propagation

When a change occurs (permission added, tool modified, etc.):

```
RiskPropagationEvent:
  - source_node_id: UUID
  - affected_node_ids: list[UUID]
  - trigger_type: str
  - risk_delta: float
  - propagated: bool
```

### Propagation Algorithm

1. Start from changed node
2. BFS/DFS along outgoing edges
3. For each affected node:
   - Recompute risk_score = max(current, max(incoming_risk * weight))
   - If risk increased, continue propagation
   - Track risk_delta
2. Update all affected nodes
3. Recompute critical paths
3. Record RiskPropagationEvent

## Blast Radius Assessment

Given a compromised node, what's the blast radius?

```python
BlastRadiusAssessment:
  - source_node_id: UUID
  - affected_nodes: list[UUID]
  - blast_radius_score: float (avg risk of affected)
  - max_depth: int
  - affected_assets: list[str]
  - affected_data_stores: list[str]
  - critical_paths: list[list[UUID]]
```

Algorithm:
1. BFS from source node along outgoing edges
2. Track depth and affected nodes
3. Categorize affected nodes by type
4. Identify critical paths passing through source
5. Compute blast radius score (weighted average risk)

## API Endpoints

```
POST   /api/v1/risk-graph/build                    # Build/rebuild graph
GET    /api/v1/risk-graph/targets/{id}             # Get graph by target
GET    /api/v1/risk-graph/{graph_id}               # Get graph by ID
GET    /api/v1/risk-graph/{graph_id}/blast-radius  # Blast radius from node
POST   /api/v1/risk-graph/{graph_id}/propagate     # Trigger propagation
GET    /api/v1/risk-graph/{graph_id}/critical-paths
GET    /api/v1/risk-graph/{graph_id}/entry-points
GET    /api/v1/risk-graph/{graph_id}/risk-propagation-history
```

## Integration Points

### With Digital Twin
- Twin components → Graph nodes
- Twin edges → Graph edges
- Component risk scores → Node risk scores
- Change events → Propagation triggers

### With Change Detection
- Detected changes → Graph updates
- New attack vectors → New edges/nodes
- Assumption violations → Risk increases

### With Correlation Engine
- Correlated findings → Composite paths
- Systemic risk → Graph risk score
- Blast radius → Correlation severity

### With Attack Graph
- Attack graph edges → Risk graph edges
- Attack paths → Critical paths
- MITRE techniques → Node metadata

### With Posture Engine
- Graph risk score → Posture metric
- Critical paths count → Posture metric
- Blast radius → Unresolved risk metric

### With Intelligence
- Regression findings → Risk graph updates
- Attack coverage → Graph coverage metric
- Risk trend → Graph risk history

## Graph Queries

| Query | Purpose |
|-------|---------|
| Critical paths | Find highest-risk attack paths |
| Blast radius | What's affected if node compromised? |
| Permission audit | Who can access what? |
| Data flow | Where does sensitive data go? |
| Attack coverage | What's tested vs untested? |
| Dependency chain | What depends on vulnerable component? |

## Visualization Export

Supports export to:
- GraphML (for Gephi, yEd)
- Cytoscape.js JSON
- D3.js force-directed format
- Mermaid diagram

## Acceptance Criteria

Given Target v1 → Target v2 with permission change:
1. Risk graph for v1 exists
2. Change detection detects permission change
3. Risk propagation triggers from changed permission node
4. Affected tool/database nodes updated
5. New critical paths identified
6. Blast radius from changed permission computed
7. Risk propagation event recorded
8. Graph risk score updated
9. Posture engine picks up new risk score
10. Change detection reports broken assumptions