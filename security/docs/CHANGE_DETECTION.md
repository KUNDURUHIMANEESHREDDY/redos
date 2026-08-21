# Change Detection Engine

## Overview

The Change Detection Engine continuously monitors AI system targets for changes and automatically identifies which security assumptions are affected.

## Change Types Monitored

| Category | Change Types |
|----------|--------------|
| **Model** | Model version, architecture, parameters, fine-tuning |
| **Prompts** | System prompt, prompt templates, few-shot examples |
| **Tools** | Tool definitions, tool implementations, tool availability |
| **Permissions** | Tool permissions, data access, network access, API scopes |
| **RAG** | Index rebuild, embedding model, chunking strategy, retrieval params |
| **Documents** | Document additions/removals, content changes, classification changes |
| **Agents** | Agent graph changes, handoff logic, chain modifications |
| **Dependencies** | Library versions, model weights, framework versions |
| **Policies** | Security policies, guardrails, content filters |

## Change Detection Flow

```
Target v1 Configuration
         ↓
   Snapshot Storage
         ↓
Target v2 Configuration (detected via git/config/API)
         ↓
   Change Detection Engine
         ↓
   ┌─────────────────────────────────────┐
   │  Change Events                      │
   │  - Type, Severity, Category         │
   │  - Before/After values              │
   │  - Detected assumptions broken      │
   │  - Attack surface impact            │
   └─────────────────────────────────────┘
```

## Security Assumption Analysis

The engine maintains a catalog of security assumptions and maps changes to assumption validity:

| Assumption | Affected By |
|------------|-------------|
| "Model cannot execute arbitrary code" | MODEL_CHANGE, SYSTEM_PROMPT_CHANGE |
| "System prompt prevents harmful outputs" | SYSTEM_PROMPT_CHANGE, POLICY_CHANGE |
| "Tools have restricted permissions" | TOOL_PERMISSION_CHANGE, TOOL_CHANGE |
| "RAG index contains only approved documents" | RAG_INDEX_CHANGE, DOCUMENT_CHANGE |
| "Agent follows configured policies" | AGENT_CONFIG_CHANGE, POLICY_CHANGE |
| "Dependencies are vetted" | DEPENDENCY_CHANGE |

## Attack Surface Impact

Changes that increase attack surface:
- **TOOL_PERMISSION_CHANGE** → New tool capabilities exposed
- **TOOL_CHANGE** → New tool capabilities or behaviors
- **AGENT_CONFIG_CHANGE** → New agent paths or handoffs
- **PERMISSION_CHANGE** → Expanded data/system access
- **RAG_INDEX_CHANGE** → New document retrieval paths

## Change Severity

| Severity | Change Types |
|----------|--------------|
| CRITICAL | MODEL_CHANGE, SYSTEM_PROMPT_CHANGE, TOOL_PERMISSION_CHANGE, POLICY_CHANGE, RAG_INDEX_CHANGE |
| HIGH | TOOL_CHANGE, RAG_INDEX_CHANGE, DOCUMENT_CHANGE, AGENT_CONFIG_CHANGE, PERMISSION_CHANGE |
| MEDIUM | PROMPT_TEMPLATE_CHANGE, DEPENDENCY_CHANGE, CONFIGURATION_CHANGE |

## API Endpoints

```
POST   /api/v1/change-detection/detect
{
  "target_id": "uuid",
  "source": "scheduled_scan"
}

GET    /api/v1/change-detection/targets/{id}/history?days=30

POST   /api/v1/change-detection/rules
GET    /api/v1/change-detection/rules
```

## Integration with Regression Intelligence

When changes are detected:
1. **Affected findings** → Identified via assumption mapping
2. **Attack variants** → Determined from attack surface changes
3. **Regression tests** → Auto-selected for re-execution
3. **Campaign launch** → Targeted re-scan of affected areas

## Acceptance Criteria

Given Target v1 → Target v2 with changes:
1. Engine detects all change types (model, prompt, tools, permissions, RAG, docs, agents, policies, deps)
2. Maps each change to affected security assumptions
3. Calculates attack surface delta (new vectors, removed vectors, risk delta)
4. Outputs: broken assumptions, new attack vectors, risk increase