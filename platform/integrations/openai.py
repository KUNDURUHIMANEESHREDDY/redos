# RedOS OpenAI-Compatible Integration

## Overview

Integration with OpenAI-compatible API systems for red teaming operations. Supports GPT-4,
GPT-3.5, and other OpenAI models via the standard OpenAI API format.

## Configuration

```yaml
# RedOS OpenAI config
provider: openai
api_key: sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx
base_url: https://api.openai.com/v1  # or custom endpoint
model: gpt-4o
organization_id: org_oid
temperature: 0.7
max_tokens: 4096
timeout: 60
```

## API Client

```python
import openai
from redos.integrations.openai import OpenAIClient

client = OpenAIClient(
    api_key="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    base_url="https://api.openai.com/v1",
    organization_id="org_oid",
    default_model="gpt-4o",
)

# Chat completion for attack generation
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "You are a red teamer generating attack payloads"},
        {"role": "user", "content": "Generate an indirect prompt injection via RAG"},
    ],
    temperature=0.7,
    max_tokens=1000,
)

# Embedding for RAG systems
embedding = client.embeddings.create(
    model="text-embedding-3-small",
    input="indirect prompt injection text",
)

# Function calling for agent orchestration
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Execute attack step"}],
    functions=[{
        "name": "execute_tool",
        "description": "Execute a tool or API call",
        "parameters": {
            "type": "object",
            "properties": {
                "tool": {"type": "string"},
                "params": {"type": "object"}
            }
        }
    }],
    function_call={"name": "execute_tool"},
)
```

## Supported Operations

| Operation | endpoint | Description |
|-----------|----------|-------------|
| `chat/completions` | `POST /v1/chat/completions` | Standard chat completion |
| `embeddings` | `POST /v1/embeddings` | Text embeddings for RAG |
| `function calling` | `POST /v1/chat/completions` | Agent tool orchestration |
| `moderations` | `POST /v1/moderations` | Content moderation |
| `audio` | `POST /v1/audio` | Speech synthesis/recognition |
| `images` | `POST /v1/images` | Image generation |

## RedOS-Specific Extensions

### Attack Payload Generation

```python
from redos.integrations.openai import OpenAIClient
from redos.models import Finding, Evidence

client = OpenAIClient(...)

# Generate indirect prompt injection
response = client.generate_attack_prompt_injection(
    target_description="RAG system with document retrieval",
    vector_store="pinecone-index",
    goal="Extract PII from context",
)

# Store as evidence
evidence = Evidence(
    finding_id=finding_id,
    type="model_output",
    content=response['choices'][0]['message']['content'],
    metadata={
        "model": "gpt-4o",
        "prompt_tokens": response['usage']['prompt_tokens'],
        "completion_tokens": response['usage']['completion_tokens'],
    }
)
```

### RAG System Integration

```python
from redos.integrations.openai import OpenAIClient
from redos.integrations.rag import RAGSystem

# Initialize RAG with OpenAI
rag = RAGSystem(
    client=OpenAIClient(...),
    vector_store="pinecone://index-name",
    embedding_model="text-embedding-3-small",
)

# Search for relevant documents
results = rag.search("indirect prompt injection", top_k=5)

# Generate attack path
attack_path = rag.generate_attack_path(
    vulnerability_type="prompt_injection",
    target_description="retrieval-augmented generation system",
)
```

### Tool Use Orchestration

```python
from redos.integrations.openai import OpenAIClient
import json

client = OpenAIClient(...)

messages = [{"role": "user", "content": "Scan this target"}]

while True:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        functions=[{
            "name": "execute_attack_step",
            "description": "Execute one step of the attack campaign",
            "parameters": {
                "type": "object",
                "properties": {
                    "step": {"type": "string"},
                    "target": {"type": "string"},
                    "tool": {"type": "string"},
                    "parameters": {"type": "object"}
                }
            }
        }],
        function_call={"name": "execute_attack_step"},
    )
    
    message = response.choices[0].message
    function_call = message.function_call
    
    if function_call:
        # Execute the step
        result = execute_attack_step_fn(
            step=function_call.name,
            parameters=function_call.arguments,
        )
        
        # Add result to messages
        messages.append({
            "role": "function",
            "name": function_call.name,
            "content": json.dumps(result),
        })
    else:
        # Done - return final response
        break
```

## Rate Limiting & Quotas

| Limit Type | Default | Configurable | Window |
|-----------|---------|--------------|--------|
| Requests per minute | 100 | Org policy | 1 minute |
| Requests per day | 10,000 | Org policy | 24 hours |
| Tokens per minute | 10,000 | Org policy | 1 minute |
| Tokens per day | 100,000 | Org policy | 24 hours |
| Concurrent requests | 10 | Org policy | - |

Quota violations return error code `QUOTA_EXCEEDED` with retry-after header.

## Fallback & Provider Switching

```python
from redos.integrations.openai import OpenAIClient
from redos.integrations.anthropic import AnthropicClient
from redos.integrations.ollama import OllamaClient

# Primary: OpenAI
primary = OpenAIClient(
    api_key=os.getenv("OPENAI_KEY"),
    base_url="https://api.openai.com/v1",
)

# Fallback: Anthropic
fallback = AnthropicClient(
    api_key=os.getenv("ANTHROPIC_KEY"),
    base_url="https://api.anthropic.com/v1",
)

# Fallback: Local Ollama
local = OllamaClient(
    base_url="http://localhost:11434",
    model="llama3:8b",
)

# Switch logic
def with_fallback_ai(func, primary, *fallbacks, **kwargs):
    try:
        return func(primary, **kwargs)
    except Exception as e:
        for fallback in fallbacks:
            try:
                return func(fallback, **kwargs)
            except Exception:
                continue
        raise Exception("All AI providers failed")
```

## OpenAI Compatibility Table

| OpenAI Feature | Supported | Notes |
|---------------|-----------|-------|
| `gpt-4o` | ✅ | Full support |
| `gpt-4-turbo` | ✅ | Full support |
| `gpt-4` | ✅ | Full support |
| `gpt-3.5-turbo` | ✅ | Full support |
| `embedding` models | ✅ | text-embedding-*-* |
| `function calling` | ✅ | Schema may vary |
| `tool use` | ✅ | Via function calling |
| `moderations` | ✅ | Full support |
| `audio` | ⚠️ | Basic support |
| `images` | ⚠️ | Basic support |
| `beta features` | ⚠️ | Feature flags required |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | required | API authentication |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | Custom endpoint |
| `OPENAI_ORG_ID` | - | Organization identifier |
| `OPENAI_MODEL` | `gpt-4o` | Default model name |
| `OPENAI_TEMPERATURE` | `0.7` | Sampling temperature |
| `OPENAI_MAX_TOKENS` | `4096` | Max completion tokens |
| `OPENAI_TIMEOUT` | `60` | Request timeout (seconds) |
| `OPENAI_PROXY` | - | HTTP proxy URL |
| `OPENAI_VERIFY_SSL` | `true` | SSL verification toggle |

## Audit Logging

Every OpenAI operation logs to RedOS audit system:

```json
{
  "user_id": "user_oid",
  "action": "ai_completion",
  "resource_type": "openai_chat",
  "resource_id": "chat_completion_oid",
  "details": {
    "model": "gpt-4o",
    "prompt_tokens": 150,
    "completion_tokens": 450,
    "total_tokens": 600,
    "gate_result": "pass",
    "campaign_id": "camp_oid",
    "organization_id": "org_oid"
  },
  "ip_address": "192.168.1.1",
  "user_agent": "RedOS Platform",
  "created_at": "2024-01-15T10:30:00Z"
}
```

## Quota Management

```python
from redos.integrations.openai import OpenAIClient

client = OpenAIClient(...)

# Check remaining quota
quota = client.get_quota()
print(f"Remaining: {quota.remaining_tokens} / {quota.total_tokens}")

# Set custom quota
client.set_quota(daily=50000, per_minute=50)

# Alert on low quota
if quota.remaining_tokens < quota.total_tokens * 0.1:
    # Send alert to organization
    pass
```