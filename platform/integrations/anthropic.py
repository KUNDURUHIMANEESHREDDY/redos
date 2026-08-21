# RedOS Anthropic Integration

## Overview

Integration with Anthropic's Claude API for red teaming operations. Supports Claude 3 Opus,
Sonnet, and Haiku models with enhanced tool use and reasoning capabilities.

## Configuration

```yaml
# RedOS Anthropic config
provider: anthropic
api_key: anon_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
model: claude-3-opus-20240229
temperature: 0.7
max_tokens: 4096
top_k: 40
top_p: 0.999
timeout: 60
```

## API Client

```python
from redos.integrations.anthropic import AnthropicClient

client = AnthropicClient(
    api_key="anon_xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    model="claude-3-opus-20240229",
    temperature=0.7,
    max_tokens=4096,
)

# Message completion
response = client.messages.create(
    model="claude-3-opus-20240229",
    max_tokens=4096,
    temperature=0.7,
    messages=[
        {"role": "user", "content": "Generate an attack campaign against RAG system"}
    ],
    system="You are a red teamer conducting security analysis.",
)

# Tool use with Claude
response = client.messages.create(
    model="claude-3-opus-20240229",
    max_tokens=4096,
    temperature=0.7,
    messages=[{"role": "user", "content": "Execute attack step"}],
    system="You have access to the following tools:",
    tools=[
        {
            "name": "execute_tool",
            "description": "Execute a tool or API call",
            "input_schema": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string"},
                    "params": {"type": "object"}
                }
            }
        }
    ],
    tool_choice={"type": "tool", "name": "execute_tool"},
)
```

## Supported Models

| Model | Context | Max Tokens | Best For |
|-------|---------|------------|----------|
| `claude-3-opus-20240229` | 200K | 4K | Complex reasoning, attack generation |
| `claude-3-sonnet-20240229` | 200K | 4K | Balanced cost/performance |
| `claude-3-haiku-20240307` | 200K | 4K | Fast operations, simple tasks |

## Tool Use & Agent Orchestration

```python
from redos.integrations.anthropic import AnthropicClient

client = AnthropicClient(...)

# Multi-turn tool use loop
messages = []
loop_count = 0
max_loops = 10

while loop_count < max_loops:
    loop_count += 1
    
    response = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=4096,
        temperature=0.7,
        messages=messages,
        system="You are conducting a red team engagement. "
               "Use tools when needed to gather information or perform actions.",
        tools=[
            {
                "name": "search_vector_store",
                "description": "Search vector database for relevant documents",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "collection": {"type": "string"},
                        "top_k": {"type": "integer", "default": 5}
                    }
                }
            },
            {
                "name": "execute_api_call",
                "description": "Make an HTTP API call",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string"},
                        "url": {"type": "string"},
                        "headers": {"type": "object"},
                        "body": {"type": "object"}
                    }
                }
            }
        ]
    )
    
    # Check if tool use
    if response.stop_reason == "tool_use":
        # Add assistant message
        messages.append({
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": tool.id,
                    "type": "tool_use",
                    "name": tool.name,
                    "input": tool.input
                }
            ]
        })
        # Loop continues - user adds tool result
    else:
        # Done - return response
        break
```

## Anthropic-Specific Features

### System Prompt Engineering

```python
from redos.integrations.anthropic import AnthropicClient

client = AnthropicClient(...)

# Effective system prompts for red teaming
system_prompts = {
    "attack_generation": """
You are a red teamer conducting a security assessment. 
Your goal is to identify vulnerabilities through controlled testing.
Always operate within authorized boundaries.
Document all findings with evidence.
Never execute commands that could damage systems.
""",
    
    "analysis": """
You are analyzing security findings from red team operations.
Identify root causes and prioritize by risk.
Provide remediation recommendations.
Reference evidence for all conclusions.
""",
    
    "report_generation": """
You are generating a security report for stakeholders.
Use clear, non-technical language where appropriate.
Highlight critical findings first.
Provide actionable remediation steps.
Structure with executive summary first.
"""
}
```

### System Prompt Injection

```python
from redos.integrations.anthropic import AnthropicClient

client = AnthropicClient(...)

# Generate system prompt that's resistant to injection
def secure_system_prompt(base_prompt: str, sanitization_rules: list) -> str:
    """Apply sanitization rules to prevent prompt injection"""
    prompt = base_prompt
    for rule in sanitization_rules:
        if rule == "remove_think_tokens":
            prompt = prompt.replace("<\|observation|>", "").replace("<\|end|>", "")
        if rule == "limit_context":
            prompt = prompt[:10000]  # Hard limit
        if rule =="forbid_certain_phrases":
            for phrase in ["ignore previous instructions", "system prompt", "you are"]:
                prompt = prompt.replace(phrase, "")
    return prompt

prompt = secure_system_prompt(
    base_prompt="You are a red teamer...",
    sanitization_rules=["remove_think_tokens", "limit_context"]
)
```

## Rate Limiting & Quotas

| Limit Type | Default | Configurable | Window |
|-----------|---------|--------------|--------|
| Requests per minute | 5 | Org policy | 1 minute |
| Requests per hour | 500 | Org policy | 1 hour |
| Tokens per minute | 20K | Org policy | 1 minute |
| Tokens per hour | 500K | Org policy | 1 hour |
| Concurrent requests | 5 | Org policy | - |

## Quota Management

```python
from redos.integrations.anthropic import AnthropicClient

client = AnthropicClient(...)

# Check quota
quota = client.get_quota()
print(f"Input tokens: {quota.input_tokens_remaining}")
print(f"Output tokens: {quota.output_tokens_remaining}")

# Set custom quota
client.set_quota(
    requests_per_minute=10,
    requests_per_hour=200,
    tokens_per_minute=5000,
    tokens_per_hour=50000
)

# Check before expensive operations
if not client.has_sufficient_quota(
    input_tokens=5000,
    output_tokens=10000,
    min_requests=1
):
    # Use fallback model or wait
    pass
```

## Anthropic Compatibility Table

| Feature | Supported | Notes |
|---------|-----------|-------|
| `claude-3-opus-20240229` | ✅ | Full support |
| `claude-3-sonnet-20240229` | ✅ | Full support |
| `claude-3-haiku-20240307` | ✅ | Full support |
| `tool use` | ✅ | Complete support |
| `system` messages | ✅ | Full support |
| `tool results` | ✅ | Via API |
| `streaming` | ✅ | SSE support |
| `metadata` | ✅ | Returned in response |
| `beta features` | ⚠️ | Feature flags |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | required | API authentication |
| `ANTHROPIC_BASE_URL` | `https://api.anthropic.com` | Custom endpoint |
| `ANTHROPIC_MODEL` | `claude-3-opus-20240229` | Default model |
| `ANTHROPIC_TEMPERATURE` | `0.7` | Sampling temperature |
| `ANTHROPIC_MAX_TOKENS` | `4096` | Max completion tokens |
| `ANTHROPIC_TIMEOUT` | `60` | Request timeout (seconds) |
| `ANTHROPIC_PROXY` | - | HTTP proxy URL |
| `ANTHROPIC_VERIFY_SSL` | `true` | SSL verification toggle |

## Audit Logging

Every Anthropic operation logs to RedOS audit system with same schema as OpenAI integration,
ensuring consistent audit across all AI providers.

## Fallback Orchestration

```python
from redos.integrations.anthropic import AnthropicClient
from redos.integrations.openai import OpenAIClient

anthropic = AnthropicClient(...)
openai = OpenAIClient(...)

def query_ai(prompt, prefer="anthropic"):
    """Query AI with automatic fallback"""
    models = {
        "anthropic": (anthropic, "claude-3-opus-20240229"),
        "openai": (openai, "gpt-4o"),
    }
    
    client, model = models.get(prefer, models["anthropic"])
    
    try:
        if prefer == "anthropic":
            response = client.messages.create(
                model=model,
                messages=[{"role": "user", "content": prompt}]
            )
        else:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}]
            )
        return response
    except Exception as e:
        # Automatic fallback
        other_prefer = "openai" if prefer == "anthropic" else "anthropic"
        client, model = models[other_prefer]
        return query_ai(prefer=other_prefer)
```