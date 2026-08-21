# RedOS MCP Servers Integration

## Overview

Integration with Model Context Protocol (MCP) servers for standardized AI model communication.
MCP provides a unified interface for interacting with various AI models, prompt pipelines,
and model orchestration systems.

## MCP Protocol Specification

### Message Format

```json
{
  "jsonrpc": "2.0",
  "id": "unique-request-id",
  "method": "tools/call",
  "params": {
    "name": "tool_name",
    "arguments": {
      "param1": "value1",
      "param2": 42
    }
  }
}
```

### Supported Methods

| Method | Description | Parameters | Response |
|--------|-------------|------------|----------|
| `tools/call` | Execute a tool or function | `name`, `arguments` | `result`, `is_error`, `content` |
| `tools/list` | List available tools | - | `tools` array |
| `prompts/get` | Get a prompt template | `prompt_name` | `prompt`, `messages` |
| `prompts/list` | List available prompts | - | `prompts` array |
| `resources/list` | List available resources | - | `resources` array |
| `resource/read` | Read a resource | `uri` | `text`, `mimeType` |

### MCP Server Configuration

```yaml
# RedOS MCP config
mcp_servers:
  - name: "primary-mcp"
    url: "http://localhost:8000/mcp"
    auth: "api_key"
    api_key: "mcp_secret_key"
    models:
      - "gpt-4o"
      - "claude-3-opus-20240229"
      - "llama3:8b"
    timeout: 60
    retry_count: 3
    failover:
      - name: "secondary-mcp"
        url: "http://backup-mcp:8000/mcp"
```

### MCP Client

```python
from redos.integrations.mcp import MCPClient

client = MCPClient(
    base_url="http://localhost:8000/mcp",
    api_key="mcp_secret_key",
    timeout=60,
)

# List available tools
tools = client.list_tools()
for tool in tools['tools']:
    print(f"• {tool['name']}: {tool['description']}")

# Call a tool
result = client.call_tool(
    name="search_vector_store",
    arguments={
        "query": "indirect prompt injection",
        "collection": "redteam-knowledge",
        "top_k": 5,
    }
)
print(result['content'][0]['text'])

# List available prompts
prompts = client.list_prompts()
for prompt in prompts['prompts']:
    print(f"• {prompt['name']}")

# Get a prompt
prompt_data = client.get_prompt(
    prompt_name="attack_generation",
    variables={
        "target": "RAG system",
        "goal": "extract PII",
    }
)
print(prompt_data['prompt'])
```

### MCP for Attack Generation

```python
from redos.integrations.mcp import MCPClient

client = MCPClient(...)

# Generate attack payload via MCP
attack_prompt = """
Generate an indirect prompt injection for a RAG system.
Target: Document retrieval system with vector search.
Goal: Extract user PII from retrieved context.
"""

result = client.call_tool(
    name="generate_attack",
    arguments={
        "prompt": attack_prompt,
        "model": "gpt-4o",
        "format": "json",
    }
)

attack_payload = json.loads(result['content'][0]['text'])
print(f"Generated payload: {attack_payload['payload']}")
print(f"Stealth score: {attack_payload['stealth_score']}")
```

### MCP Resource Management

```python
from redos.integrations.mcp import MCPClient

client = MCPClient(...)

# Register a new tool
tool_definition = {
    "name": "execute_attack_step",
    "description": "Execute one step of a RedOS attack campaign",
    "input_schema": {
        "type": "object",
        "properties": {
            "step_id": {"type": "string"},
            "parameters": {"type": "object"}
        }
    }
}

result = client.register_tool(tool_definition)
print(f"Tool registered: {result['success']}")

# Discover resources
resources = client.list_resources()
for resource in resources['resources']:
    print(f"Resource: {resource['uri']} - {resource.get('description', 'N/A')}")
```