# RedOS Integrations Documentation

## Overview

RedOS integrates with a wide variety of AI systems, agent frameworks, RAG systems, MCP servers,
and custom APIs. This document provides comprehensive guidance for connecting external services
to the RedOS platform.

## AI Provider Integrations

| Provider | Status | Key Features | Setup Complexity |
|----------|--------|-------------|-----------------|
| **OpenAI** | ✅ Supported | Chat completions, embeddings, function calling, tool use | Low |
| **Anthropic** | ✅ Supported | Claude 3 models, tool use, system prompts, extended context | Low-Medium |
| **Ollama** | ✅ Supported | Local LLMs, air-gapped, data sovereignty, cost-free inference | Medium |
| **MCP** | ✅ Supported | Unified protocol, tool discovery, prompt management, resource access | Medium |

## Agent Frameworks

| Framework | Status | Best For | Complexity |
|-----------|--------|----------|------------|
| **AutoGPT** | ✅ Supported | Autonomous campaigns, goal-driven attacks | High |
| **BabyAGI** | ✅ Supported | Step-by-step task execution, task prioritization | Medium |
| **LangGraph** | ✅ Supported | Complex workflows, stateful agents, human-in-the-loop | High |
| **CrewAI** | ✅ Supported | Team-based attacks, role-based agent allocation | Medium |
| **AutoGen** | ✅ Supported | Multi-agent discussions, human-in-the-loop | High |
| **LangChain** | ✅ Supported | Custom tools, function calling, flexible agents | Medium |

## RAG Systems

| System | Status | Vector Stores | Complexity |
|--------|--------|--------------|------------|
| **LlamaIndex** | ✅ Supported | Pinecone, Weaviate, Chroma, Qdrant | Medium |
| **Weaviate** | ✅ Supported | Native vector store | Medium |
| **Chroma** | ✅ Supported | Local, easy setup | Low |
| **Custom** | ✅ Supported | Any vector store with Python client | Medium |

## MCP Servers

| Feature | Support |
|---------|--------|
| `tools/call` | ✅ Fully supported |
| `tools/list` | ✅ Fully supported |
| `prompts/get` | ✅ Fully supported |
| `prompts/list` | ✅ Fully supported |
| `resources/list` | ✅ Fully supported |
| `resource/read` | ✅ Fully supported |

## Custom APIs

| Category | Supported APIs | Authentication |
|----------|---------------|---------------|
| **CRM** | Salesforce, HubSpot | OAuth2, API Key |
| **Messaging** | Slack, Discord, Twilio | Bot Token, API Key |
| **Billing** | Stripe, PayPal | API Key |
| **Version Control** | GitHub, GitLab | OAuth2 |
| **Ticketing** | Zendesk, ServiceNow | OAuth2 |
| **Monitoring** | Splunk, PagerDuty | OAuth2, API Key |

## Integration QuickStart

### 1. Choose Your AI Provider

```python
from redos.integrations import get_provider

# OpenAI
provider = get_provider("openai", api_key="sk-...")

# Anthropic
provider = get_provider("anthropic", api_key="anon_...")

# Ollama (local)
provider = get_provider("ollama", base_url="http://localhost:11434")

# RAG system
provider = get_provider("rag", llm="ollama:llama3:8b", vector_store="chroma")
```

### 2. Configure Agent Framework

```python
from redos.integrations.agent_frameworks import AutoGPTClient

client = AutoGPTClient(
    api_key="sk-...",
    reddos_api="https://api.redos.io",
    reddos_key="redos_key",
    goal="Identify security vulnerabilities in RAG systems",
    human_in_loop=False,
)

# Run autonomous cycle
result = client.run_cycle()
```

### 3. Add RAG Context

```python
from redos.integrations.rag import LlamaIndexRAG

rag = LlamaIndexRAG(
    llm="ollama:llama3:8b",
    vector_store="chroma",
    index_name="redteam-knowledge",
)

# Search and create findings
results = rag.search_attack_vectors(
    target_type="RAG system",
    vulnerability="prompt_injection",
    top_k=10,
)

for result in results:
    # Create finding in RedOS
    finding = Finding(
        title=result["title"],
        severity=result.get("severity", "MEDIUM"),
        description=result["description"],
        execution_id=result.get("execution_id"),
        evidence=[
            Evidence(
                type="retrieved_document",
                content=result["content"],
                metadata=result.get("metadata", {}),
            )
        ],
    )
    # Save to RedOS API
    client.save_finding(finding)
```

### 4. Set Up Security Gates

```yaml
# Configure in organization settings
gates:
  BLOCK_CRITICAL:
    enabled: true
    severity: "CRITICAL"
    action: "block"
  BLOCK_HIGH_INTRO:
    enabled: true
    hours_window: 24
    action: "block"
  WARN_MEDIUM_INCREASE:
    enabled: true
    threshold: 5
    window_days: 30
    action: "warn"
  PASS_NO_REGRESSION:
    enabled: true
  PASS_COMPLIANCE:
    enabled: false
```

### 5. Deploy and Monitor

```bash
# Deploy RedOS platform
docker-compose up -d

# Monitor integrations
docker logs redos-api-1 | grep -i "integration\|error\|warning"

# Check health
curl http://localhost:8000/api/v1/health

# View metrics
curl http://localhost:8000/metrics
```

## Integration Best Practices

### 1. Security

- Never store API keys in source code
- Use environment variables or secret management
- Enable TLS/HTTPS for all external connections
- Validate API responses against schemas
- Implement circuit breakers for failed providers
- Log all API calls for audit purposes

### 2. Reliability

- Implement fallback chains between AI providers
- Set appropriate timeouts (60-120 seconds typical)
- Handle rate limiting gracefully (backoff, retry)
- Cache repeated queries when possible
- Monitor latency and error rates
- Set up alerts for quota exhaustion

### 3. Scalability

- Use connection pooling for database APIs
- Implement request batching where possible
- Scale API clients horizontally
- Use connection strings that support pooling
- Monitor resource utilization (CPU, memory, connections)
- Plan for horizontal growth

### 4. Observability

- Track request latency and error rates
- Monitor token usage and costs
- Log all API calls with full context
- Set up metrics dashboard
- Alert on anomalies and failures
- Maintain integration runbooks

### 5. Compliance

- Ensure data residency requirements are met
- Verify AI provider terms of service
- Log all data access and modifications
- Maintain audit trails for all integrations
- Verify compliance with SOC2, ISO27001, etc.
- Document data flows and processing

## Troubleshooting Guide

### Common Issues

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| `Authentication failed` | Invalid API key or token | Check credentials, refresh token, verify scopes |
| `Rate limit exceeded` | Too many requests | Implement backoff, reduce concurrency, check quotas |
| `Timeout exceeded` | Slow API or network | Increase timeout, optimize queries, check network |
| `Invalid response format` | API version mismatch | Update API version, check schema, validate response |
| `Model not found` | Model name incorrect | Check available models, pull required model |
| `Connection refused` | Service not running | Start service, check ports, verify network |
| `SSL certificate error` | Certificate issue | Verify SSL, add to trust store, disable verification if safe |
| `Import error` | Missing dependency | Install required package, check Python version |

### Debug Mode

```python
from redos.integrations import get_provider

# Enable debug logging
provider = get_provider("openai", api_key="sk-...", debug=True)

# Or set environment variable
export REDOS_DEBUG=1

# View debug output
# - Request/response headers
# - Full API payloads
# - Token usage details
# - Error stack traces
```

### Integration Logs

All integrations log to the RedOS observability stack:

```json
{
  "integration": "openai",
  "operation": "chat_completion",
  "model": "gpt-4o",
  "success": true,
  "latency_ms": 842,
  "tokens_used": 350,
  "cost_usd": 0.0175,
  "error": null,
  "timestamp": "2024-01-15T10:30:00Z",
  "organization_id": "org_oid",
  "campaign_id": "camp_oid",
  "request_id": "req_abc123"
}
```

## API Reference

### `redos.integrations.get_provider(provider_name, **kwargs)`

Get a configured AI provider client.

```python
from redos.integrations import get_provider

client = get_provider(
    "openai",
    api_key="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    model="gpt-4o",
    debug=False,
)
```

### `redos.integrations.agent_framewares.get_framework(framework_name, **kwargs)`

Get a configured agent framework client.

```python
from redos.integrations.agent_frameworks import get_framework

client = get_framework(
    "autogpt",
    api_key="sk-...",
    reddos_api="https://api.redos.io",
    reddos_key="redos_key",
)
```

### `redos.integrations.rag.get_rag_system(rag_name, **kwargs)`

Get a configured RAG system client.

```python
from redos.integrations.rag import get_rag_system

rag = get_rag_system(
    "llamaindex",
    llm="ollama:llama3:8b",
    vector_store="chroma",
    index_name="my-index",
)
```

### `redos.integrations.custom.APIClient(config)`

Create a custom API client from configuration.

```python
from redos.integrations.custom import APIClient

client = APIClient(
    config={
        "salesforce": {
            "base_url": "https://api.salesforce.com",
            "auth_type": "oauth2",
        }
    }
)
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01-15 | Initial integration documentation |
| 1.1.0 | 2024-02-01 | Added Ollama and MCP support |
| 1.2.0 | 2024-03-01 | Added agent framework integrations |
| 1.3.0 | 2024-04-01 | Added RAG system support |
| 1.4.0 | 2024-05-01 | Added custom API integrations |
| 2.0.0 | 2026-08-20 | Comprehensive documentation overhaul |