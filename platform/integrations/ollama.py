# RedOS Ollama Integration

## Overview

Integration with Ollama for running local LLMs. Supports Llama 3, Mixtral, Phi-3, and other
models via the Ollama runtime. Ideal for air-gapped environments and data sovereignty.

## Configuration

```yaml
# RedOS Ollama config
provider: ollama
base_url: http://localhost:11434
models:
  primary: llama3:8b
  fallback: mixtral:7b
  embedding: nvidia/nvidiartl:1b
temperature: 0.7
timeout: 120
max_retries: 3
```

## API Client

```python
from redos.integrations.ollama import OllamaClient

client = OllamaClient(
    base_url="http://localhost:11434",
    model="llama3:8b",
    temperature=0.7,
    timeout=120,
)

# Chat completion
response = client.chat(
    messages=[{"role": "user", "content": "Generate attack payload"}],
    options={
        "temperature": 0.7,
        "num_predict": 4096,
    }
)

# Embedding (if model supports it)
embedding = client.embed(
    input="indirect prompt injection text"
)

# List available models
models = client.list_models()
print([m['name'] for m in models['models']])

# Generate text
response = client.generate(
    prompt="You are a red teamer...",
    options={"temperature": 0.7, "num_predict": 512}
)
```

## Supported Models

| Model Size | Context | Download | Best For |
|-----------|---------|----------|----------|
| `llama3:8b` | 8K | ~5GB | Balanced performance |
| `llama3:70b` | 8K | ~40GB | Maximum capability |
| `mixtral:8x7b` | 32K | ~25GB | Complex reasoning |
| `phi3:3.8b` | 128K | ~2GB | Fast, efficient |
| `nemotron:70b` | 8K | ~40GB | Reasoning tasks |

## Local Tool Use

```python
from redos.integrations.ollama import OllamaClient

client = OllamaClient(...)

# Tool use with local model
response = client.chat(
    messages=[{"role": "user", "content": "Search for vulnerability info"}],
    options={"tools": [
        {
            "name": "search_cve",
            "description": "Search CVE database",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string"},
                    "query": {"type": "string"}
                }
            }
        }
    ]}
)
```

## Offline & Air-Gapped Operation

### Complete Offline Mode

```bash
# Pull all required models
ollama pull llama3:8b
ollama pull mixtral:7b
ollama pull nvidia/nvidiartl:1b

# Start Ollama server (no internet required)
ollama serve

# Verify models
ollama list

# Run RedOS with local AI
REDOS_AI_PROVIDER=ollama REDOS_API_KEY=local ollama serve
```

### No Data Leakage Guarantee

- All model inference happens locally
- No API calls leave the infrastructure
- Embeddings generated on-premises
- Perfect for classified/sensitive environments

### Resource Requirements

| Model | RAM | VRAM | Disk | CPU Cores |
|-------|-----|------|------|-----------|
| `llama3:8b` | 8GB | 0GB | 5GB | 2 |
| `llama3:70b` | 50GB | 40GB | 40GB | 8 |
| `mixtral:8x7b` | 50GB | 0GB | 25GB | 8 |
| `phi3:3.8b` | 5GB | 0GB | 2GB | 2 |

## Tool Use & Function Calling

```python
from redos.integrations.ollama import OllamaClient

client = OllamaClient(...)

# Note: Ollama tool use varies by model version
response = client.chat(
    messages=[{"role": "user", "content": "Execute attack step"}],
    # Tool support depends on model
)
```

## Quota Management

| Limit Type | Default | Description |
|-----------|---------|-------------|
| Requests per minute | 60 | Configurable per org |
| Tokens per request | 4096 | Model-dependent |
| Concurrent requests | 10 | Per instance |
| Context window | Model max | Llama3: 8K, etc. |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama host URL |
| `OLLAMA_MODEL` | `llama3:8b` | Default model name |
| `OLLAMA_TIMEOUT` | `120` | Request timeout (seconds) |
| `OLLAMA_NUM_PREDICT` | `4096` | Max tokens to generate |
| `OLLAMA_TEMPERATURE` | `0.7` | Sampling temperature |
| `OLLAMA_NUM_CTX` | `8192` | Context window size |
| `OLLAMA_VERIFY_SSL` | `false` | For self-signed certs |
| `OLLAMA_NO_MODLS_OFF` | `false` | Allow model offloading |

## Performance Optimization

### Context Caching

```python
from redos.integrations.ollama import OllamaClient

client = OllamaClient(...)

# Cache repeated queries
cache = {}

def cached_chat(messages, temperature=0.7):
    cache_key = hash(str(messages))
    if cache_key in cache:
        return cache[cache_key]
    
    response = client.chat(messages, options={"temperature": temperature})
    cache[cache_key] = response
    return response
```

### Batch Inference

```python
from redos.integrations.ollama import OllamaClient

client = OllamaClient(...)

# Batch process multiple prompts
prompts = [
    "Generate attack step 1",
    "Generate attack step 2",
    "Generate attack step 3",
]

results = []
for prompt in prompts:
    result = client.chat(messages=[{"role": "user", "content": prompt}])
    results.append(result)
```

## Security & Isolation

### Container-Run Ollama

```yaml
# Docker run with resource limits
docker run -d \
  --name ollama \
  --gpus all \
  --memory 50g \
  --cpus 8 \
  -v ollama-data:/root/.ollama \
  ollama/ollama
```

### Model Verification

```bash
# Verify model integrity
ollama verify llama3:8b

# Check model size
ollama size llama3:8b

# List all models
ollama list
```

## LlamaIndex / RAG Integration

```python
from redos.integrations.ollama import OllamaClient
from llama_index.core import VectorStoreIndex, Document

client = OllamaClient(model="llama3:8b")

# Create index from documents
documents = [Document(text="...")]
index = VectorStoreIndex.from_documents(documents)

# Query with Ollama
query_engine = index.as_query_engine(llm=client)

response = query_engine.query(
    "What are the prompt injection vectors?"
)
```

## Local Model Fine-tuning

```bash
# LoRA fine-tuning example
ollama run llama3:8b "Please rewrite this prompt to be more secure..."

# Custom model creation
ollama create redos-redteam \
  -f Modelfile

# Modelfile example
FROM llama3:8b
PARAMETER temperature 0.7
PARAMETER num_ctx 8192
SYSTEM You are a red teamer conducting security assessments.
EXAMPLE User: "Test model"
Assistant: "Understood, I'm ready for secure security testing."
```

## Fallback Orchestration

```python
from redos.integrations.ollama import OllamaClient
from redos.integrations.openai import OpenAIClient

ollama = OllamaClient(model="llama3:8b")
openai = OpenAIClient(model="gpt-4o")

def query_with_fallback(prompt):
    """Try Ollama first, fall back to OpenAI"""
    try:
        response = ollama.chat(messages=[{"role": "user", "content": prompt}])
        return response
    except Exception as e:
        # Fall back to OpenAI
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}]
        )
        return response
```

## Ollama Compatibility Table

| Feature | Supported | Notes |
|---------|-----------|-------|
| `chat completions` | ✅ | Full support |
| `tool use` | ⚠️ | Model-dependent |
| `embeddings` | ⚠️ | Some models |
| `streaming` | ✅ | SSE support |
| `context window` | ✅ | Model-dependent |
| `system prompt` | ✅ | Full support |
| `temperature` | ✅ | Full support |
| `num_predict` | ✅ | Max tokens |
| `mixture of experts` | ❌ | Not supported |

## Local AI Red Teaming Example

```python
from redos.integrations.ollama import OllamaClient
from redos.integrations.rag import RAGSystem
import json

client = OllamaClient(model="llama3:8b")
rag = RAGSystem(client=client, vector_store="local-chroma")

# Full offline red team campaign step
def offline_attack_step(target_description):
    # 1. Retrieve relevant documents
    results = rag.search(f"attack {target_description}", top_k=5)
    
    # 2. Generate attack payload via local LLM
    prompt = f"""
    Target: {target_description}
    Context: {results['documents']}
    Generate an indirect prompt injection payload.
    """
    response = client.chat(messages=[{"role": "user", "content": prompt}])
    payload = response['message']['content']
    
    # 3. Store evidence
    evidence = {
        "type": "model_output",
        "content": payload,
        "model": "llama3:8b",
        "context_documents": results['documents'],
    }
    
    return payload, evidence
```