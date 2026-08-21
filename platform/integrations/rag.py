# RedOS RAG Systems Integration

## Overview

Integration with Retrieval-Augmented Generation (RAG) systems for attack campaigns that
leverage document retrieval, knowledge bases, and context-aware AI operations.

## Supported RAG Systems

| System | Vector Store | Embedding | Key Features |
|--------|-------------|-----------|-------------|
| **LlamaIndex** | Pinecone, Weaviate, Chroma, Qdrant | OpenAI, Olloma, NVIDIA | Modular, extensive docs, Python-first |
| **LangChain** | Pinecone, Weaviate, Chroma, Milvus | OpenAI, Ollama, Cohere | Extensive tooling, agent integration |
| **Weaviate** | Weaviate (native) | Cohere, OpenAI, SentenceTransformers | Native vector search, Q&A |
| **Pinecone** | Pinecone (managed) | OpenAI, Cohere, NVIDIA | Managed service, scalability |
| **Chroma** | Chroma (local) | SentenceTransformers, OpenAI | Local-first, easy setup |
| **Qdrant** | Qdrant (managed) | OpenAI, CLIP, multimodal | Filtering, hybrid search |

## LlamaIndex Integration

```python
from redos.integrations.rag import LlamaIndexRAG
from redos.integrations.ollama import OllamaClient
from llama_index.core import VectorStoreIndex, Document, Settings

# Initialize Ollama as LLM
llm = OllamaClient(model="llama3:8b").as_llm()

# Initialize embedding
Settings.embed_model = OllamaClient(model="nvidia/nvidiartl:1b").as_embedding()

# Load documents
documents = [
    Document(text="Prompt injection via retrieved context pattern 1..."),
    Document(text="RAG system architecture and components..."),
    Document(text="Prompt injection detection methods..."),
]

# Create index
index = VectorStoreIndex.from_documents(documents)

# Create query engine with Ollama LLM
query_engine = index.as_query_engine(llm=llm)

# Search for attack vectors
response = query_engine.query(
    "What are prompt injection vectors in RAG systems?"
)

print(response.response)
print(f"Source nodes: {response.source_nodes}")
```

### LlamaIndex with RedOS

```python
from redos.integrations.rag import LlamaIndexRAG
from redos.models import Finding, Evidence, Campaign

rag = LlamaIndexRAG(
    llm="ollama:llama3:8b",
    embed_model="ollama:nvidia/nvidiartl:1b",
    vector_store="chroma",  # or "pinecone", "weaviate", etc.
    index_name="redteam-knowledge",
    reddos_api="https://api.redos.io",
    reddos_key="redos_key_xxx",
)

# Campaign: Search for injection vectors
vectors = rag.search_attack_vectors(
    target_type="RAG system",
    vulnerability="prompt_injection",
    top_k=10,
)

# Store findings
for vector in vectors:
    finding = Finding(
        title=f"Prompt injection vector: {vector['title']}",
        severity=vector.get('severity', 'MEDIUM'),
        description=vector.get('description', ''),
        execution_id=vector.get('execution_id'),
        evidence=[
            Evidence(
                type="retrieved_document",
                content=vector.get('content', ''),
                metadata={
                    "source": vector.get('source'),
                    "similarity": vector.get('similarity'),
                    "document_id": vector.get('document_id'),
                }
            ),
        ],
    )
    # Save to RedOS
    rag.save_finding(finding)
```

### Advanced RAG Query Patterns

```python
from redos.integrations.rag import LlamaIndexRAG

rag = LlamaIndexRAG(...)

# Query with context augmentation
response = rag.query(
    question="How do prompt injections work in RAG systems?",
    additional_context={
        "target_description": "vector search system with OpenAI embeddings",
        "attack_phase": "reconnaissance",
    },
    template="attack_analysis",
)

# Nested retrieval (retrieve, then re-retrieve)
deep_results = rag.deep_retrieve(
    initial_query="prompt injection techniques",
    max_depth=3,
    threshold=0.7,
)

# Query with metadata filtering
filtered = rag.filtered_query(
    question="What are injection techniques?",
    filters={
        "document_type": "technical",
        "date_range": ["2023-01-01", "2024-12-31"],
        "severity": ["CRITICAL", "HIGH"],
    },
)
```

### RAG System Migration

```python
from redos.integrations.rag import LlamaIndexRAG

# Migrate from Pinecone to Weaviate
rag = LlamaIndexRAG(
    llm="ollama:llama3:8b",
    vector_store="weaviate",  # New vector store
    index_name="redteam-knowledge-migrated",
)

# Export existing index data
existing_data = rag.export_index(
    format="json",
    include_embeddings=True,
)

# Import to new system
rag.import_index(
    data=existing_data,
    format="json",
    reset=True,  # Clear existing index first
)
```

## Weaviate Integration

```python
from redos.integrations.rag import WeaviateRAG
from redos.models import Finding

rag = WeaviateRAG(
    cluster_url="http://localhost:8080",
    auth_api_key="weaviate-secret",
    llm="ollama:llama3:8b",
    index_name="redteam-knowledge",
)

# Insert documents with classifications
documents = [
    {
        "content": "Prompt injection via retrieved context",
        "metadata": {
            "title": "Prompt Injection Pattern 1",
            "severity": "CRITICAL",
            "type": "attack_vector",
            "category": "prompt_injection",
        }
    },
]

rag.batch_insert(documents)

# Search with filters
results = rag.search(
    query="prompt injection",
    filters={
        "path": ["attack_vectors"],
        "classification": "CRITICAL",
        "tier": "1",
    },
    limit=10,
)

# Hybrid search (vector + keyword)
hybrid = rag.hybrid_search(
    query="prompt injection techniques",
    vector_weight=0.7,
    keyword_weight=0.3,
    alpha=0.5,
)
```

### Chroma Integration

```python
from redos.integrations.rag import ChromaRAG
from redos.integrations.ollama import OllamaClient

rag = ChromaRAG(
    persist_directory="./chroma-data",
    llm="ollama:llama3:8b",
    embedding="ollama:nvidia/nvidiartl:1b",
    collection_name="redteam-knowledge",
)

# Add documents with metadata
ids = rag.add([
    Document(page_content="Prompt injection via context..."),
    Document(page_content="RAG system design patterns..."),
    metadatas=[
        {"severity": "CRITICAL", "type": "attack_vector"},
        {"severity": "MEDIUM", "type": "defense_pattern"},
    ],
    ids=["inj-001", "def-001"],
])

# Natural language query
results = rag.query(
    "Show me CRITICAL prompt injection vectors",
    n_results=5,
)

# Update document metadata
rag.update_document(
    id="inj-001",
    metadata={"severity": "HIGH", "last_reviewed": "2024-01-15"},
)
```

### RAG Query Templates

```python
from redos.integrations.rag import LlamaIndexRAG

rag = LlamaIndexRAG(...)

# Predefined templates
templates = rag.get_templates()

# Use template for analysis
analysis = rag.query_template(
    template_name="attack_analysis",
    question="Analyze prompt injection risk for this RAG system:",
    system_prompt="You are a security analyst assessing RAG vulnerabilities.",
    user_context={
        "system_components": ["vector store", "embedding model", "LLM"],
        "deployment": "production",
        "data_sensitivity": "PII",
    },
)
```

### RAG Quality Metrics

```python
from redos.integrations.rag import LlamaIndexRAG

rag = LlamaIndexRAG(...)

# Evaluate RAG system quality
metrics = rag.evaluate(
    test_queries=[
        "What are prompt injection vectors?",
        "How to detect prompt injections?",
        "What are mitigation strategies?",
    ],
    reference_answers=[
        "Prompt injection vectors include...",
        "Detection methods include...",
        "Mitigations include...",
    ],
)

print(f"Precision: {metrics['precision']}")
print(f"Recall: {metrics['recall']}")
print(f"F1 Score: {metrics['f1_score']}")
print(f"Answer relevance: {metrics['answer_relevance']}")
```

### RAG System Monitoring

```python
from redos.integrations.rag import LlamaIndexRAG
from redos.observability import metrics

rag = LlamaIndexRAG(...)

# Track performance over time
metrics.increment("rag.queries_total")
metrics.gauge("rag.latency_ms", rag.last_latency_ms)
metrics.gauge("rag.retrieval_accuracy", rag.last_accuracy)

# Alert on degradation
if rag.last_accuracy < 0.7:
    # Send alert
    pass
```