# RedOS Agent Frameworks Integration

## Overview

Integration with popular agent frameworks for automated red teaming operations. Supports
autonomous agents that can plan, execute, and iterate on attack campaigns through
the RedOS platform.

## Supported Frameworks

| Framework | Version | Language | Key Features |
|-----------|---------|----------|-------------|
| **AutoGPT** | v0.2+ | Python | Autonomous GPT-4 agent, goal pursuit, memory |
| **BabyAGI** | v1.0+ | Python | Task-driven agent, vector-based task memory |
| **LangGraph** | v0.1+ | Python | Cyclical graphs, stateful agents, persistence |
| **CrewAI** | v0.1+ | Python | Role-playing agents, hierarchical planning |
| **Microsoft Autogen** | v0.1+ | Python | Multi-agent conversation, LLM orchestration |
| **LangChain** | v0.1+ | Python | Tool use, agents, chains, memory |

## AutoGPT Integration

```python
from redos.integrations.agent_frameworks import AutoGPTClient
from redos.models import Finding, Evidence, Campaign

# Initialize AutoGPT with RedOS integration
client = AutoGPTClient(
    api_key="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    reddos_api="https://api.redos.io",
    reddos_api_key="redos_key_xxx",
    goal="Identify and report security vulnerabilities",
    memory_size=100,
)

# Run autonomous red team cycle
result = client.run_cycle()

# Campaign creation
campaign = client.create_campaign(
    target_description="RAG system with document retrieval",
    objectives=["Find prompt injection vectors", "Extract test credentials"],
    budget="100",  # API budget in dollars
    timeline="24h",
)

# Monitor campaign progress
for update in client.monitor_campaign(campaign.id):
    print(f"Step: {update['step']}")
    print(f"Findings: {update['findings']}")
    if update['blocked']:
        print("Campaign blocked by gates")
        break
```

### AutoGPT Memory Management

```python
from redos.integrations.agent_frameworks import AutoGPTClient

client = AutoGPTClient(...)

# Remember a finding
client.remember({
    "type": "finding",
    "content": "Prompt injection via RAG context",
    "severity": "CRITICAL",
    "evidence": "model output shows injection",
})

# Recall similar past findings
similar = client.recall({"type": "finding", "severity": "CRITICAL"})
for f in similar:
    print(f"Similar finding: {f['content'][:100]}...")
```

### AutoGPT Goal Pursuit

```python
client = AutoGPTClient(
    goal="Identify security vulnerabilities in RAG systems",
    sub_goals=[
        "Find prompt injection vectors",
        "Extract credentials from context",
        "Map attack surface",
    ],
    constraints=[
        "Do not execute destructive commands",
        "Operate within authorized scope",
        "Document all findings with evidence",
    ],
)

# Agent will autonomously break down goals into sub-tasks
result = client.run_cycle()
```

## BabyAGI Integration

```python
from redos.integrations.agent_frameworks import BabyAGIClient
from redos.database import Session
from redos.models import Finding

client = BabyAGIClient(
    api_key="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    reddos_api="https://api.redos.io",
    reddos_key="redos_key_xxx",
)

# Task creation and execution
tasks = [
    "Identify prompt injection vectors in RAG system",
    "Test tool usage for document retrieval",
    "Extract any PII found in context",
    "Document findings with evidence",
]

# BabyAGI loop
while True:
    task = client.next_task()
    
    if not task:
        break  # No more tasks
    
    result = client.execute_task(task)
    
    # Create finding if vulnerability discovered
    if result.get("vulnerability_found"):
        finding = Finding(
            title=f"Vulnerability: {task}",
            severity=result.get("severity", "MEDIUM"),
            description=result.get("description", ""),
            execution_id=result.get("execution_id"),
            evidence=[
                Evidence(
                    type="model_output",
                    content=result.get("output", ""),
                )
            ],
        )
        # Save to RedOS
        client.save_finding(finding)
```

### BabyAGI Task Prioritization

```python
from redos.integrations.agent_frameworks import BabyAGIClient

client = BabyAGIClient(...)

# Priority queue based on severity and impact
prioritized = client.prioritize_tasks(tasks)

for task in prioritized:
    # Execute based on priority
    result = client.execute_task(task)
    client.save_result(task.id, result)
```

## LangGraph Integration

```python
from redos.integrations.agent_frameworks import LangGraphClient
from redos.database import Session
from redos.models import Finding, Campaign

client = LangGraphClient(
    api_key="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    reddos_api="https://api.redos.io",
    reddos_key="redos_key_xxx",
    model="gpt-4o",
    # Define the state graph
    state_schema={
        "campaign_id": str,
        "current_step": str,
        "findings": list,
        "execution_history": list,
    },
)

# Define the graph edges (transitions)
graph_edges = [
    ("planning", "execution"),
    ("execution", "analysis"),
    ("analysis", "findings"),
    ("findings", "regression"),
    ("regression", "completed"),
]

# Add edges to graph
for edge in graph_edges:
    client.add_edge(*edge)

# Run campaign through graph
state = {"campaign_id": "camp_123", "current_step": "planning"}
final_state = client.run_graph(state)

# Access findings from final state
findings = final_state.get("findings", [])
for finding in findings:
    print(f"Finding: {finding.title} - {finding.severity}")
```

### LangGraph State Persistence

```python
from redos.integrations.agent_frameworks import LangGraphClient
from redos.database import engine
from redos.models import Finding
from sqlmodel import Session as DBSession

client = LangGraphClient(...)

# Persist state to database at each transition
def persist_state(state, session: DBSession):
    # Store current graph state
    from redos.models import CampaignState
    cs = CampaignState(
        campaign_id=state.get("campaign_id"),
        current_step=state.get("current_step"),
        json_state=json.dumps(state),
        updated_at=datetime.utcnow(),
    )
    session.add(cs)
    session.commit()

# Register persistence hook
client.on_transition(persist_state)
```

### LangGraph with Human-in-the-Loop

```python
from redos.integrations.agent_frameworks import LangGraphClient

client = LangGraphClient(...)

# Graph with approval checkpoints
graph = client.create_checkpoint_graph([
    ("planning", "approve_plan"),
    ("execution", "approve_execution"),
    ("findings", "review_findings"),
    ("regression", "approve_regression"),
])

# Each checkpoint pauses and waits for human approval
state = client.run_with_checkpoints(graph, initial_state)

# approval_required will be True at each checkpoint
# Agent pauses until human responds
```

## CrewAI Integration

```python
from redos.integrations.agent_frameworks import CrewAIClient
from redos.models import Finding, Campaign

client = CrewAIClient(
    api_key="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    reddos_api="https://api.redos.io",
    reddos_key="redos_key_xxx",
    # Define agent roles
    roles={
        "researcher": {
            "model": "gpt-4o",
            "description": "Researches attack vectors and collects intelligence",
        },
        "attacker": {
            "model": "gpt-4o",
            "description": "Executes attack steps and tests vulnerabilities",
        },
        "analyst": {
            "model": "gpt-4o",
            "description": "Analyzes findings and generates reports",
        },
        "remediator": {
            "model": "gpt-4o-mini",
            "description": "Generates remediation recommendations",
        },
    },
)

# Run crew
crew_result = client.run_crew(
    objective="Identify vulnerabilities in RAG system and report findings",
    # Agents automatically assigned by roles
)

# Access results
for finding in crew_result.findings:
    client.save_finding(finding)

for report in crew_result.reports:
    client.save_report(report)
```

### CrewAI Process Workflow

```python
client = CrewAIClient(...)

# Define processes
processes = {
    "sequential": {
        "description": "Agents work one after another",
        "execution": "sequential",
    },
    "hierarchical": {
        "description": "Senior agent oversees juniors",
        "execution": "hierarchical",
        "manager": "researcher",
    },
    "collaborative": {
        "description": "Agents collaborate throughout",
        "execution": "collaborative",
    },
}

result = client.run_crew(
    objective="Security assessment",
    process=processes["collaborative"],
)
```

## Microsoft AutoGen Integration

```python
from redos.integrations.agent_frameworks import AutoGenClient
from redos.models import Finding

client = AutoGenClient(
    api_key="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    reddos_api="https://api.redos.io",
    reddos_key="redos_key_xxx",
    # Configure multiple agents
    agents={
        "user_proxy": {
            "role": "human_proxy",
            "human_input": True,  # Requires human input
        },
        "assistant_agent": {
            "role": "red_teamer",
            "model": "gpt-4o",
            "human_like": True,
        },
        "critic_agent": {
            "role": "security_critic",
            "model": "gpt-4o",
            "evaluates": "findings",
        },
    },
)

# Start multi-agent conversation
client.start_conversation(
    topic="Conduct red team assessment of RAG system",
    max_turns=20,  # Maximum conversation turns
)

# Retrieve findings generated during conversation
findings = client.retrieve_findings()
for finding in findings:
    print(f"Finding: {finding.title} ({finding.severity})")
```

### AutoGen Conversation Patterns

```python
from redos.integrations.agent_frameworks import AutoGenClient

client = AutoGenClient(...)

# Pattern 1: Two-agent discussion
client.initiate_discussion(
    agents=["assistant_agent", "critic_agent"],
    topic="Evaluate prompt injection risks",
    turns=5,
)

# Pattern 3: Group discussion with human
client.initiate_group_discussion(
    agents=["user_proxy", "assistant_agent", "critic_agent"],
    topic="Full red team assessment",
    human_turns_required=True,
)
```

## LangChain Integration

```python
from redos.integrations.agent_frameworks import LangChainClient
from redos.models import Finding
from langchain_core.tools import Tool

client = LangChainClient(
    llm="gpt-4o",
    reddos_api="https://api.redos.io",
    reddos_key="redos_key_xxx",
)

# Define LangChain tools
tools = [
    Tool(
        name="search_redos",
        func=lambda q: client.query_redos(q),
        description="Search RedOS for existing findings",
    ),
    Tool(
        name="create_finding",
        func=lambda title, severity, desc: client.save_finding(
            Finding(title=title, severity=severity, description=desc)
        ),
        description="Create a new finding in RedOS",
    ),
    Tool(
        name="execute_attack",
        func=lambda step: client.execute_attack_step(step),
        description="Execute an attack campaign step",
    ),
]

# Set up agent with tools
agent = client.setup_agent(
    system_prompt="You are a red teamer conducting security assessments.",
    tools=tools,
)

# Run agent
response = agent.invoke({"input": "Identify prompt injection vectors in our RAG system"})
print(response["output"])
```

### LangChain Agent Types

| Agent Type | Description | Best For |
|-----------|-------------|----------|
| `zero-shot-react-description` | ReAct without prior examples | Quick setup |
| `zero-shot-cot` | Chain-of-thought without examples | Reasoning tasks |
| `agent` | With tool use and memory | General purpose |
| `structured_chat_zero_shot` | Structured output | JSON/output parsing |
| `function_calling` | With function calling | API integrations |

## Agent Framework Comparison

| Framework | Autonomy | Tool Use | Memory | Best For | Cost |
|-----------|----------|----------|--------|----------|------|
| **AutoGPT** | High | ✅ | Vector | Autonomous campaigns | $$$ |
| **BabyAGI** | Medium | ⚠️ | Task list | Step-by-step tasks | $ |
| **LangGraph** | High | ✅ | Graph state | Complex workflows | $$$ |
| **CrewAI** | Medium | ✅ | Role-based | Team-based attacks | $$ |
| **AutoGen** | High | ✅ | Conversation | Multi-agent collab | $$$ |
| **LangChain** | Medium | ✅ | Configurable | Custom tools | $ |

## Environment Variables (Agent Frameworks)

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_API_KEY` | required | LLM API key |
| `AGENT_REDDOS_API` | `https://api.redos.io` | RedOS backend URL |
| `AGENT_REDDOS_KEY` | required | RedOS API key |
| `AGENT_MODEL` | `gpt-4o` | Default LLM model |
| `AGENT_TEMPERATURE` | `0.7` | Sampling temperature |
| `AGENT_MAX_TOKENS` | `4096` | Max completion tokens |
| `AGENT_MAX_ITERATIONS` | `10` | Max agent loop iterations |
| `AGENT_MEMORY_SIZE` | `100` | Memory vector store size |
| `AGENT_HUMAN_IN_LOOP` | `false` | Require human approval |
| `AGENT_PARALLEL_EXECUTION` | `false` | Run agents in parallel |

## Safety & Oversight

### Human-in-the-Loop Configuration

```python
from redos.integrations.agent_frameworks import AutoGPTClient

client = AutoGPTClient(
    human_in_loop=True,
    max_iterations=5,  # Stop after 5 iterations without approval
    approval_threshold=0.7,  # Confidence threshold for auto-approval
)

# Agent will pause at each iteration and require:
# - Human approval to continue
# - Or stop if iteration limit reached
```

### Risk Mitigation

```python
from redos.integrations.agent_frameworks import AutoGPTClient

client = AutoGPTClient(
    safety_constraints={
        "max_api_calls_per_hour": 100,
        "forbidden_commands": ["rm -rf /", "dd", "format", "sudo"],
        "required_approval_findings": ["CRITICAL", "HIGH"],
        "max_budget_usd": 50,  # Stop if API costs exceed $50
    },
    # Agent will enforce these constraints automatically
)
```