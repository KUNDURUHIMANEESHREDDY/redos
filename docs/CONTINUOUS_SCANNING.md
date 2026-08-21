# RedOS Continuous Scanning

## Overview

RedOS continuous scanning automates security assessments on recurring schedules and event-driven
triggers. The scheduling system integrates with the fleet management and campaign execution
pipeline to provide continuous security posturing.

## Schedule Types

| Schedule | Trigger | Interval | Use Case |
|----------|---------|----------|----------|
| **Hourly** | Cron schedule | Every hour | Real-time threat model updates, short-lived campaign re-execution |
| **Daily** | Cron schedule | Every 24h | End-of-day security posture summary, overnight scanning |
| **Weekly** | Cron schedule | Every 7 days | Weekly regression scan, comprehensive posture assessment |
| **On Deployment** | CI/CD pipeline | On deploy | Ensure no regressions introduced by deployment |
| **On Model Change** | Webhook / event | When model updates | Re-scan with new model capabilities/limitations |
| **On Prompt Change** | Webhook / event | When prompt updated | Re-evaluate prompt injection vulnerabilities |
| **On Tool Change** | Webhook / event | When tooling updates | Re-scan with new tool capabilities |
| **On RAG Update** | Webhook / event | When RAG index changes | Re-evaluate retrieval-augmented generation vulnerabilities |
| **CI Event** | CI/CD system | On pipeline event | Integrate security scanning into development workflow |

## Schedule Configuration

### Cron Expressions

```yaml
# Schedule configuration in organization settings
schedules:
  hourly:
    enabled: true
    cron: "0 * * * *"  # every hour at minute 0
    targets: ["all"]  # or specific target IDs
    campaigns: ["critical_gates", "regression_scan"]
    concurrency: 4  # max parallel executions
    
  daily:
    enabled: true
    cron: "0 2 * * *"  # daily at 2 AM
    targets: ["all"]
    campaigns: ["full_assessment", "evidence_review"]
    concurrency: 8
    
  weekly:
    enabled: true
    cron: "0 3 * * 0"  # weekly Sunday at 3 AM
    targets: ["all"]
    campaigns: [" comprehensive_assessment", "compliance_report"]
    concurrency: 12
    
  on_deployment:
    enabled: true
    trigger: "ci_cd"
    campaigns: ["regression_gate"]
    concurrency: 2
    
  on_model_change:
    enabled: true
    trigger: "model_registry"
    campaigns: ["model_switch_scan"]
    concurrency: 1
    
  on_prompt_change:
    enabled: true
    trigger: "prompt_registry"
    campaigns: ["prompt_injection_scan"]
    concurrency: 1
    
  on_tool_change:
    enabled: true
    trigger: "tool_registry"
    campaigns: ["tool_capability_scan"]
    concurrency: 2
    
  on_rag_update:
    enabled: true
    trigger: "rag_registry"
    campaigns: ["rag_effectiveness_scan"]
    concurrency: 2
    
  ci_event:
    enabled: true
    trigger: "ci_pipeline"
    campaigns: ["ci_gate"]
    concurrency: 4
```

### Schedule Execution Flow

```mermaid
flowchart TD
    A[Schedule Trigger] --> B{Check Org Enabled}
    B -->|No| F[Skip - Log Skipped]
    B -->|Yes| C{Check Targets Enabled}
    C -->|No| F[Skip - Log Skipped]
    C -->|Yes| D[Filter Targets by Schedule]
    D --> E[Create Campaign(s)]
    E --> F[Gate Evaluation]
    F -->|PASS| G[Queue Campaign]
    F -->|BLOCK| H[Log Blocking Reason]
    H --> F[Skip - Gate Prevents]
    G --> I[Worker Pool Assignment]
    I --> J[Execution Start]
    J --> K[Live Execution Streaming]
    K --> L[Evidence Collection]
    L --> M[Finding Generation]
    M --> N[Posture Update]
    N --> O[Schedule Complete]
    O --> P[Notification]
    P --> F[Log Completion]
```

### Target Filtering by Schedule

Schedules can filter which targets within an organization are included:

```yaml
# Example: Daily scan only critical targets
schedules:
  daily:
    targets:
      filter: "severity_status: critical"  # only CRITICAL/HIGH targets
      exclude: ["target_db_backup"]  # exclude specific targets
    
    # Or: include specific targets only
    include:
      - "target_production_rag"
      - "target_dev_api"
      - "target_external_service"
```

### Campaign Generation by Schedule Type

#### Hourly Campaigns

```python
from redos.scheduler import ScheduleManager

schedule = ScheduleManager(org_id="org_123")

# Hourly scan - focused assessment
campaigns = await schedule.generate_campaigns(
    schedule_type="hourly",
    targets_filter="recently_active",  # targets scanned in last 24h
    campaigns=[
        "quick_gates",       # fast gate evaluation
        "prompt_injection",  # focused attack type
    ],
    concurrency=4,
)

# Typical hourly campaign output:
# - 5-10 executions started
# - 2-4 findings generated
# - Posture update within 30 minutes
```

#### Daily Campaigns

```python
# Daily scan - comprehensive assessment
campaigns = await schedule.generate_campaigns(
    schedule_type="daily",
    targets_filter="all",
    campaigns=[
        "full_assessment",
        "evidence_review",
        "regression_check",
    ],
    concurrency=8,
)

# Typical daily campaign output:
# - 20-50 executions started
# - 10-25 findings generated
# - Posture update within 2 hours
# - Compliance mapping applied
```

#### Weekly Campaigns

```python
# Weekly scan - deep assessment
campaigns = await schedule.generate_cermany(
    schedule_type="weekly",
    targets_filter="all",
    campaigns=[
        "comprehensive_assessment",
        "compliance_report",
        "regression_analysis",
    ],
    concurrency=12,
)

# Typical weekly campaign output:
# - 50-100+ executions started
# - 30-60+ findings generated
# - Full posture recalculation
# - Compliance report generation
# - Remediation priority ranking
```

#### On-Demand Campaigns

##### On Deployment

```python
# Triggered by CI/CD pipeline
await schedule.trigger(
    schedule_type="on_deployment",
    campaign_type="regression_gate",
    deployment_id="deploy_2024_01_15",
    source="github_actions",
)

# CI/CD integration example:
# .github/workflows/security-scan.yml
# - On PR merge to main
# - Trigger on_deployment schedule
# - Block merge if gates fail
```

##### On Model Change

```python
# When model is updated in the registry
await schedule.trigger(
    schedule_type="on_model_change",
    campaign_type="model_switch_scan",
    old_model="gpt-4o",
    new_model="gpt-4o-mini",
    source="model_registry_webhook",
)

# Re-scan with new model to evaluate:
# - Changed capabilities
# - Different vulnerability detection
# - Altered false positive/negative rates
```

##### On Prompt Change

```python
# When prompt is updated in the system
await schedule.trigger(
    schedule_type="on_prompt_change",
    campaign_type="prompt_injection_scan",
    old_prompt_version="v1.2",
    new_prompt_version="v1.3",
    source="prompt_registry_webhook",
)

# Re-evaluate:
# - New prompt injection vectors
# - Changed vulnerability surface
# - Updated remediation requirements
```

##### On Tool Change

```python
# When attack tools are updated
await schedule.trigger(
    schedule_type="on_tool_change",
    campaign_type="tool_capability_scan",
    old_tool_version="v2.1",
    new_tool_version="v2.2",
    source="tool_registry_webhook",
)

# Re-scan with updated tools to evaluate:
# - New attack vectors
 # - Changed capability surface
# - Updated detection rules
```

##### On RAG Update

```python
# When RAG index is updated
await schedule.trigger(
    schedule_type="on_rag_update",
    campaign_type="rag_effectiveness_scan",
    old_index_version="v1.2",
    new_index_version="v1.3",
    source="rag_registry_webhook",
)

# Re-assess:
# - Retrieval effectiveness
 # - Changed attack surface
 # - Updated evidence quality
```

##### CI Event

```python
# When CI pipeline completes
await schedule.trigger(
    schedule_type="ci_event",
    campaign_type="ci_gate",
    pipeline_id="github_actions_123",
    pr_number=123,
    source="github_actions",
)

# Integration example:
# - On every PR
# - Security gates evaluated
# - Block merge if critical findings
# - Comment PR with results
```

### Scheduler API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/schedules` | List all schedules for organization |
| `POST` | `/api/v1/schedules` | Create new schedule |
| `GET` | `/api/v1/schedules/{schedule_id}` | Get schedule details |
| `PUT` | `/api/v1/schedules/{schedule_id}` | Update schedule |
| `DELETE` | `/api/v1/schedules/{schedule_id}` | Delete schedule |
| `POST` | `/api/v1/schedules/{schedule_id}/trigger` | Manually trigger schedule |
| `GET` | `/api/v1/schedules/{schedule_id}/status` | Get schedule execution status |
| `GET` | `/api/v1/schedules/{schedule_id}/history` | Get execution history |

### Scheduler Orchestration

```python
from redos.scheduler import ScheduleManager, ScheduleOrchestrator

# Initialize scheduler
scheduler = ScheduleManager(org_id="org_123")

# Orchestrator manages concurrent execution
orchestrator = ScheduleOrchestrator(
    scheduler=scheduler,
    max_concurrent=12,
    worker_pool="default",
    queue_type="priority",
)

# Orchestrate schedule execution
results = await orchestrator.run_schedule(
    schedule_id="daily_2024_01_15",
    force_rerun=False,
)

# Results include:
# - campaigns_created: 8
# - campaigns_executed: 8
# - findings_generated: 15
# - posture_updated: true
# - duration_minutes: 45
# - errors: []
```