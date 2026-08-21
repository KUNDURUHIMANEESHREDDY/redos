# RedOS Distributed Campaign Execution

## Overview

Distributed campaign execution provides production controls for running security assessments
across worker pools with proper queuing, priority, quotas, isolation, and concurrency management.

## Worker Pool Architecture

### Worker Pool Configuration

```yaml
# Worker pool configuration
worker_pools:
  default:
    max_workers: 10
    max_concurrent_campaigns: 5
    timeout_minutes: 1440  # 24 hours max execution
    resource_limits:
      cpu: "2"
      memory: "4Gi"
      disk: "10Gi"
    cost_limit_usd: 50.0  # monthly budget
    token_budget_million: 10  # million tokens per month
    priority: 5  # 1-10, 10 highest
    autoscaling:
      enabled: true
      min_workers: 3
      max_workers: 20
      scale_up_threshold: 80  # percent utilization
      scale_down_threshold: 30  # percent utilization
  
  high_priority:
    max_workers: 5
    max_concurrent_campaigns: 2
    timeout_minutes: 4320  # 72 hours
    resource_limits:
      cpu: "4"
      memory: "8Gi"
    cost_limit_usd: 200.0
    token_budget_million: 50
    priority: 10
  
  low_priority:
    max_workers: 3
    max_concurrent_campaigns: 1
    timeout_minutes: 720  # 12 hours
    resource_limits:
      cpu: "1"
      memory: "2Gi"
    cost_limit_usd: 10.0
    token_budget_million: 2
    priority: 1
```

### Worker Pool Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `worker_pool_id` | String | Unique pool identifier |
| `active_workers` | Integer | Currently running workers |
| `idle_workers` | Integer | Available workers |
| `concurrent_campaigns` | Integer | In-flight campaigns |
| `queued_campaigns` | Integer | Waiting in queue |
| `utilization_ratio` | Ratio | active / (active + idle) |
| `cost_today_usd` | Float | Accumulated cost |
| `tokens_used_today_million` | Float | Token consumption |
| `campaigns_completed_total` | Integer | Total completed |
| `campaigns_failed_total` | Integer | Total failed |
| `campaigns_cancelled_total` | Integer | Total cancelled |

### Distributed Execution Flow

```mermaid
flowchart TD
    A[Campaign Submission] --> B[Queue Entry]
    B ->|Priority| C[Worker Pool Selection]
    C ->|Available| D[Worker Assignment]
    D ->|Started| E[Execution Begin]
    E ->|Streaming| F[Live Updates]
    F ->|Completion| G[Result Collection]
    G ->|Handoff| I[Finding Generation]
    I ->|Provenance| J[Evidence Storage]
    J ->|Posture Update| K[Campaign Complete]
    K ->|Metrics| L[Worker Pool Update]
    
    %% Failure paths
    E ->|Timeout| M[Cancellation]
    M ->|Retry| G[Result Collection]
    E ->|Error| N[Error Handling]
    N ->|Retry| G[Result Collection]
    N ->|Backpressure| O[Queue Backoff]
    O ->|Retry Later| B[Queue Entry]
```

### Campaign Queue Prioritization

```python
from redos.distributed import CampaignQueue

queue = CampaignQueue(pool_name="default")

# Submit campaigns with priority
campaign_ids = await queue.submit([
    {"campaign_type": "critical_gates", "priority": 10},
    {"campaign_type": "regression_scan", "priority": 7},
    {"campaign_type": "prompt_injection", "priority": 9},
    {"campaign_type": "evidence_review", "priority": 3},
])

# Priority ordering (high to low):
# 1. Critical security gates (priority 10)
# 2. Prompt injection analysis (priority 9)  
# 3. Regression detection (priority 7)
# 4. Evidence review (priority 3)
# 5. Routine scanning (priority 1)

# Queue behavior:
# - High priority campaigns bypass lower priority wait
# - Configurable max wait time per priority level
# - Dynamic priority adjustment based on severity
# - Preemption: high priority can interrupt lower
```

### Tenant Isolation in Distributed Execution

```python
from redos.distributed import IsolationEnforcer

enforcer = IsolationEnforcer(org_id="org_456")

# Verify isolation before execution
is_isolated = await enforcer.verify_isolation(
    campaign_id="camp_abc123",
    target_id="target_def456",
    expected_org="org_456",
)

if not is_isolated:
    raise IsolationError(
        f"Campaign {campaign_id} targets org {expected_org} "
        f"but target belongs to different organization"
    )
```

## Quota Management

### Per-Organization Quotas

```yaml
# Quota configuration
quotas:
  organization_id: "org_456"
  monthly:
    campaigns: 500
    executions: 1000
    tokens_million: 100
    cost_usd: 200
    findings: 500
  daily:
    campaigns: 50
    executions: 100
    tokens_million: 10
    cost_usd: 20
    findings: 50
  per_target:
    campaigns_per_target: 10
    executions_per_target: 20
    tokens_million_per_target: 1
    findings_per_target: 5
```

### Quota Enforcement

```python
from redos.distributed import QuotaManager

quota = QuotaManager(org_id="org_456")

# Check before campaign execution
can_execute, quota_info = quota.check(
    campaigns=1,
    executions=1,
    tokens_million=0.1,
    findings=1,
)

if not can_execute:
    raise QuotaExceededError(
        f"Quota exceeded: {quota_info['reason']}"
        f"Available: {quota_info['available']}"
    )
```

### Quota Refill Schedule

```yaml
# Quota refill configuration
refill:
  campaigns:
    monthly: "1st of month, 500 added"
    daily: "midnight UTC, 50 added"
  executions:
    monthly: "1st of month, 1000 added"
    daily: "midnight UTC, 100 added"
  tokens_million:
    monthly: "1st of month, 100 added"
    daily: "midnight UTC, 10 added"
  cost_usd:
    monthly: "1st of month, 200 added"
  findings:
    monthly: "1st of month, 500 added"
```

## Concurrency Control

### Maximum Concurrent Campaigns

```python
from redos.distributed import ConcurrencyLimiter

limiter = ConcurrencyLimiter(pool_name="default", max_concurrent=5)

# Try to acquire concurrency slot
acquired = await limiter.acquire(
    campaign_id="camp_abc123",
    timeout_minutes=30,  # wait up to 30 minutes
)

if not acquired:
    raise ConcurrencyError(
        "Maximum concurrent campaigns reached"
        f"Current: {limiter.active_campaigns}"
        f"Limit: {limiter.max_concurrent}"
    )
```

### Concurrency Release

```python
# Release slot after completion
await limiter.release(campaign_id="camp_abc123")

# Or on error/retry
await limiter.release(campaign_id="camp_abc123", failed=True)
```

## Cancellation

### Campaign Cancellation Flow

```mermaid
flowchart TD
    A[Cancellation Request] --> B[Check Campaign State]
    B -->|Running| C[Send Interrupt Signal]
    B ->|Queued| D[Remove from Queue]
    B ->|Completed| E[Log - Already Complete]
    B ->|Failed| E[Log - Already Failed]
    
    C ->|Interrupt Acknowledged| E[Log - Interrupted]
    C ->|Timeout| M[Force Terminate]
    M -> E[Log - Force Terminated]
    
    E -> M[Update Campaign State]
    E -> M[Cleanup Resources]
    E -> M[Increment Cancelled Counter]
    E -> M[Return Control to caller]
```

### Cancellation API

```python
from redos.distributed import cancel_campaign

# Cancel specific campaign
result = await cancel_campaign(
    campaign_id="camp_abc123",
    reason="Organization priority change",
    fail_gracefully=True,  # wait for current step to complete
)

print(f"Campaign cancelled: {result['cancelled']}")
print(f"Final state: {result['state']}")
print(f"Cleanup: {result['cleanup_performed']}")
```

## Cost & Token Budget Enforcement

### Cost Monitoring

```python
from redos.distributed import CostMonitor

cost_monitor = CostMonitor(org_id="org_456")

# Real-time cost tracking
while campaign_running:
    cost = cost_monitor.current_cost()
    tokens = cost_monitor.current_tokens()
    
    if cost_monitor.exceeds_budget():
        # Auto-throttle or cancel
        await campaign.pause()
        await notify_budget_exceeded(cost, tokens)
```

### Token Budget Enforcement

```yaml
# Token budget configuration
token_budgets:
  monthly_million: 10  # 10 million tokens per month
  daily_million: 1     # 1 million tokens per day
  per_campaign_million: 0.1  # 0.1 million per campaign
  
# Enforcement actions
actions:
  on_warning_80_percent:
    - log_warning
    - notify_team
  on_critical_95_percent:
    - pause_campaigns
    - notify_admin
  on_exceeded_100_percent:
    - cancel_campaigns
    - restrict_new_campaigns
    - notify_admin_immediately
```

## Backpressure Handling

### Backpressure Signals

```python
from redos.distributed import BackpressureManager

backpressure = BackpressureManager(org_id="org_456")

# Monitor backpressure signals
signals = backpressure.check_signals()

if signals.overloaded:
    # Reduce acceptance rate
    new_acceptance_rate = max(0.1, signals.current_rate * 0.5)
    
    # Queue campaigns with delay
    await queue.set_acceptance_rate(new_acceptance_rate)
    
    # Notify stakeholders
    await notify(
        f"Backpressure active: {signals.reason}"
        f"Current utilization: {signals.utilization:.1f}%"
    )
```

### Backpressure Types

| Signal | Condition | Action |
|--------|-----------|--------|
| `overloaded` | utilization > 90% | Reduce acceptance rate |
| `underutilized` | utilization < 30% | Increase acceptance rate |
| `token_exhausted` | tokens used > 90% budget | Pause campaigns |
| `worker_shortage` | available workers < 20% | Scale up workers |
| `queue_backlog` | queued campaigns > 100 | Prioritize by severity |
| `rate_limit` | API rate limit hit | Throttle all external calls |

## Distributed API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/distributed/campaigns` | Submit new campaign |
| `GET` | `/api/v1/distributed/campaigns` | List campaigns with filtering |
| `GET` | `/api/v1/distributed/campaigns/{campaign_id}` | Get campaign status |
| `POST` | `/api/v1/distributed/campaigns/{campaign_id}/execute` | Start execution |
| `POST` | `/api/v1/distributed/campaigns/{campaign_id}/cancel` | Cancel campaign |
| `POST` | `/api/v1/distributed/campaigns/{campaign_id}/pause` | Pause campaign |
| `POST` | `/api/v1/distributed/campaigns/{campaign_id}/resume` | Resume campaign |
| `GET` | `/api/v1/distributed/pools` | List worker pools |
| `GET` | `/api/v1/distributed/pools/{pool_name}` | Get pool status |
| `GET` | `/api/v1/distributed/quotas` | Get quota status |
| `GET` | `/api/v1/distributed/metrics` | Get pool metrics |

### Example: Submit and Execute Campaign

```python
from redos.distributed import submit_campaign, get_campaign

# Submit campaign
campaign_id = await submit_campaign(
    org_id="org_456",
    project_id="project_alpha",
    target_ids=["target_abc123", "target_def456"],
    campaign_type="full_assessment",
    priority=7,
    estimated_duration_minutes=120,
    tags=["assessment", "production"],
)

# Check status
campaign = await get_campaign(campaign_id=campaign_id)
print(f"Status: {campaign['status']}")
print(f"Executing: {campaign['executing']}")
print(f"Findings: {campaign['findings_generated']}")
print(f"Cost: ${campaign['cost_usd']:.4f}")
print(f"Tokens: {campaign['tokens_used_million']:.4f}M")
```

## Example: Complete Distributed Execution Lifecycle

```python
from redos.distributed import (
    submit_campaign, get_campaign, cancel_campaign,
    QuotaManager, ConcurrencyLimiter, BackpressureManager
)
from redos.fleet import FleetManager

async def run_distributed_assessment():
    org_id = "org_456"
    
    # 1. Check quotas
    quota = QuotaManager(org_id=org_id)
    can_execute, quota_info = quota.check(
        campaigns=1, executions=1, tokens_million=0.5, findings=10
    )
    if not can_execute:
        raise QuotaExceededError(quota_info['reason'])
    
    # 2. Check concurrency
    limiter = ConcurrencyLimiter(pool_name="default", max_concurrent=5)
    acquired = await limiter.acquire(campaign_id="temp_campaign")
    if not acquired:
        raise ConcurrencyError("Max concurrent campaigns reached")
    
    # 3. Check backpressure
    backpressure = BackpressureManager(org_id=org_id)
    if signals.overloaded:
        # Wait or reduce rate
        await asyncio.sleep(30)
    
    # 4. Verify tenant isolation
    fleet = FleetManager(org_id=org_id)
    isolated = await fleet.verify_target_org(
        target_ids=["target_abc123", "target_def456"],
        expected_org=org_id,
    )
    if not isolated.all:
        raise IsolationError(isolated.reasons)
    
    # 5. Submit campaign
    campaign_id = await submit_campaign(
        org_id=org_id,
        campaign_type="full_assessment",
        target_ids=["target_abc123", "target_def456"],
        priority=7,
    )
    
    # 6. Monitor execution
    while True:
        campaign = await get_campaign(campaign_id=campaign_id)
        if campaign['status'] in ['completed', 'failed', 'cancelled']:
            break
        await asyncio.sleep(10)
    
    # 7. Release concurrency
    await limiter.release(campaign_id=campaign_id)
    
    # 8. Check quotas updated
    quota.check()  # Re-check after execution
    
    return campaign
```