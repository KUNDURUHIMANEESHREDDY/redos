# RedOS Distributed Execution Module

## Distributed Campaign Execution

```python
from redos.distributed import (
    submit_campaign, get_campaign, cancel_campaign,
    QuotaManager, ConcurrencyLimiter, BackpressureManager
)
from redos.fleet import FleetManager

async def run_distributed_assessment():
    org_id = "org_456"
    
    # 1. Check quotas before execution
    quota = QuotaManager(org_id=org_id)
    can_execute, quota_info = quota.check(
        campaigns=1, executions=1, tokens_million=0.5, findings=10
    )
    if not can_execute:
        raise QuotaExceededError(quota_info['reason'])
    
    # 2. Check concurrency limits
    limiter = ConcurrencyLimiter(pool_name="default", max_concurrent=5)
    acquired = await limiter.acquire(campaign_id="temp_campaign", timeout_minutes=30)
    if not acquired:
        raise ConcurrencyError("Maximum concurrent campaigns reached")
    
    # 3. Check backpressure
    backpressure = BackpressureManager(org_id=org_id)
    if backpressure.signals.overloaded:
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
    
    # 6. Monitor execution progress
    while True:
        campaign = await get_campaign(campaign_id=campaign_id)
        if campaign['status'] in ['completed', 'failed', 'cancelled']:
            break
        await asyncio.sleep(10)
    
    # 7. Release concurrency slot
    await limiter.release(campaign_id=campaign_id)
    
    # 8. Check updated quotas
    quota.check()
    
    return campaign

# Run the assessment
import asyncio
result = asyncio.run(run_distributed_assessment())
print(f"Campaign completed: {result['status']}")
print(f"Findings: {result.get('findings_generated', 0)}")
print(f"Cost: ${result.get('cost_usd', 0):.4f}")
print(f"Tokens: {result.get('tokens_used_million', 0):.4f}M")
```

## Distributed API Operations

```python
import requests
import json

BASE_URL = "http://localhost:8000/api/v1/distributed"
headers = {"Authorization": f"Bearer {token}"}

# Submit a new campaign
resp = requests.post(f"{BASE_URL}/campaigns", json={
    "org_id": "org_456",
    "campaign_type": "full_assessment",
    "target_ids": ["target_abc123", "target_def456"],
    "priority": 7,
}, headers=headers)
campaign = resp.json()
print(f"Campaign ID: {campaign['campaign_id']}")
print(f"Status: {campaign['status']}")

# Check campaign status
resp = requests.get(f"{BASE_URL}/campaigns/{campaign['campaign_id']}", headers=headers)
campaign = resp.json()
print(f"Findings: {campaign.get('findings_generated', 0)}")
print(f"Cost: ${campaign.get('cost_usd', 0):.4f}")

# Pause campaign
resp = requests.post(f"{BASE_URL}/campaigns/{campaign['campaign_id']}/pause", headers=headers)
print(f"Paused: {resp.json()}")

# Resume campaign
resp = requests.post(f"{BASE_URL}/campaigns/{campaign['campaign_id']}/resume", headers=headers)
print(f"Resumed: {resp.json()}")

# Cancel campaign
resp = requests.post(f"{BASE_URL}/campaigns/{campaign['campaign_id']}/cancel", 
                     json={"reason": "Organization priority change"}, headers=headers)
print(f"Cancelled: {resp.json()}")

# Check quotas
resp = requests.get(f"{BASE_URL}/quotas", headers=headers)
quotas = resp.json()
print(f"Quota status: {json.dumps(quotas, indent=2)}")

# Check metrics
resp = requests.get(f"{BASE_URL}/metrics", headers=headers)
metrics = resp.json()
print(f"Metrics: {json.dumps(metrics, indent=2)}")
```