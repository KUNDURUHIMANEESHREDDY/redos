# RedOS Scheduler Module

## Schedule Manager - Continuous Scanning

```python
from redos.scheduler import ScheduleManager
import asyncio

async def main():
    # Initialize scheduler for organization
    scheduler = ScheduleManager(org_id="org_456")
    
    # Generate hourly campaigns (focused assessment)
    hourly_campaigns = await scheduler.generate_campaigns(
        schedule_type="hourly",
        targets_filter="recently_active",
        campaigns=["quick_gates", "prompt_injection"],
        concurrency=4,
    )
    print(f"Hourly campaigns: {len(hourly_campaigns)}")
    
    # Generate daily campaigns (comprehensive assessment)
    daily_campaigns = await scheduler.generate_campaigns(
        schedule_type="daily",
        targets_filter="all",
        campaigns=["full_assessment", "evidence_review", "regression_check"],
        concurrency=8,
    )
    print(f"Daily campaigns: {len(daily_campaigns)}")
    
    # Generate weekly campaigns (deep assessment)
    weekly_campaigns = await scheduler.generate_campaigns(
        schedule_type="weekly",
        targets_filter="all",
        campaigns=["comprehensive_assessment", "compliance_report", "regression_analysis"],
        concurrency=12,
    )
    print(f"Weekly campaigns: {len(weekly_campaigns)}")
    
    # Trigger on-demand schedules
    # On deployment
    await scheduler.trigger(schedule_type="on_deployment", campaign_type="regression_gate", deployment_id="deploy_2024_01_15")
    
    # On model change
    await scheduler.trigger(schedule_type="on_model_change", campaign_type="model_switch_scan", old_model="gpt-4o", new_model="gpt-4o-mini")
    
    # On prompt change
    await scheduler.trigger(schedule_type="on_prompt_change", campaign_type="prompt_injection_scan", old_prompt_version="v1.2", new_prompt_version="v1.3")
    
    # On tool change
    await scheduler.trigger(schedule_type="on_tool_change", campaign_type="tool_capability_scan", old_tool_version="v2.1", new_tool_version="v2.2")
    
    # On RAG update
    await scheduler.trigger(schedule_type="on_rag_update", campaign_type="rag_effectiveness_scan", old_index_version="v1.2", new_index_version="v1.3")
    
    # CI event
    await scheduler.trigger(schedule_type="ci_event", campaign_type="ci_gate", pipeline_id="github_actions_123", pr_number=123)

if __name__ == "__main__":
    asyncio.run(main())
```

## Schedule API Usage

```python
import requests
import json

BASE_URL = "http://localhost:8000/api/v1/schedules"
headers = {"Authorization": f"Bearer {token}"}

# List all schedules
resp = requests.get(f"{BASE_URL}", headers=headers)
schedules = resp.json()
print(json.dumps(schedules, indent=2))

# Create a daily schedule
resp = requests.post(f"{BASE_URL}", json={
    "name": "daily_assessment",
    "schedule_type": "daily",
    "cron": "0 2 * * *",
    "targets_filter": "all",
    "campaigns": ["full_assessment", "evidence_review", "regression_check"],
    "concurrency": 8,
}, headers=headers)
print(f"Created schedule: {resp.json()['schedule_id']}")

# Manually trigger a schedule
resp = requests.post(f"{BASE_URL}/schedule_id_123/trigger", headers=headers)
print(f"Triggered schedule: {resp.json()}")
```

## Scheduler Orchestration

```python
from redos.scheduler import ScheduleManager, ScheduleOrchestrator

# Initialize
scheduler = ScheduleManager(org_id="org_123")
orchestrator = ScheduleOrchestrator(scheduler=scheduler, max_concurrent=12)

# Run a schedule with orchestration
results = await orchestrator.run_schedule(
    schedule_id="daily_2024_01_15",
    force_rerun=False,
)

print(f"Campaigns created: {results['campaigns_created']}")
print(f"Campaigns executed: {results['campaigns_executed']}")
print(f"Findings generated: {results['findings_generated']}")
print(f"Duration: {results['duration_minutes']} minutes")
print(f"Errors: {results['errors']}")
```