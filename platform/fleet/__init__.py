# RedOS Fleet Module

## Fleet Manager - Multi-Target Operations

```python
from redos.fleet import FleetManager
import asyncio

async def main():
    # Initialize fleet manager for organization
    fleet = FleetManager(
        organization_id="org_456",
        db_connection="mongodb://mongo:27017",
        redis_url="redis://redis:6379",
    )
    
    # Register multiple targets concurrently
    targets = [
        {"name": "RAG System - Production", "type": "rag_system", "model": "gpt-4o", "tags": ["rag", "production"]},
        {"name": "API Target - Staging", "type": "api", "model": "gpt-4o-mini", "tags": ["api", "staging"]},
        {"name": "Model API - External", "type": "model_api", "model": "claude-3-opus", "tags": ["external", "claude"]},
        {"name": "Internal Service", "type": "service", "model": "llama3:8b", "tags": ["internal"]},
    ]
    
    # Register all targets concurrently
    tasks = []
    for t in targets:
        tasks.append(fleet.register_target(
            name=t["name"],
            target_type=t["type"],
            model=t["model"],
            tags=t.get("tags", [])
        ))
    
    results = await asyncio.gather(*tasks)
    for i, result in enumerate(results):
        print(f"Registered: {targets[i]['name']} -> {result}")
    
    # Get fleet posture
    posture = await fleet.get_posture()
    print(f"\nOrganization Posture: {posture['posture_score']}/10")
    print(f"Total Targets: {posture['total_targets']}")
    print(f"Active Targets: {posture['active_targets']}")
    print(f"Findings by Severity: {posture['findings_by_severity']}")
    
    # Verify tenant isolation
    is_isolated = await fleet.verify_tenant_isolation(
        target_ids=["target_abc123", "target_def456"],
        expected_org="org_456"
    )
    print(f"\nTenant isolation verified: {is_isolated}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Fleet API Integration

```python
import requests
import json

# Fleet operations via API
BASE_URL = "http://localhost:8000/api/v1/fleet"

# Get organization posture
resp = requests.get(f"{BASE_URL}/orgs/{org_id}", headers={"Authorization": f"Bearer {token}"})
posture = resp.json()
print(json.dumps(posture, indent=2))

# List targets
resp = requests.get(f"{BASE_URL}/orgs/{org_id}/projects/{proj_id}/targets", 
                    headers={"Authorization": f"Bearer {token}"})
targets = resp.json()
print(f"Found {len(targets['targets'])} targets")

# Register new target
resp = requests.post(f"{BASE_URL}/orgs/{org_id}/projects/{proj_id}/targets",
                     json={"name": "New Target", "type": "rag_system", "model": "gpt-4o"},
                     headers={"Authorization": f"Bearer {token}"})
new_target = resp.json()
print(f"Registered: {new_target['target_id']}")

# Create campaign
resp = requests.post(f"{BASE_URL}/fleet/campaigns",
                     json={"name": "Weekly Assessment", "target_ids": ["target1", "target2"]},
                     headers={"Authorization": f"Bearer {token}"})
campaign = resp.json()
print(f"Created campaign: {campaign['campaign_id']}")
```

## Concurrent Target Scanning

```python
from redos.fleet import FleetManager
from redos.distributed import submit_campaign

async def scan_multiple_targets():
    fleet = FleetManager(organization_id="org_456")
    
    # Get all active targets
    targets = await fleet.get_active_targets()
    
    # Submit campaigns concurrently for multiple targets
    campaign_tasks = []
    for target in targets[:10]:  # Scan first 10 targets concurrently
        task = submit_campaign(
            org_id="org_456",
            target_ids=[target["target_id"]],
            campaign_type="full_assessment",
            priority=7,
        )
        campaign_tasks.append(task)
    
    # Execute all campaigns concurrently
    campaign_ids = await asyncio.gather(*campaign_tasks)
    print(f"Started {len(campaign_ids)} concurrent campaigns")
    
    # Monitor progress
    for i, campaign_id in enumerate(campaign_ids):
        await asyncio.sleep(5)  # Check every 5 seconds
        status = await get_campaign_status(campaign_id)
        print(f"Campaign {i+1}: {status['status']} - {status.get('findings_generated', 0)} findings")

if __name__ == "__main__":
    asyncio.run(scan_multiple_targets())
```