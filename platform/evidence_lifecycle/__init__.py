# RedOS Evidence Lifecycle Module

## Evidence Lifecycle Management

```python
from redos.evidence_lifecycle import EvidenceLifecycleManager, RetentionPolicy, ArchiveManager

async def main():
    org_id = "org_456"
    lifecycle_mgr = EvidenceLifecycleManager(org_id=org_id)
    
    # 1. Set up retention policies
    retention_policy = RetentionPolicy(
        findings_tier="medium_term",  # 90 days
        evidence_tier="long_term",    # 365 days
        auto_archive=True,
        archive_path="s3://redos/archived/",
        purge_after_years={"findings": 2, "evidence": 5},
    )
    
    await lifecycle_mgr.set_retention_policy(retention_policy)
    print("Retention policy set")
    
    # 2. Archive old evidence
    archive_mgr = ArchiveManager(org_id=org_id)
    
    # Archive evidence older than 90 days
    archived = await archive_mgr.archive_old_evidence(
        days_old=90,
        tier="long_term",
    )
    print(f"Archived {archived['count']} evidence items")
    print(f"Moved to: {archived['archive_path']}")
    
    # 3. Verify evidence integrity
    integrity = await lifecycle_mgr.verify_evidence_integrity(
        evidence_ids=["ev_abc123", "ev_def456"],
    )
    print(f"Evidence integrity verified: {integrity}")
    
    # 4. Execute deletion with legal hold check
    # First check for legal holds
    legal_holds = await lifecycle_mgr.check_legal_holds(
        evidence_ids=["ev_abc123"],
    )
    if legal_holds.has_legal_hold:
        print("Cannot delete - legal hold active")
    else:
        # Safe to delete
        deleted = await lifecycle_mgr.delete_evidence(
            evidence_ids=["ev_old123"],
            permanently=True,
        )
        print(f"Deleted {deleted['count']} evidence items")
    
    # 5. Export evidence for compliance
    export = await lifecycle_mgr.export_evidence(
        format="json",
        date_range=("2024-01-01", "2024-12-31"),
        include_metadata=True,
    )
    print(f"Exported {export['count']} evidence items")
    print(f"Format: {export['format']}")
    print(f"Download: {export['download_url']}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Evidence Retention Tiers

| Tier | Duration | Action at Expiry | Automated |
|------|----------|-----------------|-----------|
| `short_term` | 7 days | Auto-delete | ✅ |
| `medium_term` | 30 days | Auto-compress, retain metadata | ✅ |
| `long_term` | 365 days | Move to cold storage | ✅ |
| `persistent` | Indefinite | Never auto-delete | ❌ |

## Evidence Lifecycle API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/evidence_lifecycle/retention-policy` | Get retention policy |
| `PUT` | `/api/v1/evidence_lifecycle/retention-policy` | Update retention policy |
| `POST` | `/api/v1/evidence_lifecycle/archival` | Archive old evidence |
| `GET` | `/api/v1/evidence_lifecycle/integrity` | Verify evidence integrity |
| `POST` | `/api/v1/evidence_lifecycle/legal-hold` | Set legal hold |
| `POST` | `/api/v1/evidence_lifecycle/legal-hold/{id}/release` | Release legal hold |
| `GET` | `/api/v1/evidence_lifecycle/export` | Export evidence |
| `GET` | `/api/v1/evidence_lifecycle/stats` | Get lifecycle statistics |

## Legal Hold Management

```python
from redos.evidence_lifecycle import EvidenceLifecycleManager

lifecycle_mgr = EvidenceLifecycleManager(org_id="org_456")

# Set legal hold on specific evidence
await lifecycle_mgr.set_legal_hold(
    evidence_ids=["ev_critical_001", "ev_critical_002"],
    reason="Active litigation - XYZ Corp vs RedOS",
    held_by="legal-team",
    held_until="2025-12-31",
)

# Check for legal holds before deletion
has_hold = await lifecycle_mgr.check_legal_holds(
    evidence_ids=["ev_critical_001"],
)

if has_hold.has_legal_hold:
    print("Cannot delete - legal hold active until", has_hold.held_until)
else:
    print("Safe to delete - no legal hold active")

# Release legal hold
await lifecycle_mgr.release_legal_hold(
    evidence_id="ev_critical_001",
    released_by="legal-team",
    reason="Litigation resolved",
)
```

## Evidence Integrity Verification

```python
from redos.evidence_lifecycle import EvidenceLifecycleManager
import json

lifecycle_mgr = EvidenceLifecycleManager(org_id="org_456")

# Verify integrity of specific evidence items
integrity_results = await lifecycle_mgr.verify_evidence_integrity(
    evidence_ids=["ev_abc123", "ev_def456", "ev_ghi789"],
)

for result in integrity_results:
    print(f"Evidence {result['evidence_id']}:")
    print(f"  Integrity valid: {result['integrity_valid']}")
    print(f"  Checksum match: {result['checksum_match']}")
    print(f"  Storage location: {result['storage_location']}")
    print(f"  Age: {result['age_days']} days")
    if result['errors']:
        print(f"  Errors: {result['errors']}")
    
    # Verify checksum
    if result['checksum_match']:
        print(f"  Stored checksum: {result['stored_checksum']}")
        print(f"  Computed checksum: {result['computed_checksum']}")
```

## Evidence Export

```python
from redos.evidence_lifecycle import EvidenceLifecycleManager
import httpx

lifecycle_mgr = EvidenceLifecycleManager(org_id="org_456")

# Export evidence in JSON format
export = await lifecycle_mgr.export_evidence(
    format="json",
    date_range=("2024-01-01", "2024-12-31"),
    include_metadata=True,
    include_original_content=True,
    organization_filter="org_456",
)

print(f"Export summary:")
print(f"  Items exported: {export['count']}")
print(f"  Format: {export['format']}")
print(f"  Download URL: {export['download_url']}")
print(f"  Total size: {export['size_bytes']} bytes")
print(f"  Includes content: {export['includes_content']}")
print(f"  Includes metadata: {export['includes_metadata']}")

# Or download via streaming
async with httpx.AsyncClient() as client:
    response = await client.get(export['download_url'], stream=True)
    total = 0
    async for chunk in response.iter_chunks():
        total += len(chunk)
    print(f"Downloaded {total} bytes via streaming")
```