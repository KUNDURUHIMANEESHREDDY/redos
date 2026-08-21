# RedOS Enterprise Controls

## Overview

Enterprise controls provide the governance, compliance, and management capabilities required
for RedOS to operate as a serious security platform in regulated environments. These
controls span organizational structure, access management, policy enforcement, data
retention, and reporting.

## Organizational Structure

### Organizations

An organization is the top-level container for security operations. All resources—projects,
targets, users, findings, evidence—belong to an organization.

#### Organization Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `name` | String | Human-readable name (unique) |
| `description` | String | Optional description |
| `created_at` | DateTime | Creation timestamp |
| `updated_at` | DateTime | Last update timestamp |
| `status` | Enum | `active`, `paused`, `archived` |
| `quotas` | Object | Resource quotas (executions, findings, evidence) |
| `gate_config` | JSON | Security gate configuration |
| `retention_policy` | JSON | Evidence and finding retention rules |
| `compliance_frameworks` | Array | Compliance standards applied |

### Organization Hierarchy

```
Organization (Global)
├── Organization A
│   ├── Project Alpha
│   │   ├── Target A1
│   │   └── Target A2
│   ├── Project Beta
│   │   └── Target B1
│   └── Team Red
│       └── Member A
├── Organization B
│   ├── Project Gamma
│   └── Target G1
└── Organization C (paused)
```

### Organization API Endpoints

| Method | Endpoint | Description | Permissions |
|--------|----------|-------------|-------------|
| `GET` | `/api/v1/organizations` | List organizations user belongs to | User, Admin |
| `POST` | `/api/v1/organizations` | Create new organization | Admin |
| `GET` | `/api/v1/organizations/{id}` | Get organization details | User, Admin |
| `PUT` | `/api/v1/organizations/{id}` | Update organization | Admin |
| `DELETE` | `/api/v1/organizations/{id}` | Archive organization | Admin |

### Teams

Teams are sub-groups within an organization, enabling finer-grained access control.

#### Team Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `name` | String | Human-readable name (unique within org) |
| `description` | String | Optional description |
| `role` | Enum | `admin`, `member`, `viewer` |
| `created_at` | DateTime | Creation timestamp |
| `updated_at` | DateTime | Last update timestamp |
| `member_count` | Integer | Number of members |
| `resource_quotas` | Object | Per-team resource limits |

#### Team API Endpoints

| Method | Endpoint | Description | Permissions |
|--------|----------|-------------|-------------|
| `GET` | `/api/v1/organizations/{org_id}/teams` | List teams in organization | Admin |
| `POST` | `/api/v1/organizations/{org_id}/teams` | Create team | Admin |
| `GET` | `/api/v1/teams/{team_id}` | Get team details | Team members, Admin |
| `PUT` | `/api/v1/teams/{team_id}` | Update team | Admin |
| `DELETE` | `/api/v1/teams/{team_id}` | Delete team | Admin |

### Service Accounts

Service accounts are non-human accounts for automated systems, CI/CD pipelines, and
external services.

#### Service Account Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `name` | String | Service name |
| `type` | Enum | `ci_cd`, `automation`, `integration`, `system` |
| `role` | Enum | `admin`, `read_only`, `custom` |
| `scopes` | Array | Permitted actions |
| `api_key` | String | Generated API key |
| `created_at` | DateTime | Creation timestamp |
| `expires_at` | DateTime | Expiration timestamp |
| `last_used_at` | DateTime | Last usage timestamp |
| `status` | Enum | `active`, `revoked`, `expired` |

#### Service Account API Endpoints

| Method | Endpoint | Description | Permissions |
|--------|----------|-------------|-------------|
| `GET` | `/api/v1/service-accounts` | List service accounts | Admin |
| `POST` | `/api/v1/service-accounts` | Create service account | Admin |
| `GET` | `/api/v1/service-accounts/{id}` | Get service account details | Owner, Admin |
| `PUT` | `/api/v1/service-accounts/{id}` | Update service account | Owner, Admin |
| `POST` | `/api/v1/service-accounts/{id}/rotate-key` | Rotate API key | Owner, Admin |
| `POST` | `/api/v1/service-accounts/{id}/revoke` | Revoke access | Owner, Admin |

## RBAC Refinement

### Permission Granularity

RedOS RBAC supports fine-grained permissions at the resource level.

#### Permission Structure

```
permission: {resource}:{action}:{conditions}
```

#### Resource Types

| Resource | CRUD | Additional Actions |
|----------|------|-------------------|
| `organizations` | CR | `transfer_owner`, `change_tier` |
| `projects` | CRUD | `archive`, `restore`, `change_ownership` |
| `targets` | CRUD | `pause`, `resume`, `change_status` |
| `campaigns` | CRUD | `pause`, `resume`, `cancel`, `replay` |
| `executions` | CR | `terminate`, `replay`, `export` |
| `findings` | CRUD | `merge`, `split`, `reclassify` |
| `evidence` | CRUD | `download`, `delete`, `reclassify` |
| `gate_decisions` | CR | `override`, `appeal` |
| `reports` | CR | `export`, `schedule` |
| `compliance` | CR | `map`, `unmap`, `assess` |

#### Role Definitions

| Role | Permissions |
|------|-------------|
| `super_admin` | All permissions across all resources |
| `org_admin` | All permissions within organization |
| `project_admin` | All permissions within project |
| `team_admin` | Permissions within team scope |
| `user` | Create own findings, view own resources |
| `viewer` | Read-only access, no creation |
| `service_account:admin` | Service account management |
| `service_account:read_only` | Read-only access for automation |

#### Custom Role Example

```yaml
# Define custom role in organization settings
role: "red_team_lead"
permissions:
  organizations: [view, edit]
  projects: [create, view, edit, delete]
  targets: [create, view, edit, pause, resume]
  campaigns: [create, view, edit, start, stop, cancel]
  findings: [create, view, edit, merge, reclassify]
  evidence: [create, view, edit, download, delete]
  gates: [view, edit, override]
  reports: [view, export, schedule]
  api_keys: [create, view, rotate, revoke]
```

## API Keys

### API Key Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `key` | String | The actual API key (sensitive) |
| `name` | String | Human-readable name |
| `type` | Enum | `user`, `service_account`, `team`, `organization` |
| `scopes` | Array | Permitted actions/resources |
| `organization_id` | UUID | owning organization |
| `project_id` | UUID | owning project (if applicable) |
| `team_id` | UUID | owning team (if applicable) |
| `permissions` | Array | Permitted actions |
| `expires_at` | DateTime | Expiration timestamp |
| `last_used_at` | DateTime | Last usage timestamp |
| `call_count` | Integer | Total API call count |
| `status` | Enum | `active`, `revoked`, `expired`, `paused` |

### API Key Scopes

Scopes define what an API key can do:

```json
{
  "scopes": [
    "findings:create",
    "findings:view",
    "findings:edit",
    "evidence:view",
    "campaigns:view",
    "campaigns:start",
    "gates:view"
  ]
}
```

### API Key API Endpoints

| Method | Endpoint | Description | Permissions |
|--------|----------|-------------|-------------|
| `GET` | `/api/v1/api-keys` | List API keys | User, Admin |
| `POST` | `/api/v1/api-keys` | Create API key | Admin |
| `GET` | `/api/v1/api-keys/{key_id}` | Get API key details | Owner, Admin |
| `PUT` | `/api/v1/api-keys/{key_id}` | Update API key scopes | Owner, Admin |
| `POST` | `/api/v1/api-keys/{key_id}/rotate` | Rotate/regenerate key | Owner, Admin |
| `POST` | `/api/v1/api-keys/{key_id}/revoke` | Revoke key immediately | Owner, Admin |
| `GET` | `/api/v1/api-keys/{key_id}/usage` | Get usage statistics | Owner, Admin |

### API Key Usage Tracking

```python
from redos.integrations.custom import APIKeyManager

manager = APIKeyManager()

# Get usage statistics
stats = manager.get_usage(key_id="key_123")

print(f"Total calls: {stats['call_count']}")
print(f"Today: {stats['today_count']}")
print(f"Peak minute: {stats['peak_minute_calls']}")
print(f"Expires: {stats['expires_at']}")
print(f"Last used: {stats['last_used_at']}")

# Check if key is still valid
if manager.is_valid(key_id="key_123"):
    print("Key is active and valid")
else:
    print("Key is revoked or expired")
```

## Security Policies

### Policy Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `name` | String | Policy name (unique) |
| `description` | String | Policy description |
| `type` | Enum | `finding`, `evidence`, `execution`, `compliance` |
| `conditions` | JSON | If-then conditions |
| `actions` | Array | Allowed/blocked actions |
| `severity` | Enum | `info`, `low`, `medium`, `high`, `critical` |
| `is_active` | Boolean | Whether policy is active |
| `applies_to` | Array | Organizations, projects, targets |
| `created_at` | DateTime | Creation timestamp |
| `updated_at` | DateTime | Last update timestamp |
| `created_by` | UUID | User who created policy |

### Policy Conditions

```json
{
  "conditions": {
    "severity": ["CRITICAL", "HIGH"],
    "finding_type": "prompt_injection",
    "campaign_age_hours": 24,
    "organization_id": "org_123",
    "target_status": "active",
    "finding_status": "active"
  },
  "actions": [
    "block_campaign_launch",
    "require_approval",
    "escalate_to_admin",
    "create_finding",
    "notify_team"
  ],
  "metadata": {
    "notify_method": "email",
    "escalation_path": ["team_lead", "org_admin"],
    "expiry_hours": 168
  ]
}
```

### Pre-Configured Security Policies

| Policy Name | Type | Conditions | Actions |
|-------------|------|------------|---------|
| `BLOCK_CRITICAL_FINDINGS` | finding | `severity`: `CRITICAL` | `block_campaign_launch` |
| `WARN_MEDIUM_INCREASE` | finding | `severity`: `MEDIUM`, `count_30d > 5` | `notify_team` |
| `REQUIRE_REGRESSION_GATE` | finding | `gate:PASS_NO_REGRESSION` must pass | `pass_failed_gate` |
| `COMPLIANCE_MAP_REQUIRED` | finding | must map to compliance standard | `require_mapping` |
| `EVIDENCE_REQUIRED` | finding | must have associated evidence | `require_evidence` |
| `ISOLATE_CRITICAL_TARGETS` | target | `severity`: `CRITICAL` | `pause_target`, `enhanced_monitoring` |
| `RETAIN_90_DAYS` | evidence | age > 90 days | `auto_archive`, `purge_if_older` |
| `INTERNAL_ONLY` | finding | `organization_id` not in external list | `block_external_access` |

### Policy Evaluation

```python
from redos.enterprise.policies import PolicyEngine

engine = PolicyEngine(org_id="org_123")

# Evaluate policies against a finding
result = engine.evaluate(
    policy_names=["BLOCK_CRITICAL_FINDINGS", "REQUIRE_REGRESSION_GATE"],
    finding=finding,
    context={
        "campaign_id": "camp_123",
        "organization_id": "org_123",
    }
)

print(f"Policies triggered: {result['triggered']}")
print(f"Actions required: {result['actions']}")
print(f"Pass/fail: {result['pass_fail']}")
print(f"Details: {result['details']}")
```

## Retention Policies

### Finding Retention

| Retention Tier | Duration | Action at Expiry |
|---------------|----------|----------------|
| `short_term` | 30 days | Auto-archive, keep metadata |
| `medium_term` | 90 days | Auto-archive, retain findings |
| `long_term` | 365 days | Retain all data |
| `persistent` | Indefinite | Never auto-delete |

### Evidence Retention

| Retention Tier | Duration | Action at Expiry |
|---------------|----------|----------------|
| `short_term` | 7 days | Auto-delete |
| `medium_term` | 30 days | Auto-compress, retain metadata |
| `long_term` | 90 days | Move to cold storage |
| `persistent` | 1 year + | Archive to object storage |

### Retention Policy Configuration

```yaml
# In organization settings
retention_policy:
  findings:
    tier: "medium_term"
    auto_archive: true
    archive_path: "s3://redos/archived_findings/"
    purge_after_years: 2
  
  evidence:
    tier: "long_term"
    auto_archive: true
    archive_path: "s3://redos/archived_evidence/"
    purge_after_years: 5
    
  # Global settings
  default_tier: "medium_term"
  auto_cleanup: true
  cleanup_schedule: "0 2 * * 0"  # Weekly at 2 AM
```

### Retention API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/retention/policy` | Get retention policy |
| `PUT` | `/api/v1/retention/policy` | Update retention policy |
| `POST` | `/api/v1/retention/cleanup` | Run manual cleanup |
| `GET` | `/api/v1/retention/stats` | Get retention statistics |

## Export & Reports

### Export Formats

| Format | Features | Use Case |
|--------|----------|----------|
| `JSON` | Full data, nested objects | API consumption, analysis |
| `CSV` | Tabular data, easy import | Spreadsheets, reporting |
| `PDF` |Formatted reports, executive view | Stakeholder presentations |
| `HTML` | Interactive reports, web view | Internal dashboards |
| `XML` | Legacy system compatibility | Enterprise integrations |
| `JSONL` | Line-delimited, streaming | Large dataset processing |

### Export API Endpoints

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `GET` | `/api/v1/exports/findings` | Export findings | `format`, `date_range`, `severity`, `campaign_id`, `organization_id`, `compliance_framework` |
| `GET` | `/api/v1/exports/evidence` | Export evidence | `format`, `date_range`, `type`, `finding_id`, `organization_id` |
| `GET` | `/api/v1/exports/campaigns` | Export campaign data | `format`, `date_range`, `status` |
| `GET` | `/api/v1/exports/audit-logs` | Export audit logs | `date_range`, `action`, `user_id`, `organization_id` |
| `GET` | `/api/v1/exports/reports` | Export pre-built reports | `report_type`, `date_range`, `format`, `organization_id` |

### Pre-Built Report Types

| Report Type | Description | Audience |
|-----------|-----------|----------|
| `executive_security` | High-level summary, key metrics, top findings | C-level executives, board members |
| `technical_vulnerability` | Detailed vulnerability findings, technical details | Security engineers, CTOs |
| `attack_campaign` | Campaign timeline, steps, findings | Red team leads, project managers |
| `regression` | Before/after comparison, test results | DevOps, development leads |
| `remediation` | Fix status, verification, open items | Security ops, development teams |
| `compliance` | Compliance framework mapping, gaps | Compliance officers, auditors |
| `evidence_export` | All evidence with redactions | Forensics, legal teams |
| `compliance_framework` | Specific framework (SOC2, ISO27001, NIST) | Auditors, compliance teams |

### Report Generation

```python
from redos.enterprise.reporting import ReportGenerator

generator = ReportGenerator(org_id="org_123")

# Generate executive security report
executive_report = generator.generate(
    report_type="executive_security",
    date_range=("2024-01-01", "2024-01-31"),
    format="pdf",
    include_charts=True,
    include_remediation_status=True,
)

# Save to file
executive_report.save("executive_security_report_jan2024.pdf")

# Or get base64 for API response
base64_pdf = executive_report.get_base64()

# Download via API
response = generator.download(
    report_type="executive_security",
    format="pdf",
    date_range=("2024-01-01", "2024-01-31")
)
```

## Compliance Mapping

### Supported Frameworks

| Framework | Control ID | Mapping | Status |
|-----------|----------|---------|--------|
| **SOC 2** | CC6.7 | Finding severity mapping, evidence retention | ✅ Configured |
| **SOC 2** | CC7.2 | Finding lifecycle, retention policies | ✅ Configured |
| **ISO 27001** | A.12.4 | Asset management, finding retention | ✅ Configured |
| **ISO 27001** | A.8.1 | Information security policies | ✅ Configured |
| **NIST CSF** | PR.IP | Vulnerability identification, finding generation | ✅ Configured |
| **NIST CSF** | DE.CM | Continuous monitoring, finding generation | ✅ Configured |
| **PCI DSS** | 10.2 | Audit trails, finding retention | ✅ Configured |
| **HIPAA** | 164.312 | Data retention, access controls | ✅ Configured |

### Compliance Mapping Configuration

```yaml
# In organization settings
compliance_frameworks:
  - name: "SOC 2 Type II"
    controls:
      - id: "CC6.7"
        mapping:
          finding_severity_mapping:
            CRITICAL: "high_severity_incident"
            HIGH: "medium_severity_incident"
            MEDIUM: "low_severity_incident"
            LOW: "info"
          retention_policy:
            findings: "medium_term"
            evidence: "long_term"
          required_gates:
            - "BLOCK_CRITICAL_FINDINGS"
            - "REQUIRE_REGRESSION_GATE"
          
  - name: "ISO 27001 A.12.4"
    controls:
      - id: "A.12.4"
        mapping:
          asset_classification: "finding.severity"
          retention:
            findings: "medium_term"
            evidence: "persistent"
          required_actions:
            - "document_root_cause"
            - "assign_owner"
          
  - name: "NIST CSF"
    controls:
      - id: "PR.IP"
        mapping:
          vulnerability_identification: "finding generation"
          continuous_monitoring: "gate_evaluation"
          reporting: "report_generation"
          
  - name: "PCI DSS"
    controls:
      - id: "10.2"
        mapping:
          audit_trail: "audit_logging"
          finding_retention: "retention_policy"
          incident_response: "escalation_policies"
```

### Compliance API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/compliance/frameworks` | List configured frameworks |
| `GET` | `/api/v1/compliance/frameworks/{framework_id}` | Get framework details |
| `GET` | `/api/v1/compliance/mapping` | Get finding-to-control mapping |
| `POST` | `/api/v1/compliance/assess` | Run compliance assessment |
| `GET` | `/api/v1/compliance/report` | Generate compliance report |

### Compliance Assessment

```python
from redos.enterprise.compliance import ComplianceAssessor

assessor = ComplianceAssessor(org_id="org_123", framework="SOC 2 Type II")

# Run assessment against all findings
result = assessor.assess(
    date_range=("2024-01-01", "2024-01-31"),
    include_evidence=True,
    include_gate_status=True,
)

print(f"Framework: {result['framework']}")
print(f"Total findings: {result['total_findings']}")
print(f"Compliant: {result['compliant_findings']}")
print(f"Non-compliant: {result['non_compliant_findings']}")
print(f"Gap score: {result['gap_score']:.1f}%")
print(f"Pass/fail: {result['pass_fail']}")

# Get detailed gaps
for gap in result['gaps']:
    print(f"• {gap['control_id']}: {gap['description']}")
    print(f"  Required: {gap['required_action']}")
    print(f"  Current state: {gap['current_state']}")
```