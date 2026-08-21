# Remediation Model Specification

## Overview

Remediation is generated from **evidence-backed root cause analysis** and tied to vulnerability type templates. Every remediation action must have verification steps.

## Remediation Action

```python
class RemediationAction:
    action_id: UUID
    title: str
    description: str
    priority: int              # 1 = highest
    effort: str                # low, medium, high
    category: str              # code_change, configuration, infrastructure, process
    references: list[str]      # Links to OWASP, CWE, etc.
    verification_steps: list[str]  # REQUIRED - how to verify fix
```

## Remediation Templates

Pre-defined templates per vulnerability type:

| Vulnerability Type | Template Actions |
|-------------------|------------------|
| SQL_INJECTION | 1. Parameterized Queries (priority 1), 2. Input Validation (priority 2) |
| COMMAND_INJECTION | 1. Safe APIs (priority 1), 2. Input Sanitization (priority 2) |
| XSS | 1. Output Encoding (priority 1), 2. CSP Headers (priority 2) |
| PATH_TRAVERSAL | 1. Path Normalization (priority 1) |
| BROKEN_AUTH | 1. MFA (priority 1), 2. Secure Sessions (priority 2) |

## Root Cause Analysis

Performed by `RootCauseAnalyzer`:

```python
class RootCause:
    cause_id: UUID
    description: str           # Root cause description
    category: str              # input_validation, output_encoding, auth, crypto, etc.
    evidence_ids: list[UUID]   # Evidence supporting root cause
    contributing_factors: list[str]
    code_location: str | None  # File:line if determinable
    configuration_issue: str | None
```

**Root Cause Categories:**
- `input_validation` - SQL injection, command injection, path traversal
- `output_encoding` - XSS
- `authentication` - Broken auth
- `authorization` - Broken access control
- `cryptography` - Sensitive data exposure

## Remediation Generation Flow

```
Finding
  ↓
RootCauseAnalyzer.analyze(finding) → RootCause
  ↓
RemediationService.generate_remediation(finding)
  ↓
1. Template actions for vulnerability_type
2. Root cause action (if root_cause exists, priority 1)
  ↓
List[RemediationAction]
```

## Remediation Lifecycle

```
Finding status: CONFIRMED
  ↓
Finding.remediation = [actions]
Finding.status = REMEDIATED
  ↓
All verification_steps complete
  ↓
Finding.status = REGRESSION_TESTED
  ↓
Regression tests pass
  ↓
Finding.status = FIXED
```

## Verification Requirements

**Every RemediationAction MUST have:**
- At least one verification_step
- Verification steps must be executable/testable
- References to standards (OWASP, CWE, CVE)

## Code Examples

Templates include code examples:
```python
{
    "python_bad": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
    "python_good": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
}
```

## API Operations

### Generate Remediation
```
POST /api/v1/remediation/generate
{"finding_id": "uuid"}
```

### Apply Remediation
```
POST /api/v1/remediation/apply/{finding_id}
{"actions": [...]}
```

### Verify Remediation
```
POST /api/v1/remediation/verify/{finding_id}
```

### Analyze Root Cause
```
POST /api/v1/remediation/root-cause/{finding_id}
```

## Validation Rules

1. Finding must be in CONFIRMED status to apply remediation
2. Remediation actions required for REMEDIATED transition
3. Verification steps required for REGRESSION_TESTED transition
4. Root cause must reference evidence IDs
5. Code location should be determinable from process trace evidence

## Evidence Traceability

- Root cause `evidence_ids` = finding.evidence_ids
- Contributing factors derived from evidence analysis
- Code location from process_trace evidence
- Template references linked to OWASP/CWE

## Anti-Fabrication Guarantees

1. **Root cause from evidence** - Never guessed from vulnerability name
2. **Verification required** - Cannot progress without testable steps
3. **Template-driven** - Actions based on vulnerability type, not attack name
4. **Audit trail** - All remediation actions stored with timestamps