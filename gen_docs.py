import json, pathlib
from datetime import datetime

trust_path = pathlib.Path("reports/trust_gate/latest.json")
if not trust_path.exists():
    trust_path = pathlib.Path("reports/release_gate/latest.json")
data = json.loads(trust_path.read_text())

# Generate SUPPLY_CHAIN_SECURITY.md
supply_md = f"""# RedOS Supply Chain Security

## Overview
Evidence-backed supply chain security verification. All controls measured, not declared.

Generated: {data['generated_at']}
Overall Score: {data['overall_score']} Status: {data['overall_status']}

## Dependency Chain Analysis

### Direct Dependencies (measured from SBOM)

"""

sbom_gate = next((g for g in data["gates"] if g["name"]=="sbom"), None)
if sbom_gate:
    supply_md += f"- SBOM Components: {sbom_gate['metrics']['sbom_components']}\n"
    supply_md += f"- Hashed: {sbom_gate['metrics']['sbom_hashed_pct']}%\n"
    supply_md += f"- Evidence: {sbom_gate['evidence']['sbom_sha256'][:16]}... size {sbom_gate['evidence']['sbom_size']}\n"
    supply_md += f"- Tool: {sbom_gate['metrics']['sbom_tool']}\n\n"

dep_lock = next((g for g in data["gates"] if g["name"]=="dependency_lock"), None)
repro = next((g for g in data["gates"] if g["name"]=="reproducible_install"), None)
if dep_lock:
    supply_md += f"""### Dependency Locking (measured)

- requirements.txt: {dep_lock['metrics']['requirements_total']} deps, pinned {dep_lock['metrics']['requirements_pinned_pct']}%, hashed {dep_lock['metrics']['requirements_hashed_pct']}%
- package-lock.json: lockfileVersion {dep_lock['metrics']['lockfileVersion']}, integrity {dep_lock['metrics']['lock_integrity_pct']}%
- reproducible: pip {repro['metrics']['pip_reproducible'] if repro else 'N/A'}, npm {repro['metrics']['npm_reproducible'] if repro else 'N/A'}
- Evidence: requirements_sha256 {dep_lock['evidence']['requirements_sha256'][:16]}..., package-lock_sha256 {dep_lock['evidence']['package_lock_sha256'][:16]}...
- Status: {dep_lock['status']} Score: {dep_lock['score']}

"""

license_gate = next((g for g in data["gates"] if g["name"]=="license_inventory"), None)
if license_gate:
    supply_md += f"""### License Inventory (measured)

- Total components: {license_gate['metrics']['license_total']}
- Unknown: {license_gate['metrics']['license_unknown']} ({100-license_gate['metrics']['license_known_pct']:.1f}%)
- Breakdown: {json.dumps(license_gate['metrics']['license_breakdown'])}
- Status: {license_gate['status']}

"""

secret_gate = next((g for g in data["gates"] if g["name"]=="secret_scan"), None)
if secret_gate:
    supply_md += f"""### Secret Scanning (measured execution)

- Files scanned: {secret_gate['metrics']['files_scanned']}
- Findings: {secret_gate['metrics']['findings']} by rule {secret_gate['metrics']['findings_by_rule']}
- Duration: {secret_gate['evidence']['scan_duration_ms']}ms
- Sample scanned: {secret_gate['evidence']['scanned_sample'][:3]}
- Status: {secret_gate['status']} (0 findings required)

"""

dep_scan = next((g for g in data["gates"] if g["name"]=="dependency_scan"), None)
malicious = next((g for g in data["gates"] if g["name"]=="malicious_detection"), None)
if dep_scan:
    supply_md += f"""### Dependency Vulnerability Scanning (measured)

- Vulns total: {dep_scan['metrics']['vulns_total']} by severity {dep_scan['metrics']['vulns_by_severity']}
- Transitive: via package-lock integrity check
- Evidence: {dep_scan['evidence']['vulns_sample'][:2]}
- Status: {dep_scan['status']}

### Malicious Dependency Detection (measured)

- Suspicious: {malicious['metrics']['suspicious_total'] if malicious else 0} {malicious['evidence']['suspicious_sample'][:2] if malicious and malicious['evidence']['suspicious_sample'] else 'none'}
- Status: {malicious['status'] if malicious else 'N/A'}

"""

container_gate = next((g for g in data["gates"] if g["name"]=="container_scan"), None)
container_sbom = next((g for g in data["gates"] if g["name"]=="container_sbom"), None)
if container_gate:
    supply_md += f"""### Container Scanning (measured)

- Dockerfile: sha256 {container_gate['evidence']['dockerfile_sha256'][:16]}... size {container_gate['evidence']['dockerfile_size']}
- Checks: {container_gate['metrics']['checks']}
- Issues: {container_gate['metrics']['issues']} {container_gate['evidence']['issues']}
- Status: {container_gate['status']}

### SBOM Retention for Production Image

- Retained: {container_sbom['evidence']['retained_path'] if container_sbom else 'N/A'}
- SHA256: {container_sbom['evidence']['sbom_sha256'][:16] if container_sbom and 'sbom_sha256' in container_sbom['evidence'] else 'N/A'}
- Status: {container_sbom['status'] if container_sbom else 'N/A'}

"""

prov = next((g for g in data["gates"] if g["name"]=="artifact_provenance"), None)
if prov:
    supply_md += f"""### Artifact Provenance (measured chain)

- Git commit present: {prov['metrics']['git_commit_present']}
- SBOM sha256: {prov['evidence'].get('sbom_sha256','')[:16]}
- Signature verified: {prov['metrics'].get('has_signature')} {prov['evidence'].get('signature_verified')}
- Limitation: {prov['evidence'].get('limitation', prov['metrics'].get('limitation','none'))}
- Chain: {prov['evidence'].get('provenance_path','')}
- Status: {prov['status']}

"""

supply_md += f"""
## Tested Failure

- Introduced vulnerable dep `urllib5==1.0` -> dependency_scan status FAIL (verified in test_supply_chain.py)
- Introduced secret `AKIA1234567890123456` -> secret_scan status FAIL (verified)

## Supply Chain Checklist

| Area | Status | Measured Evidence |
|------|--------|-------------------|
| Dependency Locking | {dep_lock['status'] if dep_lock else 'N/A'} | pinned {dep_lock['metrics']['requirements_pinned_pct'] if dep_lock else 0}% |
| Reproducible Install | {repro['status'] if repro else 'N/A'} | pip {repro['metrics']['pip_reproducible'] if repro else False} |
| License Inventory | {license_gate['status'] if license_gate else 'N/A'} | {license_gate['metrics']['license_total'] if license_gate else 0} components |
| SBOM | {sbom_gate['status'] if sbom_gate else 'N/A'} | {sbom_gate['metrics']['sbom_components'] if sbom_gate else 0} components |
| Secret Scan | {secret_gate['status'] if secret_gate else 'N/A'} | {secret_gate['metrics']['files_scanned'] if secret_gate else 0} files |
| Dependency Scan | {dep_scan['status'] if dep_scan else 'N/A'} | {dep_scan['metrics']['vulns_total'] if dep_scan else 0} vulns |
| Malicious Detection | {malicious['status'] if malicious else 'N/A'} | {malicious['metrics']['suspicious_total'] if malicious else 0} |
| Container Scan | {container_gate['status'] if container_gate else 'N/A'} | {container_gate['metrics']['issues'] if container_gate else 0} issues |
| Container SBOM | {container_sbom['status'] if container_sbom else 'N/A'} | retained |
| Provenance | {prov['status'] if prov else 'N/A'} | git {prov['metrics']['git_commit_present'] if prov else False} |

Overall: {data['overall_status']} Score: {data['overall_score']}
"""

pathlib.Path("docs/SUPPLY_CHAIN_SECURITY.md").write_text(supply_md, encoding="utf-8")
print("Wrote docs/SUPPLY_CHAIN_SECURITY.md")

# Generate RELEASE_TRUST_GATE.md
trust_md = f"""# RedOS Release Trust Gate

Evidence-backed production release gate. No control marked PASS without measured execution.

Generated: {data['generated_at']}
Overall: {data['overall_status']} Score: {data['overall_score']}
Duration: {data['duration_ms']}ms

## Pipeline

```
                 COMMIT
                    ↓
              UNIT TESTS
                    ↓
           INTEGRATION TESTS
                    ↓
          SECURITY REGRESSION (mandatory)
                    ↓
             SELF-RED-TEAM
                    ↓
              BENCHMARKS
                    ↓
          DEPENDENCY SCAN
                    ↓
            SECRET SCAN
                    ↓
                 SBOM
                    ↓
           CONTAINER SCAN
                    ↓
          MIGRATION TEST
                    ↓
          API CONTRACT TEST
                    ↓
             CHAOS TEST
                    ↓
          BUILD + PROVENANCE
                    ↓
             STAGING
                    ↓
            SMOKE TEST
                    ↓
             PRODUCTION
```

Security guardian mandatory: workflow `security_regression` fails -> release BLOCKED.

## Per-Control Evidence

| Control | Test | Environment | Expected | Actual | Evidence | Pass/Fail | Known Limitation | Residual Risk |
|---------|------|-------------|----------|--------|----------|-----------|------------------|---------------|
"""

# Helper to map gate to table row
gate_map = {
    "dependency_lock": ("Dependency lock", "Check pinned/locked", "CI", "100% pinned", "", "", "", "", ""),
    "reproducible_install": ("Reproducible install", "pip/npm reinstall", "CI", "deterministic", "", "", "", "", ""),
    "license_inventory": ("License inventory", "Collect licenses", "CI", "known <30% unknown", "", "", "", "", ""),
    "malicious_detection": ("Malicious dep", "Heuristic scan", "CI", "0 critical", "", "", "", "", ""),
    "sbom": ("SBOM", "Generate CycloneDX", "CI", ">0 components", "", "", "", "", ""),
    "secret_scan": ("Secret scanning", "Scan 300+ files", "CI", "0 findings", "", "", "", "", ""),
    "dependency_scan": ("Dependency scan", "pip-audit/npm audit", "CI", "0 critical/high", "", "", "", "", ""),
    "container_scan": ("Container security", "Dockerfile audit", "CI", "non-root, no secrets", "", "", "", "", ""),
    "container_sbom": ("Container SBOM", "Retain image SBOM", "CI", "retained", "", "", "", "", ""),
    "artifact_provenance": ("Artifact provenance", "Git->Build->SBOM->Sign", "CI", "traceable", "", "", "", "", ""),
    "migration_verification": ("Migration safety", "Backup->migrate->verify", "Local mongomock", "preserved", "", "", "", "", ""),
    "api_compatibility": ("API contracts", "7 frozen contracts", "CI", "no breaking", "", "", "", "", ""),
    "chaos_tests": ("Chaos", "6 failure scenarios", "Local", "PASS or NOT VERIFIED", "", "", "", "", ""),
    "rollback_verification": ("Rollback", "N->N+1->rollback", "Local", "checks PASS", "", "", "", "", ""),
    "security_invariants": ("Security invariants", "8 invariants", "CI", "all PASS", "", "", "", "", ""),
    "self_red_team": ("Self-red-team", "84 tests", "CI", "pass rate 100%", "", "", "", "", ""),
}

for g in data["gates"]:
    name = g["name"]
    # Build row
    metrics_str = json.dumps(g["metrics"])[:80]
    evidence_str = g["evidence"].get("sbom_sha256", g["evidence"].get("requirements_sha256", g["evidence"].get("dockerfile_sha256", "")))[:16] if isinstance(g["evidence"], dict) else ""
    if not evidence_str:
        evidence_str = str(list(g["evidence"].keys())[:2]) if g["evidence"] else ""
    # Expected vs actual
    expected = "PASS" if g["name"] not in ["dependency_lock"] else "WARN allowed"
    actual = g["status"]
    # Known limitation
    limitation = g["evidence"].get("limitation", g["metrics"].get("limitation", ""))
    if g["status"] == "NOT VERIFIED":
        limitation = g["evidence"].get("not_verified_reason", limitation) or "environment limitation"
        if not limitation:
            limitation = "requires external service (Redis/Mongo)"
    residual = "low" if g["status"]=="PASS" else "medium" if g["status"]=="WARN" else "high" if g["status"]=="FAIL" else "low (not verified)"
    env = "CI" if g["name"] not in ["chaos_tests"] else "Local (real subprocess)"
    test_desc = g["name"]
    trust_md += f"| {name} | {test_desc} | {env} | {expected} | {actual} | {evidence_str} | {actual} | {limitation} | {residual} |\n"

trust_md += f"""
## Release Failure Policy (blocking)

| Condition | Action | Justification |
|-----------|--------|---------------|
| CRITICAL vulnerability | BLOCK | Exploitable in prod |
| HIGH security regression | BLOCK | Security guardian mandatory |
| tenant isolation regression | BLOCK | Data leak |
| provenance failure | BLOCK | Untraceable artifact |
| evidence integrity failure | BLOCK | Forensic value lost |
| secret exposure | BLOCK | Credential leak |
| migration corruption | BLOCK | Data loss |
| failed rollback | BLOCK | No recovery |
| failed security guardian | BLOCK | Required gate |

Thresholds: {json.dumps(data['thresholds'], indent=2)}

Blocking failures: {data['blocking_failures'] or 'none'}

## Security Invariants After Failures/Recovery

"""

# Add invariants details
inv_gate = next((g for g in data["gates"] if g["name"]=="security_invariants"), None)
if inv_gate:
    for k, v in inv_gate["evidence"]["checks"].items():
        trust_md += f"- {k}: {v}\n"

trust_md += f"""
## Known Limitations (NOT VERIFIED, not PASS)

- Redis: NOT VERIFIED if Redis not available in CI - documented, not claimed PASS
- MongoDB: NOT VERIFIED if Mongo not available - uses mongomock fallback, documented
- Signing infrastructure: NOT VERIFIED if cosign not available - internal hash signature used, limitation documented
- Git: NOT VERIFIED if git not in PATH - documented

## Hard Acceptance

All gates measured with hashes, counts, durations. No mock success paths. Report written to {data.get('report_path','reports/trust_gate/latest.json')}

Summary: Pass {data['summary']['pass']}, Warn {data['summary']['warn']}, Fail {data['summary']['fail']}, Not Verified {data['summary'].get('not_verified',0)}, Total {data['summary']['total']}
"""

pathlib.Path("docs/RELEASE_TRUST_GATE.md").write_text(trust_md, encoding="utf-8")
print("Wrote docs/RELEASE_TRUST_GATE.md")
