# RedOS Supply Chain Security

## Overview
Evidence-backed supply chain security verification. All controls measured, not declared.

Generated: 2026-08-21T18:22:36.940783+00:00
Overall Score: 0.933 Status: PASS

## Dependency Chain Analysis

### Direct Dependencies (measured from SBOM)

- SBOM Components: 459
- Hashed: 96.3%
- Evidence: 11ce9dd5d1bc1bea... size 105427
- Tool: internal

### Dependency Locking (measured)

- requirements.txt: 17 deps, pinned 100.0%, hashed 0.0%
- package-lock.json: lockfileVersion 3, integrity 99.8%
- reproducible: pip True, npm True
- Evidence: requirements_sha256 a78d98dc1206157b..., package-lock_sha256 8e9d6609a518fad0...
- Status: WARN Score: 0.9

### License Inventory (measured)

- Total components: 883
- Unknown: 123 (13.9%)
- Breakdown: {"MIT": 517, "Apache": 39, "Apache-2.0": 27, "BSD-3-Clause": 27, "ISC": 26, "MIT License": 23, "BSD": 20, "Apache Software License": 20, "BSD-2-Clause": 13, "BSD License": 10}
- Status: PASS

### Secret Scanning (measured execution)

- Files scanned: 328
- Findings: 0 by rule {'aws_access_key': 0, 'aws_secret': 0, 'generic_api_key': 0, 'private_key': 0, 'jwt': 0, 'generic_secret': 0, 'high_entropy': 0}
- Duration: 775ms
- Sample scanned: ['.env.example', 'package.json', 'pyproject.toml']
- Status: PASS (0 findings required)

### Dependency Vulnerability Scanning (measured)

- Vulns total: 0 by severity {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
- Transitive: via package-lock integrity check
- Evidence: []
- Status: PASS

### Malicious Dependency Detection (measured)

- Suspicious: 0 none
- Status: PASS

### Container Scanning (measured)

- Dockerfile: sha256 bddc7d8b6f16b1ea... size 969
- Checks: {'minimal_base_image': True, 'no_latest_tag': True, 'non_root_user': True, 'no_unnecessary_packages': True, 'no_unnecessary_capabilities': True, 'filesystem_restrictions': True, 'secret_handling': True, 'environment_handling': True, 'healthcheck': True, 'resource_limits': True, 'multi_stage': True}
- Issues: 0 []
- Status: PASS

### SBOM Retention for Production Image

- Retained: reports\sbom\image_sbom.json
- SHA256: 11ce9dd5d1bc1bea
- Status: PASS

### Artifact Provenance (measured chain)

- Git commit present: False
- SBOM sha256: 11ce9dd5d1bc1bea
- Signature verified: True True
- Limitation: no git commit traceability - git not available in environment, documented as NOT VERIFIED
- Chain: reports\provenance\provenance_no-git.json
- Status: NOT VERIFIED


## Tested Failure

- Introduced vulnerable dep `urllib5==1.0` -> dependency_scan status FAIL (verified in test_supply_chain.py)
- Introduced secret `AKIA1234567890123456` -> secret_scan status FAIL (verified)

## Supply Chain Checklist

| Area | Status | Measured Evidence |
|------|--------|-------------------|
| Dependency Locking | WARN | pinned 100.0% |
| Reproducible Install | PASS | pip True |
| License Inventory | PASS | 883 components |
| SBOM | PASS | 459 components |
| Secret Scan | PASS | 328 files |
| Dependency Scan | PASS | 0 vulns |
| Malicious Detection | PASS | 0 |
| Container Scan | PASS | 0 issues |
| Container SBOM | PASS | retained |
| Provenance | NOT VERIFIED | git False |

Overall: PASS Score: 0.933
