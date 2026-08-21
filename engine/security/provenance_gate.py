from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engine.security.supply_chain import GateResult


def artifact_provenance(project_root: Path | None = None) -> GateResult:
    start = time.monotonic()
    root = project_root or Path.cwd()
    evidence: dict[str, Any] = {}
    metrics: dict[str, Any] = {}

    # Measure Git commit
    git_commit = ""
    git_dirty = False
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, timeout=5, cwd=str(root))
        if result.returncode == 0:
            git_commit = result.stdout.decode().strip()
            evidence["git_commit"] = git_commit
            # Check dirty
            r2 = subprocess.run(["git", "status", "--porcelain"], capture_output=True, timeout=5, cwd=str(root))
            git_dirty = bool(r2.stdout.decode().strip())
            evidence["git_dirty"] = git_dirty
            # Tag
            r3 = subprocess.run(["git", "describe", "--tags", "--always"], capture_output=True, timeout=5, cwd=str(root))
            if r3.returncode == 0:
                evidence["git_tag"] = r3.stdout.decode().strip()
    except Exception as e:
        evidence["git_error"] = str(e)

    metrics["git_commit_present"] = bool(git_commit)
    metrics["git_dirty"] = git_dirty

    # Measure Build artifact traceability
    sbom_path = root / "sbom.json"
    sbom_hash = ""
    if sbom_path.exists():
        sbom_hash = hashlib.sha256(sbom_path.read_bytes()).hexdigest()
        evidence["sbom_sha256"] = sbom_hash
        evidence["sbom_size"] = sbom_path.stat().st_size
        metrics["sbom_exists"] = True
    else:
        metrics["sbom_exists"] = False

    # Simulate build artifact: hash of deployment/Dockerfile + package-lock
    build_inputs = []
    for p in [root / "deployment" / "Dockerfile", root / "package-lock.json", root / "requirements.txt"]:
        if p.exists():
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            build_inputs.append({"path": str(p.relative_to(root)), "sha256": h[:16]})
    evidence["build_inputs"] = build_inputs
    metrics["build_inputs"] = len(build_inputs)

    # Artifact signature/provenance: check for sbom.sig and provenance file
    sig_path = root / "sbom.json.sig"
    provenance_path = root / "reports" / "provenance" / "latest.json"
    has_sig = sig_path.exists()
    has_provenance = provenance_path.exists()
    metrics["has_signature"] = has_sig
    metrics["has_provenance"] = has_provenance

    # Try to verify signature if present
    verified = False
    sig_valid = None
    if has_sig and sbom_hash:
        try:
            sig_content = sig_path.read_text(encoding="utf-8")
            m = re.search(r"sha256:([a-f0-9]{64})", sig_content)
            if m:
                expected = m.group(1)
                sig_valid = (expected == sbom_hash)
                verified = sig_valid
                evidence["signature_verified"] = sig_valid
                evidence["signature_sha256"] = m.group(1)[:16]
            else:
                evidence["signature_format_unknown"] = True
        except Exception as e:
            evidence["signature_verify_error"] = str(e)

    # Generate provenance file for traceability: Git commit -> Build -> SBOM -> Scan -> Artifact -> Signature -> Deploy
    provenance_data = {
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "build_inputs": build_inputs,
        "sbom_sha256": sbom_hash,
        "sbom_components": 0,
        "signature_verified": verified,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chain": ["Git commit", "Build", "Test", "SBOM", "Security scan", "Artifact", "Signature/provenance", "Deploy"],
    }
    # Get SBOM components if exists
    if sbom_path.exists():
        try:
            data = json.loads(sbom_path.read_text(encoding="utf-8"))
            comps = data.get("components") or []
            provenance_data["sbom_components"] = len(comps)
        except Exception:
            pass

    # Write provenance
    provenance_dir = root / "reports" / "provenance"
    provenance_dir.mkdir(parents=True, exist_ok=True)
    prov_file = provenance_dir / f"provenance_{git_commit[:7] if git_commit else 'no-git'}.json"
    latest = provenance_dir / "latest.json"
    try:
        prov_file.write_text(json.dumps(provenance_data, indent=2), encoding="utf-8")
        latest.write_text(json.dumps(provenance_data, indent=2), encoding="utf-8")
        evidence["provenance_path"] = str(prov_file.relative_to(root))
        evidence["provenance_written"] = True
    except Exception as e:
        evidence["provenance_write_error"] = str(e)

    evidence["measured"] = True

    # Determine status: need git commit + SBOM + signature chain
    # If signing infrastructure cannot be executed, document limitation rather than claim PASS
    if not git_commit:
        status, score = "NOT VERIFIED", 0.6
        metrics["limitation"] = "no git commit traceability - git not available in environment, documented as NOT VERIFIED"
        evidence["not_verified"] = True
    elif git_dirty:
        status, score = "WARN", 0.5
        metrics["limitation"] = "dirty working tree"
    elif not sbom_hash:
        status, score = "FAIL", 0.2
    elif not has_sig:
        status, score = "WARN", 0.6
        evidence["limitation"] = "signing infrastructure not executed in environment - documented not passed"
    elif not verified:
        status, score = "FAIL", 0.3
    else:
        status, score = "PASS", 0.95

    # If cannot verify signature due to missing tooling, mark as NOT VERIFIED not PASS
    if has_sig and sig_valid is False:
        evidence["signature_status"] = "FAIL"
    elif has_sig and sig_valid is True:
        evidence["signature_status"] = "PASS"
    elif has_sig:
        evidence["signature_status"] = "NOT VERIFIED - tooling limitation documented"

    duration = int((time.monotonic() - start) * 1000)
    return GateResult(name="artifact_provenance", status=status, score=score, metrics=metrics, evidence=evidence, duration_ms=duration)
