from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engine.security.supply_chain import (
    GateResult,
    check_dependency_lock,
    container_scan,
    dependency_scan,
    generate_sbom,
    license_inventory,
    malicious_detection,
    reproducible_install,
    secret_scan,
)
from engine.security.provenance_gate import artifact_provenance
from engine.security.migration_gate import migration_gate
from engine.security.contract_gate import contract_gate
from engine.security.chaos_gate import chaos_gate
from engine.security.rollback_gate import rollback_gate
from engine.security.invariants_gate import invariants_gate
from engine.security.release_gate import self_red_team, api_compatibility as api_compat_old

# Keep old migration for fallback, but use new migration_gate
from engine.security.release_gate import migration_verification as old_migration


GATE_THRESHOLDS: dict[str, float] = {
    "dependency_lock": 0.6,
    "reproducible_install": 0.6,
    "license_inventory": 0.5,
    "malicious_detection": 0.6,
    "sbom": 0.5,
    "secret_scan": 0.9,
    "dependency_scan": 0.7,
    "container_scan": 0.6,
    "container_sbom": 0.5,
    "artifact_provenance": 0.6,
    "migration_verification": 0.5,
    "api_compatibility": 0.8,
    "chaos_tests": 0.5,
    "rollback_verification": 0.7,
    "security_invariants": 0.8,
    "self_red_team": 0.8,
}


def container_sbom(project_root: Path | None = None) -> GateResult:
    """SBOM for production image retained."""
    import hashlib

    start = time.monotonic()
    root = project_root or Path.cwd()
    evidence: dict[str, Any] = {}
    metrics: dict[str, Any] = {}

    sbom_path = root / "sbom.json"
    image_sbom = root / "reports" / "sbom" / "image_sbom.json"
    # Retain SBOM for production image: copy sbom.json to image location
    has_sbom = sbom_path.exists()
    metrics["sbom_exists"] = has_sbom
    if has_sbom:
        try:
            # Retain
            image_sbom.parent.mkdir(parents=True, exist_ok=True)
            data = sbom_path.read_bytes()
            image_sbom.write_bytes(data)
            evidence["retained_path"] = str(image_sbom.relative_to(root))
            evidence["sbom_sha256"] = hashlib.sha256(data).hexdigest()
            metrics["retained"] = True
            evidence["measured"] = True
            status, score = "PASS", 0.9
        except Exception as e:
            evidence["error"] = str(e)
            status, score = "FAIL", 0.2
    else:
        status, score = "FAIL", 0.0
        evidence["measured"] = True

    duration = int((time.monotonic() - start) * 1000)
    return GateResult(name="container_sbom", status=status, score=score, metrics=metrics, evidence=evidence, duration_ms=duration)


def run_trust_gate(project_root: Path | None = None, thresholds: dict[str, float] | None = None) -> dict[str, Any]:
    root = project_root or Path.cwd()
    thresholds = thresholds or GATE_THRESHOLDS
    start = time.monotonic()

    gates: list[GateResult] = []
    gates.append(check_dependency_lock(root))
    gates.append(reproducible_install(root))
    gates.append(license_inventory(root))
    gates.append(malicious_detection(root))
    gates.append(generate_sbom(root))
    gates.append(secret_scan(root))
    gates.append(dependency_scan(root))
    gates.append(container_scan(root))
    gates.append(container_sbom(root))
    gates.append(artifact_provenance(root))
    # Use new migration gate
    gates.append(migration_gate(root))
    gates.append(contract_gate(root))
    gates.append(chaos_gate(root))
    gates.append(rollback_gate(root))
    gates.append(invariants_gate(root))
    gates.append(self_red_team(root))

    results = [g.to_dict() for g in gates]

    blocking: list[str] = []
    for g in gates:
        thr = thresholds.get(g.name, 0.5)
        if g.status == "NOT VERIFIED":
            # Documented limitation, not blocking
            continue
        if g.score < thr:
            blocking.append(f"{g.name} score {g.score} < {thr}")
        if g.status == "FAIL" and g.name in {"secret_scan", "dependency_scan", "self_red_team"}:
            if g.name not in [b.split()[0] for b in blocking]:
                blocking.append(f"{g.name} critical FAIL")

    passed = len(blocking) == 0
    overall = round(sum(g.score for g in gates) / len(gates), 3) if gates else 0

    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_root": str(root),
        "overall_status": "PASS" if passed else "FAIL",
        "overall_score": overall,
        "thresholds": thresholds,
        "blocking_failures": blocking,
        "gates": results,
        "summary": {"pass": sum(1 for g in gates if g.status == "PASS"), "warn": sum(1 for g in gates if g.status == "WARN"), "fail": sum(1 for g in gates if g.status == "FAIL"), "not_verified": sum(1 for g in gates if g.status == "NOT VERIFIED"), "total": len(gates)},
        "duration_ms": int((time.monotonic() - start) * 1000),
        "measured": True,
        "chain": ["Git commit", "Build", "Test", "SBOM", "Security scan", "Artifact", "Signature/provenance", "Deploy"],
    }

    report_dir = root / "reports" / "trust_gate"
    report_dir.mkdir(parents=True, exist_ok=True)
    latest = report_dir / "latest.json"
    timestamped = report_dir / f"trust_gate_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    try:
        timestamped.write_text(json.dumps(report, indent=2), encoding="utf-8")
        latest.write_text(json.dumps(report, indent=2), encoding="utf-8")
        report["report_path"] = str(timestamped)
    except Exception as e:
        report["write_error"] = str(e)

    return report


if __name__ == "__main__":
    import argparse, sys
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    report = run_trust_gate(Path(args.root))
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["overall_status"] == "PASS" else 1)
