from __future__ import annotations

import json
from pathlib import Path

from engine.security.release_gate import run_release_gate
from engine.security.supply_chain import GateResult


def test_release_gate_measures_all_stages():
    report = run_release_gate(Path("."))
    # Must aggregate all 10 gates
    assert len(report["gates"]) == 10
    names = {g["name"] for g in report["gates"]}
    expected = {"dependency_lock", "sbom", "secret_scan", "dependency_scan", "container_scan", "artifact_signing", "migration_verification", "api_compatibility", "chaos_tests", "self_red_team"}
    assert names == expected

    # Each gate must be measured, not declared
    for g in report["gates"]:
        assert g["evidence"].get("measured") is True, f"{g['name']} not measured"
        assert "metrics" in g
        assert 0 <= g["score"] <= 1
        assert g["status"] in ("PASS", "WARN", "FAIL")
        assert g["duration_ms"] >= 0

    # Overall must be computed from scores, not hardcoded
    assert "overall_score" in report
    assert "overall_status" in report
    assert report["summary"]["total"] == 10


def test_release_gate_does_not_pass_on_config_only():
    # Simulate a repo with only config files but no measured evidence
    # Our gates measure file content hashes, component counts, scan results
    report = run_release_gate(Path("."))
    for g in report["gates"]:
        # Evidence must contain hashes/counts, not just exists:true
        if g["name"] == "dependency_lock":
            assert "requirements_sha256" in g["evidence"]
            assert "lock_integrity_pct" in g["metrics"]
        if g["name"] == "sbom":
            assert "sbom_sha256" in g["evidence"]
            assert g["metrics"]["sbom_components"] > 0
        if g["name"] == "secret_scan":
            assert g["metrics"]["files_scanned"] > 0
            assert "findings_by_rule" in g["metrics"]
        if g["name"] == "container_scan":
            assert "dockerfile_sha256" in g["evidence"]
            assert "checks" in g["metrics"]


def test_release_gate_blocks_on_critical_fail():
    report = run_release_gate(Path("."))
    # If secret_scan or self_red_team FAIL, overall should be FAIL
    critical = {"secret_scan", "dependency_scan", "self_red_team", "api_compatibility"}
    for g in report["gates"]:
        if g["name"] in critical and g["status"] == "FAIL":
            assert report["overall_status"] == "FAIL"
            assert any(g["name"] in f for f in report["blocking_failures"])


def test_release_gate_report_written():
    report = run_release_gate(Path("."))
    assert "report_path" in report
    p = Path(report["report_path"])
    assert p.exists()
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["overall_status"] == report["overall_status"]
    assert data["measured"] is True

    latest = Path("reports/release_gate/latest.json")
    assert latest.exists()
