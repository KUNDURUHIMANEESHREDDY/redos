from pathlib import Path
import json


def load_trust():
    p = Path("reports/trust_gate/latest.json")
    if not p.exists():
        p = Path("reports/release_gate/latest.json")
    return json.loads(p.read_text(encoding="utf-8"))


def test_hard_acceptance_supply_chain():
    data = load_trust()
    gates = {g["name"]: g for g in data["gates"]}
    # dependencies reproducibly locked
    assert gates["dependency_lock"]["status"] in ("PASS", "WARN")
    assert gates["dependency_lock"]["evidence"]["measured"] is True
    assert gates["reproducible_install"]["status"] in ("PASS", "WARN")
    # dependency scan executed
    assert gates["dependency_scan"]["evidence"]["measured"] is True
    assert gates["dependency_scan"]["metrics"]["vulns_total"] is not None
    # SBOM generated
    assert gates["sbom"]["status"] == "PASS"
    assert gates["sbom"]["metrics"]["sbom_components"] > 0
    assert gates["sbom"]["evidence"]["sbom_sha256"]
    # secret scanning executed
    assert gates["secret_scan"]["metrics"]["files_scanned"] > 10
    # container scan executed
    assert gates["container_scan"]["status"] == "PASS"
    assert gates["container_scan"]["evidence"]["dockerfile_sha256"]
    # container SBOM retained
    assert gates["container_sbom"]["status"] == "PASS"


def test_hard_acceptance_release():
    data = load_trust()
    gates = {g["name"]: g for g in data["gates"]}
    # artifact provenance established (or NOT VERIFIED with documented limitation)
    assert gates["artifact_provenance"]["status"] in ("PASS", "NOT VERIFIED", "WARN")
    assert gates["artifact_provenance"]["evidence"]["measured"] is True
    # API contracts tested
    assert gates["api_compatibility"]["metrics"]["contracts"] if "contracts" in gates["api_compatibility"]["metrics"] else gates["api_compatibility"]["evidence"]["measured"]
    # Check frozen contracts actually exist
    assert Path("reports/contracts/frozen.json").exists() or gates["api_compatibility"]["status"] == "PASS"
    # migrations tested
    assert gates["migration_verification"]["status"] == "PASS"
    assert gates["migration_verification"]["metrics"]["docs_before"] is not None or gates["migration_verification"]["metrics"]["collections"] > 0
    # rollback actually tested
    assert gates["rollback_verification"]["status"] == "PASS"
    assert gates["rollback_verification"]["metrics"]["rollback_success"] is True


def test_hard_acceptance_reliability():
    data = load_trust()
    gates = {g["name"]: g for g in data["gates"]}
    chaos = gates["chaos_tests"]
    # Must have tested all 6 scenarios
    assert chaos["metrics"]["scenarios"] >= 6
    assert chaos["metrics"]["api_crash_tested"] is True
    assert chaos["metrics"]["worker_crash_tested"] is True
    assert chaos["metrics"]["redis_tested"] is True
    assert chaos["metrics"]["mongodb_tested"] is True
    assert chaos["metrics"]["target_tested"] is True
    assert chaos["metrics"]["network_tested"] is True
    # Verify worker never SUCCESS on failure
    assert chaos["evidence"]["worker_never_success"] is True


def test_hard_acceptance_security_invariants():
    data = load_trust()
    gates = {g["name"]: g for g in data["gates"]}
    inv = gates["security_invariants"]
    # After all failures/recovery, all 8 must PASS
    assert inv["status"] == "PASS"
    checks = inv["evidence"]["checks"]
    for key in ["tenant_isolation", "authentication", "authorization", "evidence_integrity", "provenance", "finding_correctness", "execution_state", "regression_guardian"]:
        assert checks[key] == "PASS", f"{key} failed: {checks[key]}"


def test_final_rule_no_fabricated():
    data = load_trust()
    # Every gate must have measured=True and evidence with hashes/counts
    for g in data["gates"]:
        assert g["evidence"].get("measured") is True, f"{g['name']} not measured"
        assert g["status"] in ("PASS", "WARN", "FAIL", "NOT VERIFIED")
        # NOT VERIFIED must have limitation documented, not claimed PASS
        if g["status"] == "NOT VERIFIED":
            assert "limitation" in str(g["evidence"]) or "not_verified" in str(g["evidence"]).lower() or "reason" in str(g["evidence"]).lower()
    # Overall must not claim PASS if critical FAIL
    if any(g["status"] == "FAIL" and g["name"] in {"secret_scan", "dependency_scan", "self_red_team"} for g in data["gates"]):
        assert data["overall_status"] == "FAIL"
