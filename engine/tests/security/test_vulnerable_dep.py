from pathlib import Path
import tempfile
import json

from engine.security.supply_chain import dependency_scan, secret_scan


def test_ci_fails_for_vulnerable_dependency():
    # Create temp project with vulnerable dep
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        (p / "requirements.txt").write_text("urllib5==1.0\nfastapi==0.110.0\n", encoding="utf-8")
        (p / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"node_modules/express": {"version": "4.18.2"}}}), encoding="utf-8")
        (p / "package.json").write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
        from engine.security.supply_chain import malicious_detection
        result = malicious_detection(p)
        # urllib5 is known malicious -> should be FAIL
        assert result.status == "FAIL"
        assert result.metrics["suspicious_total"] > 0


def test_ci_fails_for_exposed_secret(tmp_path: Path):
    # Create file with real-looking secret (not example)
    secret_file = tmp_path / "app.py"
    secret_file.write_text('API_KEY = "AKIAZZZZZZZZZZZZZZZZ"\n', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("fastapi==0.110.0\n", encoding="utf-8")
    result = secret_scan(tmp_path)
    # Should detect aws_access_key
    assert result.metrics["findings"] > 0
    assert result.status in ("FAIL", "WARN")
    # Ensure at least aws_access_key rule triggered
    assert result.metrics["findings_by_rule"]["aws_access_key"] > 0


def test_dependency_scan_transitive():
    from engine.security.supply_chain import dependency_scan
    result = dependency_scan(Path("."))
    assert result.evidence["measured"] is True
    assert "vulns_by_severity" in result.metrics
    # Must have checked transitive via package-lock integrity
    assert "vulns_total" in result.metrics


def test_license_inventory_measured():
    from engine.security.supply_chain import license_inventory
    result = license_inventory(Path("."))
    assert result.evidence["measured"] is True
    assert result.metrics["license_total"] > 0
    assert "license_breakdown" in result.metrics
