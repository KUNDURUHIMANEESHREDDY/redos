"""
Benchmark Target Registry

Loads and manages benchmark targets with ground-truth vulnerabilities.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

from engine.targets.config import TargetConfig


class BenchmarkTarget:
    """Wrapper for a benchmark target with ground truth."""
    
    def __init__(self, module_path: Path):
        self.module_path = module_path
        self.target_config: TargetConfig | None = None
        self.expected_results: dict[str, Any] = {}
        self._load()
    
    def _load(self) -> None:
        """Load the target module and extract config and expected results."""
        spec = importlib.util.spec_from_file_location(
            self.module_path.stem, self.module_path
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Could not load module from {self.module_path}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[self.module_path.stem] = module
        spec.loader.exec_module(module)
        
        self.target_config = getattr(module, "TARGET_CONFIG", None)
        self.expected_results = getattr(module, "EXPECTED_RESULTS", {})
        
        if self.target_config is None:
            raise RuntimeError(f"No TARGET_CONFIG found in {self.module_path}")
    
    @property
    def target_id(self) -> str:
        return self.target_config.target_id if self.target_config else self.module_path.stem
    
    @property
    def vulnerabilities(self) -> list[str]:
        return self.target_config.extra.get("vulnerabilities", []) if self.target_config else []
    
    @property
    def ground_truth(self) -> dict[str, Any]:
        return self.target_config.extra.get("ground_truth", {}) if self.target_config else {}
    
    def get_expected_result(self, vuln_type: str) -> dict[str, Any] | None:
        """Get expected result for a specific vulnerability type."""
        return self.expected_results.get(vuln_type)
    
    def has_vulnerability(self, vuln_type: str) -> bool:
        """Check if ground truth says this vulnerability exists."""
        gt = self.ground_truth.get(vuln_type, {})
        return gt.get("exists", False)
    
    def get_ground_truth_indicators(self, vuln_type: str) -> list[str]:
        gt = self.ground_truth.get(vuln_type, {})
        return gt.get("indicators", [])
    
    def get_ground_truth_cvss(self, vuln_type: str) -> float:
        gt = self.ground_truth.get(vuln_type, {})
        return gt.get("cvss", 0.0)
    
    def should_succeed(self, vuln_type: str) -> bool:
        expected = self.expected_results.get(vuln_type, {})
        return expected.get("should_succeed", False)


class TargetRegistry:
    """Registry of all benchmark targets."""
    
    def __init__(self, targets_dir: Path = None):
        self.targets_dir = targets_dir or Path(__file__).parent.parent / "targets"
        self._targets: dict[str, BenchmarkTarget] = {}
        self._load_all()
    
    def _load_all(self) -> None:
        """Load all benchmark targets from the targets directory."""
        for file_path in self.targets_dir.glob("*_v1.py"):
            try:
                target = BenchmarkTarget(file_path)
                self._targets[target.target_id] = target
            except Exception as e:
                print(f"Warning: Failed to load target from {file_path}: {e}")
    
    def get(self, target_id: str) -> BenchmarkTarget | None:
        return self._targets.get(target_id)
    
    def all(self) -> list[BenchmarkTarget]:
        return list(self._targets.values())
    
    def by_vulnerability(self, vuln_type: str) -> list[BenchmarkTarget]:
        """Get all targets that have a specific vulnerability."""
        return [t for t in self._targets.values() if vuln_type in t.vulnerabilities]
    
    def all_vulnerabilities(self) -> set[str]:
        """Get all unique vulnerability types across all targets."""
        vulns = set()
        for target in self._targets.values():
            vulns.update(target.vulnerabilities)
        return vulns
    
    def __len__(self) -> int:
        return len(self._targets)
    
    def __contains__(self, target_id: str) -> bool:
        return target_id in self._targets
    
    def __iter__(self):
        return iter(self._targets.values())


# Global registry instance
TARGET_REGISTRY = TargetRegistry()