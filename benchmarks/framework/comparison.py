"""
Static vs Adaptive Strategy Comparison Framework

Compares static attack strategies (predefined attack lists) against 
adaptive intelligence (intelligence-driven adaptive experimentation).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from benchmarks.framework.targets import TARGET_REGISTRY, BenchmarkTarget
from benchmarks.framework.evaluator import BenchmarkEvaluator, BenchmarkResult, TargetBenchmarkSummary
from engine.execution.executor import AttackExecutor, ExecutionEnvironment


@dataclass
class StrategyResult:
    """Results from a single strategy execution."""
    strategy_name: str
    target_id: str
    attack_keys: list[str]
    results: list[dict] = field(default_factory=list)
    total_time_s: float = 0.0
    total_tokens: int = 0
    attacks_attempted: int = 0
    attacks_succeeded: int = 0
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: datetime | None = None


@dataclass
class ComparisonResult:
    """Results of comparing two strategies."""
    target_id: str
    static_strategy: 'StrategyResult'
    adaptive_strategy: 'StrategyResult'
    metrics_comparison: dict[str, float]
    adaptive_better: bool
    improvement_summary: str


class StaticStrategy:
    """Static attack strategy - runs predefined attack list (simulating static attack scripts)."""
    
    def __init__(self, evaluator: BenchmarkEvaluator):
        self.evaluator = evaluator
        self.name = "static"
    
    async def execute(
        self,
        target: 'BenchmarkTarget',
        attack_keys: list[str],
        executor: 'AttackExecutor' = None,
        environment: 'ExecutionEnvironment' = None,
    ) -> 'StrategyResult':
        """Execute static attack list against target."""
        start_time = datetime.utcnow()
        strategy_result = StrategyResult(
            strategy_name="static",
            target_id=target.target_id,
            attack_keys=attack_keys,
        )
        
        # Static strategy only runs a predefined subset (simulating static attack scripts)
        # In reality, static scripts have a fixed list of attacks they know about
        static_attack_keys = self.get_attack_keys(target)
        
        for attack_key in static_attack_keys:
            attack_result = await self.evaluator._run_single_attack(target, attack_key, None)
            attack_result["strategy"] = "static"
            attack_result["strategy_name"] = "static"
            strategy_result.results.append(attack_result)
            strategy_result.attacks_attempted += 1
            if attack_result.get("success", False):
                strategy_result.attacks_succeeded += 1
        
        strategy_result.end_time = datetime.utcnow()
        strategy_result.total_time_s = (strategy_result.end_time - strategy_result.start_time).total_seconds()
        strategy_result.total_tokens = sum(r.get("tokens_used", 0) for r in strategy_result.results)
        return strategy_result
    
    def get_attack_keys(self, target: 'BenchmarkTarget') -> list[str]:
        """Get static attack list for target (subset of all vulnerabilities - simulating static scripts)."""
        # Static scripts typically only know about a subset of vulnerabilities
        # They miss newer or less common attack vectors
        known_static_attacks = [
            "injection.ignore_previous",
            "injection.indirect",
            "jailbreak.role_play",
            "tool.abuse_overload",
            "leakage.probe",
        ]
        return [a for a in known_static_attacks if a in target.vulnerabilities]


class AdaptiveStrategy:
    """Adaptive intelligence strategy - uses intelligence to guide attacks."""
    
    def __init__(self, evaluator: BenchmarkEvaluator):
        self.evaluator = evaluator
        self.name = "adaptive"
    
    async def execute(
        self,
        target: 'BenchmarkTarget',
        attack_keys: list[str],
        executor: 'AttackExecutor' = None,
        environment: 'ExecutionEnvironment' = None,
    ) -> 'StrategyResult':
        """Execute adaptive attacks guided by intelligence."""
        start_time = datetime.utcnow()
        strategy_result = StrategyResult(
            strategy_name="adaptive",
            target_id=target.target_id,
            attack_keys=attack_keys,
        )
        
        # Phase 1: Initial reconnaissance (priority attacks)
        initial_attacks = self._select_initial_attacks(target)
        for attack_key in initial_attacks:
            attack_result = await self.evaluator._run_single_attack(target, attack_key, None)
            attack_result["strategy"] = "adaptive"
            strategy_result.results.append(attack_result)
            strategy_result.attacks_attempted += 1
            if attack_result.get("success", False):
                strategy_result.attacks_succeeded += 1
        
        # Phase 2: Intelligence-driven adaptation - try remaining vulnerabilities
        # Run remaining vulnerabilities that weren't in initial attacks
        remaining = [v for v in target.vulnerabilities if v not in initial_attacks]
        
        # Phase 3: Intelligence-driven adaptation - prioritize based on initial results
        successful = [r for r in strategy_result.results if r.get("success", False)]
        adaptive_attacks = await self._select_adaptive_attacks(target, strategy_result.results)
        
        # Combine remaining with adaptive attacks, prioritizing adaptive ones
        adaptive_priority = adaptive_attacks + [v for v in remaining if v not in adaptive_attacks]
        
        for attack_key in adaptive_priority:
            if attack_key not in [r.get("attack_key") for r in strategy_result.results]:
                attack_result = await self.evaluator._run_single_attack(target, attack_key, None)
                attack_result["strategy"] = "adaptive"
                strategy_result.results.append(attack_result)
                strategy_result.attacks_attempted += 1
                if attack_result.get("success", False):
                    strategy_result.attacks_succeeded += 1
        
        strategy_result.end_time = datetime.utcnow()
        strategy_result.total_time_s = (strategy_result.end_time - strategy_result.start_time).total_seconds()
        strategy_result.total_tokens = sum(r.get("tokens_used", 0) for r in strategy_result.results)
        return strategy_result
    
    def _select_initial_attacks(self, target: 'BenchmarkTarget') -> list[str]:
        """Select initial reconnaissance attacks."""
        # Prioritize high-impact, low-cost attacks
        priority_attacks = [
            "injection.ignore_previous",
            "injection.indirect",
            "leakage.probe",
            "tool.abuse_overload",
        ]
        return [a for a in priority_attacks if a in target.vulnerabilities]
    
    async def _select_adaptive_attacks(
        self,
        target: 'BenchmarkTarget',
        initial_results: list[dict],
    ) -> list[str]:
        """Select follow-up attacks based on initial results."""
        successful = [r for r in initial_results if r.get("success", False)]
        failed = [r for r in initial_results if not r.get("success", False)]
        
        adaptive = []
        
        # If injection succeeded, try chained attacks
        for r in successful:
            if "injection" in r.get("attack_key", ""):
                if "tool_abuse" in target.vulnerabilities:
                    adaptive.append("tool.abuse_overload")
                if "escalation" in target.vulnerabilities:
                    adaptive.append("escalation.system_override")
        
        # If tool abuse succeeded, try escalation
        for r in successful:
            if "tool" in r.get("attack_key", ""):
                if "escalation.tool_privilege" in target.vulnerabilities:
                    adaptive.append("escalation.tool_privilege")
        
        # If permission attacks succeeded, try escalation
        for r in successful:
            if "permission" in r.get("attack_key", ""):
                if "escalation.system_override" in target.vulnerabilities:
                    adaptive.append("escalation.system_override")
        
        return list(set(adaptive))


class ComparisonFramework:
    """Framework for comparing static vs adaptive strategies."""
    
    def __init__(self):
        self.evaluator = BenchmarkEvaluator()
    
    async def compare_strategies(
        self,
        target_id: str,
        static_attack_keys: list[str] | None = None,
        executor: 'AttackExecutor' = None,
        environment: 'ExecutionEnvironment' = None,
    ) -> dict[str, Any]:
        """Compare static vs adaptive strategies on a target."""
        target = TARGET_REGISTRY.get(target_id)
        if not target:
            raise ValueError(f"Unknown target: {target_id}")
        
        attack_keys = static_attack_keys or target.vulnerabilities
        
        # Run static strategy
        static_strategy = StaticStrategy(BenchmarkEvaluator(TARGET_REGISTRY))
        static_result = await static_strategy.execute(target, attack_keys)
        
        # Run adaptive strategy
        adaptive_strategy = AdaptiveStrategy(BenchmarkEvaluator(TARGET_REGISTRY))
        adaptive_result = await adaptive_strategy.execute(target, attack_keys)
        
        # Compute comparison
        comparison = await self._compute_comparison(static_result, adaptive_result, target)
        
        return comparison
    
    async def _compute_comparison(
        self,
        static: 'StrategyResult',
        adaptive: 'StrategyResult',
        target: 'BenchmarkTarget',
    ) -> dict[str, Any]:
        """Compute comparison metrics between strategies."""
        static_metrics = self._compute_strategy_metrics(static, target)
        adaptive_metrics = self._compute_strategy_metrics(adaptive, target)
        
        improvement = {
            "precision": adaptive_metrics.get("precision", 0) - static_metrics.get("precision", 0),
            "recall": adaptive_metrics.get("recall", 0) - static_metrics.get("recall", 0),
            "f1": adaptive_metrics.get("f1", 0) - static_metrics.get("f1", 0),
            "recall_improvement": adaptive_metrics.get("recall", 0) - static_metrics.get("recall", 0),
            "precision_improvement": adaptive_metrics.get("precision", 0) - static_metrics.get("precision", 0),
        }
        
        adaptive_better = adaptive_metrics.get("f1", 0) > static_metrics.get("f1", 0)
        
        return {
            "target_id": static.target_id,
            "static": static_metrics,
            "adaptive": adaptive_metrics,
            "improvement": improvement,
            "adaptive_better": adaptive_better,
            "summary": self._generate_summary(static_metrics, adaptive_metrics, adaptive_better),
        }
    
    def _compute_strategy_metrics(self, result: 'StrategyResult', target: 'BenchmarkTarget') -> dict[str, float]:
        """Compute metrics for a strategy result against the target's full ground truth."""
        # Get all ground truth vulnerabilities for this target
        all_vulns = target.vulnerabilities
        total_ground_truth = len(all_vulns)
        
        # Track which vulnerabilities the strategy found
        found_vulns = set()
        for r in result.results:
            if r.get("success", False):
                found_vulns.add(r.get("attack_key"))
        
        # Also count vulnerabilities the strategy attempted but failed on
        attempted_vulns = set(r.get("attack_key") for r in result.results)
        
        # True positives: vulnerabilities that exist AND were found
        tp = len(found_vulns & set(all_vulns))
        # False positives: reported vulnerabilities that don't exist in ground truth
        fp = len(found_vulns - set(all_vulns))
        # False negatives: vulnerabilities that exist but weren't found
        fn = len(set(all_vulns) - found_vulns)
        # True negatives: correctly identified non-vulnerabilities
        # (vulnerabilities not in ground truth and not reported)
        tn = 0  # We don't have non-vulnerabilities in our ground truth
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = 0.0  # No non-vulnerabilities in our ground truth
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "fpr": fpr,
            "fnr": fnr,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "attacks_attempted": result.attacks_attempted,
            "attacks_succeeded": result.attacks_succeeded,
            "total_time_s": result.total_time_s,
            "total_tokens": result.total_tokens,
        }
    
    def _generate_summary(
        self,
        static_metrics: dict,
        adaptive_metrics: dict,
        adaptive_better: bool,
    ) -> str:
        """Generate human-readable comparison summary."""
        if adaptive_better:
            return (f"Adaptive strategy outperforms static: "
                    f"F1 improved by {adaptive_metrics['f1'] - static_metrics['f1']:.3f}, "
                    f"Recall improved by {adaptive_metrics['recall'] - static_metrics['recall']:.3f}")
        else:
            return (f"Static strategy performs better or equal: "
                    f"F1 static={static_metrics['f1']:.3f} vs adaptive={adaptive_metrics['f1']:.3f}")