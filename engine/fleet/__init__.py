"""Agent 2 fleet intelligence layers: posture, change detection, correlation,
regression intelligence, assurance, analytics, risk graph, digital twin, and
knowledge base. All layers consume records produced by the engine and reuse
existing machinery (replay, evidence-chain validation, findings gateway);
none of them fabricate evidence.
"""

from engine.fleet.analytics import FleetAnalytics, FleetMetrics
from engine.fleet.assurance import AssuranceEngine, AssuranceReport
from engine.fleet.change import ChangeDetector, ChangeReport, TargetSnapshot
from engine.fleet.correlation import CorrelationCluster, CorrelationEngine
from engine.fleet.knowledge import KnowledgeBase, KnowledgeLesson
from engine.fleet.posture import PostureEngine, PostureSnapshot
from engine.fleet.regression_intel import RegressionIntelligence, RegressionTrend
from engine.fleet.risk_graph import RiskGraph
from engine.fleet.twin import TargetTwin

__all__ = [
    "AssuranceEngine",
    "AssuranceReport",
    "ChangeDetector",
    "ChangeReport",
    "CorrelationCluster",
    "CorrelationEngine",
    "FleetAnalytics",
    "FleetMetrics",
    "KnowledgeBase",
    "KnowledgeLesson",
    "PostureEngine",
    "PostureSnapshot",
    "RegressionIntelligence",
    "RegressionTrend",
    "RiskGraph",
    "TargetSnapshot",
    "TargetTwin",
]