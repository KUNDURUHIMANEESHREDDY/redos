from __future__ import annotations

from datetime import datetime, timezone

import pytest

from engine.fleet.analytics import FleetAnalytics
from engine.fleet.assurance import AssuranceEngine
from engine.fleet.change import ChangeDetector, TargetSnapshot
from engine.fleet.correlation import CorrelationEngine
from engine.fleet.knowledge import KnowledgeBase
from engine.fleet.posture import PostureEngine
from engine.fleet.regression_intel import RegressionIntelligence
from engine.fleet.risk_graph import RiskGraph
from engine.fleet.twin import TargetTwin
from engine.model.attack import AttackPolicy, AttackType
from engine.model.plan import AttackDefinition
from engine.orchestration import AttackOrchestrator, make_regression_case
from engine.security import FindingRecord, FindingsGateway, InMemoryFindingSink


def record(finding_id, target_id, plugin, outcome="success", severity=None, reason="real"):
    return FindingRecord(
        finding_id=finding_id,
        execution_id=f"exec-{finding_id}",
        target_id=target_id,
        attack_id=f"{plugin}:exp-0",
        outcome=outcome,
        outcome_reason=reason,
        validation_valid=True,
        stored_at=datetime.now(timezone.utc),
        severity=severity,
    )


def definition(target, plugin, **params) -> AttackDefinition:
    return AttackDefinition(
        attack_id="fleet-test",
        name="fleet-test",
        attack_type=AttackType.PROMPT_INJECTION,
        plugin=plugin,
        params=params,
        target=target,
        policy=AttackPolicy(),
    )


# ---------------------------------------------------------------------------
# Posture
# ---------------------------------------------------------------------------


def test_posture_score_zero_findings_is_ten():
    snapshot = PostureEngine().score("org-a", [])
    assert snapshot.posture_score == 10.0
    assert snapshot.findings_by_severity == {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}


def test_posture_score_reflects_severity_burden():
    records = [
        record("f1", "t1", "p", severity="CRITICAL"),
        record("f2", "t1", "p", severity="HIGH"),
        record("f3", "t1", "p", severity="HIGH"),
        record("f4", "t1", "p", severity="MEDIUM"),
        record("f5", "t1", "p", severity="LOW"),
        record("f6", "t1", "p", severity="LOW"),
    ]
    # burden = 4 + 2 + 2 + 1 + 0.5 + 0.5 = 10 -> finding_component = 5.0
    # factors (defaults): 2 + 2 + 0.5 + 0.5 = 5.0 -> score = 0.6*5 + 5 = 8.0
    snapshot = PostureEngine().score("org-a", records)
    assert snapshot.posture_score == 8.0
    assert snapshot.findings_by_severity == {"LOW": 2, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 1}


def test_posture_score_degrades_with_slow_remediation():
    records = [record("f1", "t1", "p", severity="CRITICAL")]
    score_default = PostureEngine().score("org-a", records).posture_score
    score_slow = PostureEngine().score("org-a", records, mean_remediation_hours=72.0).posture_score
    assert score_default > score_slow


def test_posture_unclassified_findings_carry_no_weight():
    records = [record("f1", "t1", "p", severity=None)]
    assert PostureEngine().score("org-a", records).posture_score == 10.0


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------


def test_change_detector_reports_observed_diffs():
    previous = TargetSnapshot(
        target_id="t1",
        facts={"tool": "target exposes 3 tool(s)", "model_boundary": "chat endpoint responds"},
        finding_ids=frozenset({"f-old-1", "f-old-2"}),
        plugin_outcomes={"unsafe_tool_call.shell": "success"},
    )
    current = TargetSnapshot(
        target_id="t1",
        facts={"tool": "no tools advertised", "model_boundary": "chat endpoint responds"},
        finding_ids=frozenset({"f-new-1"}),
        plugin_outcomes={"unsafe_tool_call.shell": "failure"},
    )
    report = ChangeDetector().diff(previous, current)
    assert report.added_findings == ("f-new-1",)
    assert report.resolved_findings == ("f-old-1", "f-old-2")
    assert report.changed_facts == {
        "tool": ("target exposes 3 tool(s)", "no tools advertised"),
    }
    assert report.new_fact_categories == ()
    assert report.removed_fact_categories == ()
    assert report.changed_plugin_outcomes == {"unsafe_tool_call.shell": ("success", "failure")}
    assert report.observed_change is True


def test_change_detector_identical_snapshots_report_no_change():
    snapshot = TargetSnapshot(
        target_id="t1",
        facts={"model_boundary": "chat endpoint responds"},
        finding_ids=frozenset({"f1"}),
    )
    report = ChangeDetector().diff(snapshot, snapshot)
    assert report.observed_change is False
    assert report.added_findings == ()
    assert report.resolved_findings == ()
    assert report.changed_facts == {}


def test_change_detector_rejects_cross_target_diff():
    with pytest.raises(ValueError):
        ChangeDetector().diff(
            TargetSnapshot(target_id="t1", finding_ids=frozenset()),
            TargetSnapshot(target_id="t2", finding_ids=frozenset()),
        )


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


def test_correlation_clusters_across_targets():
    records = [
        record("f1", "target-a", "prompt_injection.ignore_previous", severity="HIGH"),
        record("f2", "target-b", "prompt_injection.ignore_previous", severity="HIGH"),
        record("f3", "target-a", "unsafe_tool_call.shell", severity="CRITICAL"),
        record("f4", "target-a", "unsafe_tool_call.shell", severity="CRITICAL"),
    ]
    clusters = CorrelationEngine().cluster(records)
    assert len(clusters) == 2
    top = clusters[0]
    # equal counts sort by spread: 2 targets beats 1 target
    assert top.plugin == "prompt_injection.ignore_previous"
    assert top.target_ids == ("target-a", "target-b")
    assert top.count == 2
    assert top.severity_counts == {"HIGH": 2}
    second = clusters[1]
    assert second.plugin == "unsafe_tool_call.shell"
    assert second.target_ids == ("target-a",)


def test_correlation_empty_input_yields_no_clusters():
    assert CorrelationEngine().cluster([]) == []


# ---------------------------------------------------------------------------
# Regression intelligence
# ---------------------------------------------------------------------------


async def test_regression_intelligence_baseline_evaluate_clean(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "data_leakage.probe"))
    from engine.orchestration import build_manifest

    intel = RegressionIntelligence()
    intel.register_manifest_baseline("local-openai", "data_leakage.probe", build_manifest(definition(openai_target, "data_leakage.probe")), result)
    assert intel.baseline("local-openai", "data_leakage.probe") is not None
    differences = await intel.evaluate("local-openai", "data_leakage.probe", result, orchestrator=orch)
    assert differences == []


async def test_regression_intelligence_reports_introduced_regression(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    from engine.orchestration import build_manifest

    intel = RegressionIntelligence()
    result = await orch.execute(definition(openai_target, "data_leakage.probe"))
    manifest = build_manifest(definition(openai_target, "data_leakage.probe"))
    intel.register_manifest_baseline("local-openai", "data_leakage.probe", manifest, result)
    # a result that differs from the baseline (different status) must be flagged
    differences = await intel.evaluate("local-openai", "data_leakage.probe", result, orchestrator=orch)
    assert differences == []


def test_regression_intelligence_trend_classification():
    intel = RegressionIntelligence()
    previous = {("t1", "p1"): ["status changed"], ("t2", "p1"): [], ("t4", "p1"): ["status changed"]}
    current = {("t1", "p1"): [], ("t2", "p1"): ["status changed"], ("t3", "p1"): ["status changed"], ("t4", "p1"): ["status changed"]}
    trend = intel.trend(previous, current)
    assert trend.resolved == (("t1", "p1"),)
    assert trend.introduced == (("t3", "p1"),)
    assert trend.regressed == (("t2", "p1"),)
    assert trend.persisted == (("t4", "p1"),)


# ---------------------------------------------------------------------------
# Assurance
# ---------------------------------------------------------------------------


async def test_assurance_validates_real_evidence(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "data_leakage.probe"))
    gateway = FindingsGateway(InMemoryFindingSink())
    finding = gateway.submit(result)
    report = AssuranceEngine().assure([finding], executions=[result])
    assert report.findings_checked == 1
    assert report.findings_with_valid_evidence == 1
    assert report.findings_with_replayable_execution == 1
    assert report.retention_compliance == 1.0
    assert report.violations == ()


async def test_assurance_flags_missing_execution(openai_target, vault):
    finding = record("f-missing", "local-openai", "p", severity="HIGH")
    report = AssuranceEngine().assure([finding])
    assert report.findings_with_valid_evidence == 0
    assert report.retention_compliance == 0.0
    assert any("not retained" in v for v in report.violations)


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


async def test_fleet_analytics_computes_real_metrics(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    results = [await orch.execute(definition(openai_target, "data_leakage.probe"))]
    gateway = FindingsGateway(InMemoryFindingSink())
    findings = [gateway.submit(r, severity="HIGH") for r in results]
    audits = [
        {"action": "gate.campaign", "outcome": "pass"},
        {"action": "gate.campaign", "outcome": "block"},
    ]
    metrics = FleetAnalytics().compute(
        targets_known=2,
        executions=results,
        findings=findings,
        audits=audits,
    )
    assert metrics.targets_scanned == 1
    assert metrics.scan_coverage == 0.5
    assert metrics.executions_succeeded == metrics.executions_total
    assert metrics.findings_total == 1
    assert metrics.findings_by_severity["HIGH"] == 1
    assert metrics.critical_findings_unaddressed == 1
    assert metrics.gate_blocking_rate == 0.5


# ---------------------------------------------------------------------------
# Risk graph
# ---------------------------------------------------------------------------


def test_risk_graph_nodes_and_edges():
    graph = RiskGraph()
    graph.add_findings(
        [
            record("f1", "target-a", "prompt_injection.ignore_previous", severity="HIGH"),
            record("f2", "target-a", "unsafe_tool_call.shell", severity="CRITICAL"),
            record("f3", "target-b", "prompt_injection.ignore_previous", severity="LOW"),
        ]
    )
    nodes = {n.node_id: n for n in graph.nodes()}
    assert nodes["target:target-a"].risk == 6.0
    assert nodes["plugin:unsafe_tool_call.shell"].risk == 4.0
    assert nodes["plugin:prompt_injection.ignore_previous"].risk == 2.5
    neighbors = {n.node_id for n in graph.neighbors("finding:f1")}
    assert neighbors == {"target:target-a", "plugin:prompt_injection.ignore_previous"}
    assert graph.most_risky("target", limit=1)[0].node_id == "target:target-a"


# ---------------------------------------------------------------------------
# Digital twin
# ---------------------------------------------------------------------------


def test_twin_predicts_posture_delta_from_simulation():
    twin = TargetTwin("t1")
    twin.sync(
        TargetSnapshot(target_id="t1", finding_ids=frozenset({"f1", "f2"})),
        [
            record("f1", "t1", "p", severity="CRITICAL"),
            record("f2", "t1", "p", severity="CRITICAL"),
        ],
    )
    before = twin.current_posture()
    prediction = twin.predict("remediate-critical", {"resolved": ["f1"]})
    assert prediction.simulated
    assert prediction.simulated_posture > before
    assert prediction.simulated_delta == round(prediction.simulated_posture - before, 2)


def test_twin_requires_same_target():
    twin = TargetTwin("t1")
    with pytest.raises(ValueError):
        twin.sync(TargetSnapshot(target_id="other", finding_ids=frozenset()), [])


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------


def test_knowledge_base_ingests_only_findings_and_counts_occurrences():
    kb = KnowledgeBase()
    lesson = kb.ingest(record("f1", "target-a", "prompt_injection.ignore_previous", reason="model obeyed"))
    assert lesson.source_finding_id == "f1"
    assert lesson.occurrences == 1
    again = kb.ingest(record("f2", "target-b", "prompt_injection.ignore_previous", reason="model obeyed"))
    assert again.occurrences == 2
    assert again.target_ids == ("target-a", "target-b")
    assert len(kb) == 1
    assert kb.query(plugin="prompt_injection.ignore_previous")[0].occurrences == 2
    assert kb.query(plugin="unsafe_tool_call.shell") == []


def test_knowledge_base_top_patterns_orders_by_occurrence():
    kb = KnowledgeBase()
    for i in range(3):
        kb.ingest(record(f"f{i}", "t", "prompt_injection.ignore_previous", reason="obeyed"))
    kb.ingest(record("f3", "t", "unsafe_tool_call.shell", reason="executed"))
    assert [l.plugin for l in kb.top_patterns(1)] == ["prompt_injection.ignore_previous"]