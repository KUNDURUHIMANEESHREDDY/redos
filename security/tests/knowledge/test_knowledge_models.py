"""
Tests for knowledge models
"""
import pytest
from uuid import uuid4
from datetime import datetime
from security.knowledge.models import (
    KnowledgeEntry,
    KnowledgeType,
    KnowledgeStatus,
    AttackPattern,
    VulnerabilityPattern,
    RemediationPattern,
    RegressionPattern,
    TargetProfile,
    CampaignStrategy,
    KnowledgeEntrySearch,
)


class TestKnowledgeModels:
    def test_knowledge_entry_creation(self):
        entry = KnowledgeEntry(
            knowledge_type=KnowledgeType.ATTACK_PATTERN,
            title="SQL Injection Attack",
            description="SQL injection attack pattern",
            content={"vector": "sql_injection", "steps": ["inject", "exploit"]},
            status=KnowledgeStatus.DRAFT,
            confidence=0.8,
            tags=["sql_injection", "injection"],
            mitre_techniques=["T1190"],
            vulnerability_types=["sql_injection"],
        )
        assert entry.entry_id is not None
        assert entry.knowledge_type == KnowledgeType.ATTACK_PATTERN
        assert entry.confidence == 0.8

    def test_knowledge_entry_with_evidence_and_findings(self):
        evidence_id = uuid4()
        finding_id = uuid4()
        entry = KnowledgeEntry(
            knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
            title="SQL Injection Pattern",
            description="SQL injection vulnerability pattern",
            evidence_ids=[evidence_id],
            finding_ids=[finding_id],
            affected_targets=[uuid4()],
            related_entries=[uuid4()],
        )
        assert len(entry.evidence_ids) == 1
        assert len(entry.finding_ids) == 1

    def test_attack_pattern(self):
        pattern = AttackPattern(
            entry_id=uuid4(),
            name="SQL Injection",
            description="SQL injection via user input",
            attack_vector="sql_injection",
            prerequisites=["User input not sanitized", "Direct query execution"],
            steps=[
                {"step": 1, "action": "Inject SQL payload"},
                {"step": 2, "action": "Extract data"},
            ],
            mitre_techniques=["T1190"],
            mitre_tactics=["initial_access"],
            indicators=["SQL error messages", "Unexpected data return"],
            exploitability=0.9,
            impact=0.8,
            countermeasures=["Parameterized queries", "Input validation"],
        )
        assert pattern.attack_vector == "sql_injection"
        assert "T1190" in pattern.mitre_techniques
        assert pattern.exploitability == 0.9

    def test_vulnerability_pattern(self):
        pattern = VulnerabilityPattern(
            entry_id=uuid4(),
            vulnerability_type="sql_injection",
            root_cause_pattern="Direct string concatenation in SQL query",
            common_locations=["login.py", "search.py"],
            trigger_conditions=["User input in WHERE clause"],
            exploit_patterns=["' OR '1'='1", "UNION SELECT"],
            detection_signatures=["SQL error messages", "Unexpected row counts"],
            remediation_patterns=["Use parameterized queries", "Input validation"],
            false_positive_patterns=["Legitimate SQL in comments"],
            severity_distribution={"critical": 5, "high": 10, "medium": 3},
            confidence=0.85,
        )
        assert pattern.vulnerability_type == "sql_injection"
        assert pattern.confidence == 0.85
        assert len(pattern.common_locations) == 2

    def test_remediation_pattern(self):
        pattern = RemediationPattern(
            entry_id=uuid4(),
            vulnerability_type="sql_injection",
            title="Parameterized Queries",
            description="Use parameterized queries to prevent SQL injection",
            remediation_steps=[
                "Identify all SQL queries using string concatenation",
                "Replace with parameterized queries",
                "Test with SQL injection payloads",
            ],
            code_examples={
                "python_bad": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
                "python_good": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
            },
            configuration_changes=[{"setting": "db.driver", "value": "parameterized"}],
            verification_steps=["Test with SQL injection payloads", "Verify query execution"],
            effectiveness=0.95,
            effort_estimate="low",
        )
        assert pattern.vulnerability_type == "sql_injection"
        assert pattern.effectiveness == 0.95
        assert "python_bad" in pattern.code_examples

    def test_regression_pattern(self):
        pattern = RegressionPattern(
            entry_id=uuid4(),
            vulnerability_type="sql_injection",
            regression_triggers=["system_prompt_change", "tool_permission_change"],
            detection_patterns=["' OR '1'='1", "UNION SELECT"],
            recurrence_rate=0.15,
            typical_time_to_regression=30,
            prevention_strategies=["Monitor for system prompt changes", "Validate tool permissions after changes"],
            detection_rules=["Check for ' OR '1'='1 in input"],
            confidence=0.8,
        )
        assert pattern.vulnerability_type == "sql_injection"
        assert pattern.recurrence_rate == 0.15
        assert "system_prompt_change" in pattern.regression_triggers

    def test_target_profile(self):
        profile = TargetProfile(
            target_id=uuid4(),
            target_type="llm_model",
            attack_surface_summary={"total_findings": 10, "by_type": {"sql_injection": 3, "xss": 2}},
            common_vulnerabilities=["sql_injection", "xss"],
            common_attack_vectors=["prompt_injection", "sql_injection"],
            risk_profile="high",
            defense_posture={"remediation_velocity": 0.8, "regression_rate": 0.1},
            historical_regressions=2,
            remediation_velocity=0.8,
            attack_success_rate=0.15,
        )
        assert profile.target_type == "llm_model"
        assert profile.risk_profile == "high"
        assert profile.remediation_velocity == 0.8

    def test_campaign_strategy(self):
        strategy = CampaignStrategy(
            name="Prompt Injection First",
            description="Start with prompt injection for LLM models",
            target_types=["llm_model", "rag_system"],
            attack_vectors=["prompt_injection", "jailbreak", "system_prompt_leak"],
            phases=[
                {"name": "recon", "vectors": ["prompt_injection", "tool_discovery"]},
                {"name": "exploitation", "vectors": ["sql_injection", "command_injection"]},
            ],
            success_rate=0.75,
            avg_findings_per_run=3.5,
            avg_critical_findings=0.8,
            recommended_targets=["llm_model", "rag_system"],
            prerequisites=["Target has LLM endpoint"],
            estimated_duration=30,
            success_criteria=["Find at least 1 critical", "Coverage > 60%"],
        )
        assert strategy.success_rate == 0.75
        assert "llm_model" in strategy.target_types

    def test_knowledge_entry_search(self):
        search = KnowledgeEntrySearch(
            query="sql injection",
            knowledge_types=[KnowledgeType.ATTACK_PATTERN, KnowledgeType.VULNERABILITY_PATTERN],
            statuses=["verified"],
            tags=["sql_injection"],
            mitre_techniques=["T1190"],
            vulnerability_types=["sql_injection"],
            target_ids=[uuid4()],
            min_confidence=0.7,
            date_from=datetime.utcnow(),
            date_to=datetime.utcnow(),
            limit=20,
            offset=0,
        )
        assert search.query == "sql injection"
        assert KnowledgeType.ATTACK_PATTERN in search.knowledge_types
        assert search.min_confidence == 0.7

    def test_knowledge_type_enum(self):
        assert KnowledgeType.ATTACK_PATTERN.value == "attack_pattern"
        assert KnowledgeType.VULNERABILITY_PATTERN.value == "vulnerability_pattern"
        assert KnowledgeType.REMEDIATION_PATTERN.value == "remediation_pattern"
        assert KnowledgeType.REGRESSION_PATTERN.value == "regression_pattern"

    def test_knowledge_status_enum(self):
        assert KnowledgeStatus.DRAFT.value == "draft"
        assert KnowledgeStatus.VERIFIED.value == "verified"
        assert KnowledgeStatus.DEPRECATED.value == "deprecated"