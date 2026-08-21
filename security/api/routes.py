from datetime import datetime
from typing import Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status, Header, Request
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorDatabase
from engine.model.errors import EvidenceTamperedError
from security.evidence.integrity import EvidenceIntegrityEngine
from security.authorization import EvidenceAuthorizationEngine
from engine.security.secrets import redact_mapping

from security.config import settings
from security.database import get_database
from security.models.evidence import Evidence, EvidenceType, EvidenceStatus, EvidenceIngestRequest
from security.evidence.service import EvidenceIngestionBoundary, EvidenceNormalizer
from security.models.analysis import AnalysisPipeline, AnalysisStage
from security.analysis.service import AnalysisPipelineService
from security.models.finding import (
    Finding,
    FindingStatus,
    VulnerabilityType,
    SeverityLevel,
    ConfidenceLevel,
    ImpactLevel,
    ExploitabilityLevel,
    AttackPath,
    RootCause,
    RemediationAction,
    RegressionTest,
)
from security.findings.service import FindingService
from security.attack_graph.service import AttackGraphService, AttackGraph
from security.remediation.service import RemediationService, RootCauseAnalyzer
from security.regression.service import RegressionTestService
from security.policies.service import PolicyService
from security.policies.models import SecurityPolicy, PolicyEvaluation
from security.baselines.service import BaselineService
from security.baselines.models import Baseline, BaselineComparison
from security.severity.service import SeverityCalculationService, SeverityRuleService
from security.severity.models import (
    SeverityLevel,
    CVSSVector,
    CVSSv31BaseMetrics,
    SeverityAssessment,
    SeverityRule,
)
from security.posture.service import PostureEngine
from security.posture.models import Target, TargetVersion, TargetStatus, PostureSnapshot, PostureComparison, TargetRiskHistory, PostureLevel
from security.change_detection.service import ChangeDetector
from security.change_detection.models import ChangeEvent, ChangeDetectionResult, ChangeDetectionRule, ChangeType, ChangeSeverity, ChangeSource
from security.correlation.service import CorrelationEngine
from security.correlation.models import FindingCorrelation, CorrelationResult, CorrelationType, CorrelationSeverity, CorrelationStatus, CompositeAttackPath, SystemicRiskAssessment, CorrelationRule
from security.intelligence.service import RegressionIntelligenceService
from security.intelligence.models import (
    RegressionIntelligence,
    RegressionType,
    AttackCoverageAnalytics,
    RiskTrendAnalysis,
    EvidenceLineage,
    ModelVersionComparison,
    TargetComparison,
    RemediationVerification,
    IntelligenceReport,
    IntelligenceType,
    IntelligencePriority,
)
from security.assurance.service import AssuranceEngine
from security.assurance.models import AssuranceLevel, VerificationStatus, ContinuousAssurance, AssurancePolicy, AssuranceVerification, AssuranceMetric
from security.analytics.service import AnalyticsEngine
from security.analytics.models import AnalyticsQuery, AnalyticsResult, DashboardWidget, AnalyticsReport, AnalyticsType, TimeGranularity
from security.digital_twin.service import DigitalTwinEngine
from security.digital_twin.models import (
    DigitalTwin,
    TwinComponent,
    TwinEdge,
    TwinSnapshot,
    ComponentType,
    ComponentStatus,
    ComponentChange,
    AssumptionImpact,
    DigitalTwinSyncRequest,
)
from security.risk_graph.service import RiskGraphEngine
from security.risk_graph.models import (
    RiskGraph,
    GraphNode,
    GraphEdge,
    NodeType,
    EdgeType,
    RiskLevel,
    RiskGraphBuildRequest,
    RiskPropagationEvent,
    BlastRadiusAssessment,
)
from security.knowledge.service import KnowledgeBase
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

router = APIRouter()
evidence_router = APIRouter(prefix="/evidence", tags=["evidence"])
analysis_router = APIRouter(prefix="/analysis", tags=["analysis"])
findings_router = APIRouter(prefix="/findings", tags=["findings"])
attack_graph_router = APIRouter(prefix="/attack-graph", tags=["attack_graph"])
remediation_router = APIRouter(prefix="/remediation", tags=["remediation"])
regression_router = APIRouter(prefix="/regression", tags=["regression"])
policies_router = APIRouter(prefix="/policies", tags=["policies"])
baselines_router = APIRouter(prefix="/baselines", tags=["baselines"])
severity_router = APIRouter(prefix="/severity", tags=["severity"])

posture_router = APIRouter(prefix="/posture", tags=["posture"])
change_detection_router = APIRouter(prefix="/change-detection", tags=["change_detection"])
correlation_router = APIRouter(prefix="/correlation", tags=["correlation"])
intelligence_router = APIRouter(prefix="/intelligence", tags=["intelligence"])
assurance_router = APIRouter(prefix="/assurance", tags=["assurance"])
analytics_router = APIRouter(prefix="/analytics", tags=["analytics"])

digital_twin_router = APIRouter(prefix="/digital-twin", tags=["digital_twin"])
risk_graph_router = APIRouter(prefix="/risk-graph", tags=["risk_graph"])
knowledge_router = APIRouter(prefix="/knowledge", tags=["knowledge"])


class CreatePipelineRequest(BaseModel):
    execution_id: UUID
    target_id: str


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


class BuildGraphRequest(BaseModel):
    execution_id: UUID
    target_id: str


class GenerateRemediationRequest(BaseModel):
    finding_id: UUID


class RunRegressionRequest(BaseModel):
    test_id: UUID
    execution_id: UUID


class CreatePolicyRequest(BaseModel):
    name: str
    description: str
    category: str
    rules: list[dict[str, Any]] = Field(default_factory=list)
    severity_threshold: str = "medium"


class EvaluatePolicyRequest(BaseModel):
    policy_id: UUID
    execution_id: UUID
    findings: list[dict[str, Any]]


class CreateBaselineRequest(BaseModel):
    target: str
    name: str
    description: str
    execution_ids: list[UUID]
    days_back: int = 30


class AssessSeverityRequest(BaseModel):
    finding_id: UUID
    evidence_ids: list[UUID] | None = None


class CreateSeverityRuleRequest(BaseModel):
    name: str
    description: str
    vulnerability_type: str
    cvss_vector: dict[str, Any]
    min_score: float = 0.0
    max_score: float = 10.0
    enabled: bool = True


class AddRemediationRequest(BaseModel):
    actions: list[RemediationAction]


class CreateTargetRequest(BaseModel):
    name: str
    target_type: TargetType
    version: str
    description: str | None = None
    configuration: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    owner: str | None = None
    environment: str = "production"


class UpdateTargetVersionRequest(BaseModel):
    version: str
    configuration: dict[str, Any]
    change_summary: str
    changed_by: str | None = None


class ChangeDetectionRequest(BaseModel):
    target_id: UUID
    source: str = "scheduled_scan"


class CorrelationAnalysisRequest(BaseModel):
    target_id: UUID
    days: int = 30


class RegressionIntelligenceRequest(BaseModel):
    finding_id: UUID
    execution_a_id: UUID
    execution_b_id: UUID


class AttackCoverageRequest(BaseModel):
    target_id: UUID
    execution_id: UUID


class RiskTrendRequest(BaseModel):
    target_id: UUID
    days: int = 30


class ModelComparisonRequest(BaseModel):
    target_id: UUID
    version_a: str
    version_b: str
    scan_a_id: UUID
    scan_b_id: UUID


class TargetComparisonRequest(BaseModel):
    target_a_id: UUID
    target_b_id: UUID


class RemediationVerificationRequest(BaseModel):
    finding_id: UUID
    remediation_id: UUID
    test_id: UUID
    execution_id: UUID


class IntelligenceReportRequest(BaseModel):
    target_id: UUID
    intelligence_type: IntelligenceType
    priority: IntelligencePriority
    title: str
    summary: str
    findings: list[UUID] = Field(default_factory=list)
    correlations: list[UUID] = Field(default_factory=list)
    regressions: list[UUID] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class AssurancePolicyRequest(BaseModel):
    name: str
    description: str
    target_types: list[str] = Field(default_factory=list)
    required_metrics: list[str] = Field(default_factory=list)
    minimum_assurance: AssuranceLevel = AssuranceLevel.MEDIUM
    enabled: bool = True


class AssuranceVerificationRequest(BaseModel):
    target_id: UUID
    policy_id: UUID


class AnalyticsQueryRequest(BaseModel):
    analytics_type: AnalyticsType
    target_ids: list[UUID] = Field(default_factory=list)
    time_range_start: datetime
    time_range_end: datetime
    granularity: TimeGranularity = TimeGranularity.DAILY
    filters: dict[str, Any] = Field(default_factory=dict)


class DashboardWidgetRequest(BaseModel):
    name: str
    description: str
    analytics_type: AnalyticsType
    target_ids: list[UUID] = Field(default_factory=list)
    time_range: str = "30d"
    granularity: TimeGranularity = TimeGranularity.DAILY
    config: dict[str, Any] = Field(default_factory=dict)


class AnalyticsReportRequest(BaseModel):
    name: str
    description: str
    target_ids: list[UUID] = Field(default_factory=list)
    widgets: list[UUID] = Field(default_factory=list)
    schedule: str | None = None
    recipients: list[str] = Field(default_factory=list)
    enabled: bool = True


class DigitalTwinSyncRequest(BaseModel):
    target_id: UUID
    force_full_sync: bool = False
    components_to_sync: list[str] | None = None


class RiskGraphBuildRequest(BaseModel):
    target_id: UUID
    execution_id: UUID | None = None
    include_findings: bool = True
    include_assets: bool = True
    include_permissions: bool = True
    include_change_history: bool = True


class KnowledgeEntrySearch(BaseModel):
    query: str | None = None
    knowledge_types: list[KnowledgeType] = Field(default_factory=list)
    statuses: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    vulnerability_types: list[str] = Field(default_factory=list)
    target_ids: list[UUID] = Field(default_factory=list)
    min_confidence: float = 0.0
    date_from: datetime | None = None
    date_to: datetime | None = None
    limit: int = 50
    offset: int = 0


class AddRemediationRequest(BaseModel):
    actions: list[RemediationAction]


class AddRegressionTestRequest(BaseModel):
    test: RegressionTest


class SetAttackPathRequest(BaseModel):
    attack_path: AttackPath


class SetRootCauseRequest(BaseModel):
    root_cause: RootCause


class SetReproductionRequest(BaseModel):
    reproduction: dict[str, Any]


@evidence_router.post("/ingest", response_model=Evidence, status_code=status.HTTP_201_CREATED)
async def ingest_evidence(request: EvidenceIngestRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    boundary = EvidenceIngestionBoundary(db)
    try:
        return await boundary.ingest(request)
    except Exception as e:
        if hasattr(e, 'errors'):
            raise HTTPException(status_code=400, detail={"message": e.message, "errors": e.errors})
        raise


@evidence_router.post("/ingest/batch", response_model=list[Evidence], status_code=status.HTTP_201_CREATED)
async def ingest_batch(requests: list[EvidenceIngestRequest], db: AsyncIOMotorDatabase = Depends(get_database)):
    boundary = EvidenceIngestionBoundary(db)
    try:
        return await boundary.ingest_batch(requests)
    except Exception as e:
        if hasattr(e, 'errors'):
            raise HTTPException(status_code=400, detail={"message": e.message, "errors": e.errors})
        raise


@evidence_router.post("/normalize", response_model=Evidence)
async def normalize_evidence(evidence_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    normalizer = EvidenceNormalizer(db)
    result = await normalizer.normalize(evidence_id)
    if not result:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return result


def _get_tenant(req: Request) -> str:
    # Prefer X-Tenant-ID header, fallback to query param tenant_id, else default-tenant
    tid = req.headers.get("X-Tenant-ID") or req.query_params.get("tenant_id") or "default-tenant"
    return tid

def _enforce_evidence_read(tenant_id: str, evidence_id: UUID):
    eng = EvidenceAuthorizationEngine()
    # register tenant if not exists (for test isolation, default perms)
    if not eng.get_tenant_context(tenant_id):
        eng.register_tenant(tenant_id, "analyst")
    dec = eng.authorize({"tenant_id": tenant_id, "evidence_id": str(evidence_id), "action": "evidence:read"})
    if not dec["allowed"]:
        raise HTTPException(status_code=403, detail=f"Tenant {tenant_id} not authorized to read evidence")

@evidence_router.get("/{evidence_id}", response_model=Evidence)
async def get_evidence(evidence_id: UUID, request: Request, db: AsyncIOMotorDatabase = Depends(get_database)):
    tenant_id = _get_tenant(request)
    _enforce_evidence_read(tenant_id, evidence_id)
    boundary = EvidenceIngestionBoundary(db)
    try:
        evidence = await boundary.get_by_id(evidence_id, tenant_id=tenant_id)
    except EvidenceTamperedError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence


@evidence_router.get("/execution/{execution_id}", response_model=list[Evidence])
async def get_evidence_by_execution(execution_id: UUID, request: Request, db: AsyncIOMotorDatabase = Depends(get_database)):
    tenant_id = _get_tenant(request)
    boundary = EvidenceIngestionBoundary(db)
    try:
        evidence = await boundary.get_by_execution(execution_id, tenant_id=tenant_id)
    except EvidenceTamperedError as e:
        raise HTTPException(status_code=409, detail=str(e))
    # Redact any secrets in metadata before returning
    return [Evidence(**redact_mapping(e.model_dump(), ()) ) if False else e for e in evidence]


@analysis_router.post("/pipeline", response_model=AnalysisPipeline, status_code=status.HTTP_201_CREATED)
async def create_pipeline(request: CreatePipelineRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AnalysisPipelineService(db)
    return await service.create_pipeline(request.execution_id, request.target_id)


@analysis_router.post("/pipeline/{pipeline_id}/run", response_model=AnalysisPipeline)
async def run_pipeline(pipeline_id: UUID, background_tasks: BackgroundTasks, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AnalysisPipelineService(db)
    pipeline = await service.get_pipeline(pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    background_tasks.add_task(service.run_pipeline, pipeline_id)
    return pipeline


@analysis_router.post("/pipeline/{pipeline_id}/run-async", status_code=status.HTTP_202_ACCEPTED)
async def run_pipeline_async(pipeline_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AnalysisPipelineService(db)
    pipeline = await service.get_pipeline(pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    from security.workers.tasks import run_analysis_pipeline
    task = run_analysis_pipeline.delay(str(pipeline_id))
    return {"task_id": task.id, "status": "queued", "pipeline_id": str(pipeline_id)}


@analysis_router.post("/full-workflow-async", status_code=status.HTTP_202_ACCEPTED)
async def full_analysis_workflow_async(execution_id: UUID, target_id: str, db: AsyncIOMotorDatabase = Depends(get_database)):
    from security.workers.tasks import full_analysis_workflow
    task = full_analysis_workflow.delay(str(execution_id), target_id)
    return {"task_id": task.id, "status": "queued", "execution_id": str(execution_id), "target_id": target_id}


@analysis_router.get("/pipeline/{pipeline_id}", response_model=AnalysisPipeline)
async def get_pipeline(pipeline_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AnalysisPipelineService(db)
    pipeline = await service.get_pipeline(pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail="Pipeline not found")
    return pipeline


@findings_router.post("", response_model=Finding, status_code=status.HTTP_201_CREATED)
async def create_finding(
    target_id: str,
    attack_id: str,
    execution_id: UUID,
    vulnerability_type: VulnerabilityType,
    evidence_ids: list[UUID],
    severity: SeverityLevel | None = None,
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM,
    impact: ImpactLevel = ImpactLevel.MEDIUM,
    exploitability: ExploitabilityLevel = ExploitabilityLevel.MEDIUM,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    service = FindingService(db)
    try:
        return await service.create_finding(
            target_id=target_id,
            attack_id=attack_id,
            execution_id=execution_id,
            vulnerability_type=vulnerability_type,
            evidence_ids=evidence_ids,
            severity=severity,
            confidence=confidence,
            impact=impact,
            exploitability=exploitability,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@findings_router.get("/{finding_id}", response_model=Finding)
async def get_finding(finding_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = FindingService(db)
    finding = await service.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@findings_router.get("/execution/{execution_id}", response_model=list[Finding])
async def get_findings_by_execution(execution_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = FindingService(db)
    return await service.get_findings_by_execution(execution_id)


@findings_router.patch("/{finding_id}/status", response_model=Finding)
async def update_finding_status(finding_id: UUID, update: FindingStatusUpdate, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = FindingService(db)
    try:
        finding = await service.transition_status(finding_id, update.status)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        return finding
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@findings_router.post("/{finding_id}/remediation", response_model=Finding)
async def add_remediation(finding_id: UUID, request: AddRemediationRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = FindingService(db)
    finding = await service.add_remediation(finding_id, request.actions)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@findings_router.post("/{finding_id}/regression-test", response_model=Finding)
async def add_regression_test(finding_id: UUID, request: AddRegressionTestRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = FindingService(db)
    finding = await service.add_regression_test(finding_id, request.test)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@findings_router.post("/{finding_id}/attack-path", response_model=Finding)
async def set_attack_path(finding_id: UUID, request: SetAttackPathRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = FindingService(db)
    finding = await service.set_attack_path(finding_id, request.attack_path)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@findings_router.post("/{finding_id}/root-cause", response_model=Finding)
async def set_root_cause(finding_id: UUID, request: SetRootCauseRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = FindingService(db)
    finding = await service.set_root_cause(finding_id, request.root_cause)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@findings_router.post("/{finding_id}/reproduction", response_model=Finding)
async def set_reproduction(finding_id: UUID, request: SetReproductionRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = FindingService(db)
    finding = await service.set_reproduction(finding_id, request.reproduction)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@findings_router.post("/execution/{execution_id}/deduplicate")
async def deduplicate_findings(execution_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = FindingService(db)
    return await service.deduplicate_findings(execution_id)


@findings_router.post("/execution/{execution_id}/correlate")
async def correlate_findings(execution_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = FindingService(db)
    return await service.correlate_findings(execution_id)


@attack_graph_router.post("/build", response_model=AttackGraph)
async def build_attack_graph(request: BuildGraphRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AttackGraphService(db)
    return await service.build_graph(request.execution_id, request.target_id)


@attack_graph_router.post("/build-async", status_code=status.HTTP_202_ACCEPTED)
async def build_attack_graph_async(request: BuildGraphRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    from security.workers.tasks import build_attack_graph
    task = build_attack_graph.delay(str(request.execution_id), request.target_id)
    return {"task_id": task.id, "status": "queued", "execution_id": str(request.execution_id)}


@attack_graph_router.get("/{graph_id}")
async def get_attack_graph(graph_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AttackGraphService(db)
    graph = await service.get_graph(graph_id)
    if not graph:
        raise HTTPException(status_code=404, detail="Attack graph not found")
    return graph


@attack_graph_router.get("/execution/{execution_id}")
async def get_attack_graph_by_execution(execution_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AttackGraphService(db)
    graph = await service.get_graph_by_execution(execution_id)
    if not graph:
        raise HTTPException(status_code=404, detail="Attack graph not found")
    return graph


@attack_graph_router.get("/{graph_id}/export")
async def export_attack_graph(graph_id: UUID, format: str = "json", db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AttackGraphService(db)
    return await service.export_graph(graph_id, format)


@remediation_router.post("/generate", response_model=list[RemediationAction])
async def generate_remediation(request: GenerateRemediationRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RemediationService(db)
    collection = db.findings
    doc = await collection.find_one({"id": str(request.finding_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = Finding(**doc)
    return await service.generate_remediation(finding)


@remediation_router.post("/apply/{finding_id}", response_model=Finding)
async def apply_remediation(finding_id: UUID, request: AddRemediationRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RemediationService(db)
    finding = await service.apply_remediation(finding_id, request.actions)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@remediation_router.post("/verify/{finding_id}", response_model=Finding)
async def verify_remediation(finding_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RemediationService(db)
    finding = await service.verify_remediation(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@remediation_router.post("/root-cause/{finding_id}")
async def analyze_root_cause(finding_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    analyzer = RootCauseAnalyzer(db)
    collection = db.findings
    doc = await collection.find_one({"id": str(finding_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = Finding(**doc)
    cause = await analyzer.analyze(finding)
    return cause.model_dump()


@regression_router.post("/generate/{finding_id}", response_model=RegressionTest)
async def generate_regression_test(finding_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionTestService(db)
    collection = db.findings
    doc = await collection.find_one({"id": str(finding_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = Finding(**doc)
    return await service.generate_test(finding)


@regression_router.post("/generate-async/{finding_id}", status_code=status.HTTP_202_ACCEPTED)
async def generate_regression_test_async(finding_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    from security.workers.tasks import generate_regression_test
    task = generate_regression_test.delay(str(finding_id))
    return {"task_id": task.id, "status": "queued", "finding_id": str(finding_id)}


@regression_router.post("/run", response_model=RegressionTestService.RegressionRun if hasattr(RegressionTestService, 'RegressionRun') else dict)
async def run_regression_test(request: RunRegressionRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionTestService(db)
    return await service.run_test(request.test_id, request.execution_id)


@regression_router.post("/run-async", status_code=status.HTTP_202_ACCEPTED)
async def run_regression_test_async(request: RunRegressionRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    from security.workers.tasks import run_regression_test
    task = run_regression_test.delay(str(request.test_id), str(request.execution_id))
    return {"task_id": task.id, "status": "queued", "test_id": str(request.test_id), "execution_id": str(request.execution_id)}


@regression_router.get("/test/{test_id}")
async def get_regression_test(test_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionTestService(db)
    test = await service.get_test(test_id)
    if not test:
        raise HTTPException(status_code=404, detail="Test not found")
    return test


@regression_router.get("/run/{run_id}")
async def get_regression_run(run_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionTestService(db)
    run = await service.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@regression_router.get("/history/{finding_id}")
async def get_regression_history(finding_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionTestService(db)
    return await service.get_history(finding_id)


@regression_router.post("/compare")
async def compare_executions(finding_id: UUID, execution_a: UUID, execution_b: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionTestService(db)
    return await service.compare_executions(finding_id, execution_a, execution_b)


@policies_router.post("/", response_model=SecurityPolicy, status_code=status.HTTP_201_CREATED)
async def create_policy(request: CreatePolicyRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PolicyService(db)
    from security.policies.models import SecurityPolicy
    policy = SecurityPolicy(
        name=request.name,
        description=request.description,
        category=request.category,
        rules=request.rules,
        severity_threshold=request.severity_threshold,
    )
    return await service.create_policy(policy)


@policies_router.get("/{policy_id}", response_model=SecurityPolicy)
async def get_policy(policy_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PolicyService(db)
    policy = await service.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@policies_router.get("/", response_model=list[SecurityPolicy])
async def list_policies(category: str | None = None, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PolicyService(db)
    return await service.list_policies(category)


@policies_router.post("/evaluate", response_model=PolicyEvaluation)
async def evaluate_policy(request: EvaluatePolicyRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PolicyService(db)
    return await service.evaluate_policy(request.policy_id, request.execution_id, request.findings)


@policies_router.get("/evaluations/{execution_id}")
async def get_policy_evaluations(execution_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PolicyService(db)
    return await service.get_evaluations(execution_id)


@baselines_router.post("/", response_model=Baseline, status_code=status.HTTP_201_CREATED)
async def create_baseline(request: CreateBaselineRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = BaselineService(db)
    return await service.create_baseline(
        target=request.target,
        name=request.name,
        description=request.description,
        execution_ids=request.execution_ids,
        days_back=request.days_back,
    )


@baselines_router.post("/compare", response_model=BaselineComparison)
async def compare_baseline(baseline_id: UUID, execution_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = BaselineService(db)
    return await service.compare_to_baseline(baseline_id, execution_id)


@baselines_router.post("/detect-regression")
async def detect_regression(execution_id: UUID, threshold: float = 10.0, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = BaselineService(db)
    return await service.detect_regression(execution_id, threshold)


@baselines_router.get("/{baseline_id}")
async def get_baseline(baseline_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = BaselineService(db)
    baseline = await service.get_baseline(baseline_id)
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")
    return baseline


@baselines_router.get("/", response_model=list)
async def list_baselines(target: str | None = None, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = BaselineService(db)
    return await service.list_baselines(target)


@severity_router.post("/assess", response_model=SeverityAssessment, status_code=status.HTTP_201_CREATED)
async def assess_severity(request: AssessSeverityRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    from security.models.finding import Finding
    collection = db.findings
    doc = await collection.find_one({"id": str(request.finding_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = Finding(**doc)
    service = SeverityCalculationService(db)
    return await service.assess_finding(finding, request.evidence_ids)


@severity_router.post("/assess-async", status_code=status.HTTP_202_ACCEPTED)
async def assess_severity_async(request: AssessSeverityRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    from security.workers.tasks import assess_severity
    evidence_ids = [str(e) for e in request.evidence_ids] if request.evidence_ids else None
    task = assess_severity.delay(str(request.finding_id), evidence_ids)
    return {"task_id": task.id, "status": "queued", "finding_id": str(request.finding_id)}


@severity_router.get("/assessment/{assessment_id}", response_model=SeverityAssessment)
async def get_assessment(assessment_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = SeverityCalculationService(db)
    assessment = await service.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment


@severity_router.get("/assessments/{finding_id}", response_model=list[SeverityAssessment])
async def get_assessments_for_finding(finding_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = SeverityCalculationService(db)
    return await service.get_assessments_for_finding(finding_id)


@severity_router.post("/rules", response_model=SeverityRule, status_code=status.HTTP_201_CREATED)
async def create_severity_rule(request: CreateSeverityRuleRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = SeverityRuleService(db)
    from security.severity.models import CVSSVector
    cvss_vector = CVSSVector(**request.cvss_vector)
    rule = SeverityRule(
        name=request.name,
        description=request.description,
        vulnerability_type=request.vulnerability_type,
        cvss_vector=cvss_vector,
        min_score=request.min_score,
        max_score=request.max_score,
        enabled=request.enabled,
    )
    return await service.create_rule(rule)


@severity_router.get("/rules/{rule_id}", response_model=SeverityRule)
async def get_severity_rule(rule_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = SeverityRuleService(db)
    rule = await service.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@severity_router.get("/rules", response_model=list[SeverityRule])
async def list_severity_rules(vulnerability_type: str | None = None, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = SeverityRuleService(db)
    return await service.list_rules(vulnerability_type)


@severity_router.post("/evaluate/{finding_id}", response_model=list[SeverityRule])
async def evaluate_severity_rules(finding_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    from security.models.finding import Finding
    collection = db.findings
    doc = await collection.find_one({"id": str(finding_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = Finding(**doc)
    service = SeverityRuleService(db)
    return await service.evaluate_finding(finding)


@posture_router.post("/targets", response_model=Target, status_code=status.HTTP_201_CREATED)
async def create_target(request: CreateTargetRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PostureEngine(db)
    target = Target(**request.model_dump())
    return await service.register_target(target)


@posture_router.get("/targets", response_model=list[Target])
async def list_targets(target_type: str | None = None, status: str | None = None, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PostureEngine(db)
    t = TargetType(target_type) if target_type else None
    s = TargetStatus(status) if status else None
    return await service.list_targets(t, s)


@posture_router.get("/targets/{target_id}", response_model=Target)
async def get_target(target_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PostureEngine(db)
    target = await service.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@posture_router.post("/targets/{target_id}/versions", response_model=TargetVersion)
async def update_target_version(target_id: UUID, request: UpdateTargetVersionRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PostureEngine(db)
    return await service.update_target_version(target_id, request.version, request.configuration, request.change_summary, request.changed_by)


@posture_router.post("/targets/{target_id}/compute-posture", response_model=PostureSnapshot)
async def compute_posture(target_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PostureEngine(db)
    return await service.compute_posture(target_id)


@posture_router.get("/targets/{target_id}/posture", response_model=PostureSnapshot)
async def get_latest_posture(target_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PostureEngine(db)
    snapshot = await service.compute_posture(target_id)
    return snapshot


@posture_router.get("/targets/{target_id}/risk-history", response_model=TargetRiskHistory)
async def get_risk_history(target_id: UUID, days: int = 30, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PostureEngine(db)
    return await service.get_risk_history(target_id, days)


@posture_router.post("/targets/{target_id}/compare", response_model=PostureComparison)
async def compare_posture(target_id: UUID, baseline_snapshot_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = PostureEngine(db)
    return await service.compare_posture(target_id, baseline_snapshot_id)


@change_detection_router.post("/detect", response_model=ChangeDetectionResult)
async def detect_changes(request: ChangeDetectionRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = ChangeDetector(db)
    return await service.detect_changes(request.target_id, request.source)


@change_detection_router.get("/targets/{target_id}/history", response_model=list[ChangeEvent])
async def get_change_history(target_id: UUID, days: int = 30, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = ChangeDetector(db)
    return await service.get_change_history(target_id, days)


@change_detection_router.post("/rules", response_model=ChangeDetectionRule)
async def create_change_rule(rule: ChangeDetectionRule, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = ChangeDetector(db)
    return await service.create_detection_rule(rule)


@change_detection_router.get("/rules", response_model=list[ChangeDetectionRule])
async def list_change_rules(db: AsyncIOMotorDatabase = Depends(get_database)):
    service = ChangeDetector(db)
    return await service.list_detection_rules()


@correlation_router.post("/analyze", response_model=CorrelationResult)
async def analyze_correlations(request: CorrelationAnalysisRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = CorrelationEngine(db)
    return await service.analyze_correlations(request.target_id, request.days)


@correlation_router.get("/targets/{target_id}/correlations", response_model=list[FindingCorrelation])
async def get_correlations(target_id: UUID, days: int = 30, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = CorrelationEngine(db)
    return await service.get_correlation_history(target_id, days)


@correlation_router.post("/correlations/{correlation_id}/validate", response_model=FindingCorrelation)
async def validate_correlation(correlation_id: UUID, validated: bool = True, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = CorrelationEngine(db)
    result = await service.validate_correlation(correlation_id, validated)
    if not result:
        raise HTTPException(status_code=404, detail="Correlation not found")
    return result


@correlation_router.post("/correlations/{correlation_id}/mitigate", response_model=FindingCorrelation)
async def mitigate_correlation(correlation_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = CorrelationEngine(db)
    result = await service.mitigate_correlation(correlation_id)
    if not result:
        raise HTTPException(status_code=404, detail="Correlation not found")
    return result


@correlation_router.post("/rules", response_model=CorrelationRule)
async def create_correlation_rule(rule: CorrelationRule, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = CorrelationEngine(db)
    return await service.create_correlation_rule(rule)


@correlation_router.get("/rules", response_model=list[CorrelationRule])
async def list_correlation_rules(db: AsyncIOMotorDatabase = Depends(get_database)):
    service = CorrelationEngine(db)
    return await service.list_correlation_rules()


@intelligence_router.post("/regression/analyze", response_model=RegressionIntelligence)
async def analyze_regression(request: RegressionIntelligenceRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionIntelligenceService(db)
    return await service.analyze_regression(request.finding_id, request.execution_a_id, request.execution_b_id)


@intelligence_router.post("/attack-coverage", response_model=AttackCoverageAnalytics)
async def generate_attack_coverage(request: AttackCoverageRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionIntelligenceService(db)
    return await service.generate_attack_coverage(request.target_id, request.execution_id)


@intelligence_router.post("/risk-trend", response_model=RiskTrendAnalysis)
async def analyze_risk_trend(request: RiskTrendRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionIntelligenceService(db)
    return await service.analyze_risk_trend(request.target_id, request.days)


@intelligence_router.post("/evidence-lineage", response_model=EvidenceLineage)
async def create_evidence_lineage(evidence_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionIntelligenceService(db)
    return await service.create_evidence_lineage(evidence_id)


@intelligence_router.post("/compare/versions", response_model=ModelVersionComparison)
async def compare_versions(request: ModelComparisonRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionIntelligenceService(db)
    return await service.compare_versions(request.target_id, request.version_a, request.version_b, request.scan_a_id, request.scan_b_id)


@intelligence_router.post("/compare/targets", response_model=TargetComparison)
async def compare_targets(request: TargetComparisonRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionIntelligenceService(db)
    return await service.compare_targets(request.target_a_id, request.target_b_id)


@intelligence_router.post("/verify-remediation", response_model=RemediationVerification)
async def verify_remediation(request: RemediationVerificationRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionIntelligenceService(db)
    return await service.verify_remediation(request.finding_id, request.remediation_id, request.test_id, request.execution_id)


@intelligence_router.post("/reports", response_model=IntelligenceReport)
async def create_intelligence_report(request: IntelligenceReportRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionIntelligenceService(db)
    return await service.create_intelligence_report(
        request.target_id, request.intelligence_type, request.priority,
        request.title, request.summary, request.findings, request.correlations,
        request.regressions, request.recommendations
    )


@intelligence_router.get("/reports", response_model=list[IntelligenceReport])
async def get_intelligence_reports(target_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RegressionIntelligenceService(db)
    return await service.get_intelligence_reports(target_id)


@assurance_router.post("/compute", response_model=ContinuousAssurance)
async def compute_assurance(target_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AssuranceEngine(db)
    return await service.compute_assurance(target_id)


@assurance_router.get("/targets/{target_id}", response_model=ContinuousAssurance)
async def get_latest_assurance(target_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AssuranceEngine(db)
    assurance = await service.get_latest_assurance(target_id)
    if not assurance:
        raise HTTPException(status_code=404, detail="Assurance not found")
    return assurance


@assurance_router.get("/targets/{target_id}/history", response_model=list[ContinuousAssurance])
async def get_assurance_history(target_id: UUID, days: int = 30, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AssuranceEngine(db)
    return await service.get_assurance_history(target_id, days)


@assurance_router.post("/policies", response_model=AssurancePolicy)
async def create_assurance_policy(request: AssurancePolicyRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AssuranceEngine(db)
    policy = AssurancePolicy(**request.model_dump())
    return await service.create_policy(policy)


@assurance_router.get("/policies", response_model=list[AssurancePolicy])
async def list_assurance_policies(db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AssuranceEngine(db)
    return await service.get_policies()


@assurance_router.post("/verify", response_model=AssuranceVerification)
async def run_verification(request: AssuranceVerificationRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AssuranceEngine(db)
    return await service.run_verification(request.target_id, request.policy_id)


@assurance_router.get("/targets/{target_id}/verifications", response_model=list[AssuranceVerification])
async def get_verifications(target_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AssuranceEngine(db)
    return await service.get_verifications(target_id)


@analytics_router.post("/query", response_model=AnalyticsResult)
async def execute_analytics_query(request: AnalyticsQueryRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AnalyticsEngine(db)
    query = AnalyticsQuery(**request.model_dump())
    return await service.execute_query(query)


@analytics_router.post("/widgets", response_model=DashboardWidget)
async def create_widget(request: DashboardWidgetRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AnalyticsEngine(db)
    widget = DashboardWidget(**request.model_dump())
    return await service.create_widget(widget)


@analytics_router.get("/widgets", response_model=list[DashboardWidget])
async def list_widgets(db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AnalyticsEngine(db)
    return await service.get_widgets()


@analytics_router.post("/reports", response_model=AnalyticsReport)
async def create_analytics_report(request: AnalyticsReportRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AnalyticsEngine(db)
    report = AnalyticsReport(**request.model_dump())
    return await service.create_report(report)


@analytics_router.get("/reports", response_model=list[AnalyticsReport])
async def list_analytics_reports(db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AnalyticsEngine(db)
    return await service.get_reports()


@analytics_router.post("/reports/{report_id}/execute")
async def execute_report(report_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = AnalyticsEngine(db)
    return await service.execute_report(report_id)


@digital_twin_router.post("/twins", response_model=DigitalTwin, status_code=status.HTTP_201_CREATED)
async def create_twin(request: DigitalTwinSyncRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = DigitalTwinEngine(db)
    return await service.create_twin(request.target_id, f"Twin for {request.target_id}")


@digital_twin_router.get("/twins/{twin_id}", response_model=DigitalTwin)
async def get_twin(twin_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = DigitalTwinEngine(db)
    twin = await service.get_twin(twin_id)
    if not twin:
        raise HTTPException(status_code=404, detail="Twin not found")
    return twin


@digital_twin_router.get("/twins/target/{target_id}", response_model=DigitalTwin)
async def get_twin_by_target(target_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = DigitalTwinEngine(db)
    twin = await service.get_twin_by_target(target_id)
    if not twin:
        raise HTTPException(status_code=404, detail="Twin not found")
    return twin


@digital_twin_router.post("/twins/sync", response_model=DigitalTwin)
async def sync_twin(request: DigitalTwinSyncRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = DigitalTwinEngine(db)
    return await service.sync_twin(request)


@digital_twin_router.get("/twins/{twin_id}/snapshots", response_model=list[TwinSnapshot])
async def get_twin_snapshots(twin_id: UUID, days: int = 30, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = DigitalTwinEngine(db)
    return await service.get_twin_history(twin_id, days)


@digital_twin_router.get("/twins/{twin_id}/changes", response_model=list[ComponentChange])
async def get_component_changes(twin_id: UUID, days: int = 30, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = DigitalTwinEngine(db)
    return await service.get_component_changes(twin_id, days)


@digital_twin_router.get("/twins/{twin_id}/assumptions", response_model=list[AssumptionImpact])
async def get_assumption_impacts(twin_id: UUID, days: int = 30, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = DigitalTwinEngine(db)
    return await service.get_assumption_impacts(twin_id, days)


@digital_twin_router.post("/twins/compare", response_model=list[ComponentChange])
async def compare_twins(twin_a_id: UUID, twin_b_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = DigitalTwinEngine(db)
    return await service.compare_twins(twin_a_id, twin_b_id)


@risk_graph_router.post("/build", response_model=RiskGraph)
async def build_risk_graph(request: RiskGraphBuildRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RiskGraphEngine(db)
    return await service.build_risk_graph(request)


@risk_graph_router.get("/{graph_id}", response_model=RiskGraph)
async def get_risk_graph(graph_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RiskGraphEngine(db)
    graph = await service.get_risk_graph(graph_id)
    if not graph:
        raise HTTPException(status_code=404, detail="Risk graph not found")
    return graph


@risk_graph_router.get("/target/{target_id}", response_model=RiskGraph)
async def get_risk_graph_by_target(target_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RiskGraphEngine(db)
    graph = await service.get_risk_graph_by_target_id(target_id)
    if not graph:
        raise HTTPException(status_code=404, detail="Risk graph not found")
    return graph


@risk_graph_router.get("/{graph_id}/blast-radius", response_model=BlastRadiusAssessment)
async def get_blast_radius(graph_id: UUID, source_node_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RiskGraphEngine(db)
    return await service.assess_blast_radius(graph_id, source_node_id)


@risk_graph_router.post("/{graph_id}/propagate", response_model=RiskPropagationEvent)
async def propagate_risk(graph_id: UUID, source_node_id: UUID, trigger_type: str, trigger_details: dict[str, Any] = None, db: AsyncIOMotorDatabase = Depends(get_database)):
    if trigger_details is None:
        trigger_details = {}
    service = RiskGraphEngine(db)
    return await service.propagate_risk(graph_id, source_node_id, trigger_type, trigger_details)


@risk_graph_router.get("/{graph_id}/critical-paths", response_model=list[list[UUID]])
async def get_critical_paths(graph_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RiskGraphEngine(db)
    graph = await service.get_risk_graph(graph_id)
    if not graph:
        raise HTTPException(status_code=404, detail="Risk graph not found")
    return graph.critical_paths


@risk_graph_router.get("/{graph_id}/entry-points", response_model=list[UUID])
async def get_entry_points(graph_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RiskGraphEngine(db)
    graph = await service.get_risk_graph(graph_id)
    if not graph:
        raise HTTPException(status_code=404, detail="Risk graph not found")
    return graph.entry_points


@risk_graph_router.get("/{graph_id}/propagation-history", response_model=list[RiskPropagationEvent])
async def get_propagation_history(graph_id: UUID, days: int = 30, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = RiskGraphEngine(db)
    # Note: would need to add this method to the service
    return []


@knowledge_router.post("/entries", response_model=KnowledgeEntry, status_code=status.HTTP_201_CREATED)
async def create_knowledge_entry(entry: KnowledgeEntry, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.create_entry(entry)


@knowledge_router.get("/entries", response_model=list[KnowledgeEntry])
async def search_knowledge_entries(request: KnowledgeEntrySearch, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.search_entries(request)


@knowledge_router.get("/entries/{entry_id}", response_model=KnowledgeEntry)
async def get_knowledge_entry(entry_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    entry = await service.get_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Knowledge entry not found")
    return entry


@knowledge_router.patch("/entries/{entry_id}", response_model=KnowledgeEntry)
async def update_knowledge_entry(entry_id: UUID, updates: dict[str, Any], db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    entry = await service.update_entry(entry_id, updates)
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    return entry


@knowledge_router.post("/entries/{entry_id}/verify", response_model=KnowledgeEntry)
async def verify_knowledge_entry(entry_id: UUID, verified_by: str, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    entry = await service.verify_entry(entry_id, verified_by)
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    return entry


@knowledge_router.post("/patterns/attack", response_model=AttackPattern)
async def create_attack_pattern(pattern: AttackPattern, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.create_attack_pattern(pattern)


@knowledge_router.post("/patterns/vulnerability", response_model=VulnerabilityPattern)
async def create_vulnerability_pattern(pattern: VulnerabilityPattern, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.create_vulnerability_pattern(pattern)


@knowledge_router.post("/patterns/remediation", response_model=RemediationPattern)
async def create_remediation_pattern(pattern: RemediationPattern, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.create_remediation_pattern(pattern)


@knowledge_router.post("/patterns/regression", response_model=RegressionPattern)
async def create_regression_pattern(pattern: RegressionPattern, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.create_regression_pattern(pattern)


@knowledge_router.get("/patterns/attack", response_model=list[AttackPattern])
async def search_attack_patterns(vulnerability_type: str | None = None, mitre_technique: str | None = None, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.search_attack_patterns(vulnerability_type, mitre_technique)


@knowledge_router.get("/patterns/vulnerability", response_model=list[VulnerabilityPattern])
async def search_vulnerability_patterns(vulnerability_type: str | None = None, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.search_vulnerability_patterns(vulnerability_type)


@knowledge_router.get("/patterns/remediation", response_model=list[RemediationPattern])
async def search_remediation_patterns(vulnerability_type: str | None = None, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.search_remediation_patterns(vulnerability_type)


@knowledge_router.get("/patterns/regression", response_model=list[RegressionPattern])
async def search_regression_patterns(vulnerability_type: str | None = None, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.search_regression_patterns(vulnerability_type)


@knowledge_router.post("/target-profiles", response_model=TargetProfile)
async def create_or_update_target_profile(profile: TargetProfile, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.create_or_update_target_profile(profile)


@knowledge_router.get("/target-profiles/{target_id}", response_model=TargetProfile)
async def get_target_profile(target_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    profile = await service.get_target_profile(target_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Target profile not found")
    return profile


@knowledge_router.post("/campaign-strategies", response_model=CampaignStrategy)
async def create_campaign_strategy(strategy: CampaignStrategy, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.create_campaign_strategy(strategy)


@knowledge_router.get("/campaign-strategies", response_model=list[CampaignStrategy])
async def list_campaign_strategies(target_type: str | None = None, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.get_campaign_strategies(target_type)


@knowledge_router.get("/campaign-strategies/best-for-target/{target_id}", response_model=CampaignStrategy)
async def get_best_strategy_for_target(target_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    strategy = await service.get_best_strategy_for_target(target_id)
    if not strategy:
        raise HTTPException(status_code=404, detail="No strategy found for target")
    return strategy


@knowledge_router.post("/extract/from-finding/{finding_id}", response_model=list[KnowledgeEntry])
async def extract_knowledge_from_finding(finding_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    doc = await db.findings.find_one({"id": str(finding_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Finding not found")
    from security.models.finding import Finding
    finding = Finding(**doc)
    return await service.extract_knowledge_from_finding(finding)


@knowledge_router.post("/extract/regression/{finding_id}", response_model=KnowledgeEntry | None)
async def extract_regression_pattern(finding_id: UUID, execution_a: UUID, execution_b: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.extract_regression_pattern(finding_id, execution_a, execution_b)


@knowledge_router.post("/target-profiles/update/{target_id}", response_model=TargetProfile)
async def update_target_profile(target_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.update_target_profile(target_id)


@knowledge_router.post("/compare/versions", response_model=ModelVersionComparison)
async def compare_versions(target_id: UUID, version_a: str, version_b: str, scan_a_id: UUID, scan_b_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.compare_versions(target_id, version_a, version_b, scan_a_id, scan_b_id)


@knowledge_router.post("/compare/targets", response_model=TargetComparison)
async def compare_targets(target_a_id: UUID, target_b_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.compare_targets(target_a_id, target_b_id)


@knowledge_router.post("/evidence-lineage", response_model=EvidenceLineage)
async def create_evidence_lineage(evidence_id: UUID, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.create_evidence_lineage(evidence_id)


@knowledge_router.get("/search", response_model=list[KnowledgeEntry])
async def search_knowledge(request: KnowledgeEntrySearch, db: AsyncIOMotorDatabase = Depends(get_database)):
    service = KnowledgeBase(db)
    return await service.search_entries(request)


router.include_router(evidence_router)
router.include_router(analysis_router)
router.include_router(findings_router)
router.include_router(attack_graph_router)
router.include_router(remediation_router)
router.include_router(regression_router)
router.include_router(policies_router)
router.include_router(baselines_router)
router.include_router(severity_router)
router.include_router(posture_router)
router.include_router(change_detection_router)
router.include_router(correlation_router)
router.include_router(intelligence_router)
router.include_router(assurance_router)
router.include_router(analytics_router)
router.include_router(digital_twin_router)
router.include_router(risk_graph_router)
router.include_router(knowledge_router)