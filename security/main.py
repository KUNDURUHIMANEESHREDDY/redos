from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import structlog

from security.config import settings
from security.database import connect_to_mongo, close_mongo_connection
from security.api.routes import router as api_router
from security.auth.routes import router as auth_router


bearer_scheme = HTTPBearer(
    scheme_name="Bearer Token",
    description="JWT Authorization header using the Bearer scheme. Example: 'Authorization: Bearer <token>'",
    auto_error=False,
)


structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer() if settings.json_logs else structlog.dev.ConsoleRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongo()
    yield
    await close_mongo_connection()


tags_metadata = [
    {
        "name": "auth",
        "description": "Authentication and authorization. Login, register, user management.",
    },
    {
        "name": "evidence",
        "description": "Evidence ingestion, normalization, and retrieval. Raw evidence from network traffic, logs, filesystem, processes, API calls, user actions, and vulnerability scans.",
    },
    {
        "name": "analysis",
        "description": "Deterministic analysis pipeline: Evidence Validation → Behavior Extraction → Security Rules → Impact Analysis → Exploitability Analysis → Risk Calculation → Finding Generation.",
    },
    {
        "name": "findings",
        "description": "Security findings management. Query findings, update status (NEW, CONFIRMED, REMEDIATED, REGRESSION_TESTED, FIXED, FALSE_POSITIVE, WONT_FIX, DUPLICATE).",
    },
    {
        "name": "attack_graph",
        "description": "Attack graph construction and visualization. Nodes (vulnerabilities, attack steps) and edges (chains_to, leads_to, exploits, related_to). Critical path detection using NetworkX.",
    },
    {
        "name": "remediation",
        "description": "Remediation generation and root cause analysis. Template-based remediation for SQL injection, command injection, XSS, path traversal, broken auth.",
    },
    {
        "name": "regression",
        "description": "Regression test generation, execution, and comparison. Finding → Reproduction Case → Regression Test → Re-execute → Compare.",
    },
    {
        "name": "policies",
        "description": "Security policy definitions and evaluation. OWASP Top 10, PCI DSS, Zero Critical Vulnerabilities.",
    },
    {
        "name": "baselines",
        "description": "Historical baselines and regression detection. Baseline creation, metric comparison, risk score delta tracking.",
    },
    {
        "name": "severity",
        "description": "CVSS v3.1 severity calculation. Base, temporal, and environmental scores with vector strings.",
    },
    {
        "name": "tasks",
        "description": "Async task management. Celery task status, revocation.",
    },
]


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
**Evidence, Intelligence & Security Analysis Platform**

Owns the brain of the platform. Agent 1 says "Here is what happened." Agent 2 determines "What does this mean?"

## Core Capabilities

### Evidence Ingestion & Normalization
- **10 evidence types**: network_traffic, log_entry, file_system, memory_dump, process_trace, api_call, user_action, configuration, vulnerability_scan, custom
- **Status pipeline**: RAW → VALIDATED → NORMALIZED → CORRELATED → ARCHIVED
- Every finding references actual evidence (machine-verifiable)

### Deterministic Analysis Pipeline
1. **Evidence Validation** - Verify raw evidence integrity
2. **Behavior Extraction** - Match against known attack patterns
3. **Security Rules** - Apply vulnerability detection rules
4. **Impact Analysis** - Assess confidentiality, integrity, availability impact
5. **Exploitability Analysis** - Evaluate attack vector, complexity, privileges, user interaction
6. **Risk Calculation** - CVSS v3.1 base, temporal, environmental scores
7. **Finding Generation** - Create findings with evidence references

### Attack Graph Construction
- Nodes: vulnerabilities and attack steps with MITRE ATT&CK techniques
- Edges: chains_to, leads_to, exploits, related_to relationships
- Critical path detection using NetworkX shortest path algorithms

### Finding Lifecycle
- Statuses: NEW → CONFIRMED → REMEDIATED → REGRESSION_TESTED → FIXED
- Also: FALSE_POSITIVE, WONT_FIX, DUPLICATE
- Every finding includes: attack_path, root_cause, remediation, reproduction, regression_tests

### Remediation & Root Cause
- Template-based remediation for 6 vulnerability types
- Root cause analysis tied to evidence
- Verification steps for each remediation action

### Regression System
- Finding → Reproduction Case → Regression Test → Re-execute → Compare
- Cross-execution comparison for regression detection
- Independent test execution

### Security Policies & Baselines
- Pre-built policies: OWASP Top 10, PCI DSS, Zero Critical
- Baseline creation with 30-day rolling windows
- Regression detection with configurable thresholds

### CVSS v3.1 Severity Calculation
- Base metrics: AV, AC, PR, UI, S, C, I, A
- Temporal metrics: E, RL, RC
- Environmental metrics: CR, IR, AR, modified base metrics
- Vector string generation

## Authentication
All endpoints (except `/auth/*` and `/health`) require JWT Bearer token.
Use `/api/v1/auth/login` to obtain token.

## Permissions
Role-based access control:
- **Admin**: Full access + user management
- **Analyst**: Read/write all security data
- **Viewer**: Read-only access
- **Service**: Write-only for automated systems

## Async Operations
Long-running operations support async execution via Celery:
- Pipeline execution
- Attack graph building
- Regression test generation/execution
- Severity assessment
- Full analysis workflow

Use `/api/v1/tasks/{task_id}` to check status.
""",
    lifespan=lifespan,
    swagger_ui_parameters={"persistAuthorization": True},
    openapi_tags=tags_metadata,
    contact={
        "name": "Security Analysis Platform",
        "url": "https://github.com/security-analysis-platform",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/v1")
app.include_router(api_router, prefix="/api/v1")


@app.get("/health", tags=["health"])
async def health_check():
    """
    Health check endpoint.
    Returns service status and version.
    """
    return {"status": "healthy", "version": settings.app_version}


@app.get("/", tags=["root"])
async def root():
    """
    Root endpoint with API information.
    """
    return {"message": "Security Analysis Platform API", "docs": "/docs", "redoc": "/redoc"}