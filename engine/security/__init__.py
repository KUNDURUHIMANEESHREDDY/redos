from engine.security.capture import CaptureEnforcer
from engine.security.guard import AUDIT_GUARD_REJECT, ProductionGate, validate_evidence_chain
from engine.security.secrets import SecretsVault, redact_any, redact_mapping, redact_text, sanitize_api_response, sanitize_error_message, sanitize_log_record, sanitize_model_output, sanitize_tool_arguments
from engine.security.ssrf import SSRFPolicy, classify_ip, validate_target_urls, validate_url
from engine.security.storage import FindingRecord, FindingsGateway, FindingSink, InMemoryFindingSink
from engine.security.evidence import (
    AuthorizedEvidenceStore,
    EvidenceIntegrityEngine,
    EvidenceRecord,
    EvidenceTamperDetector,
    SecureEvidenceStore,
)
from engine.security.authorization import (
    EvidencePermission,
    ResourceType,
    Role,
    UserContext,
    ResourceContext,
    AccessRequest,
    AuthorizationEngine,
    get_authorization_engine,
    authenticate_user,
    authorize_resource,
    has_permission,
    get_permissions,
    ROLE_PERMISSIONS,
    ORG_READ,
    ORG_WRITE,
    ORG_DELETE,
    PROJECT_READ,
    PROJECT_WRITE,
    PROJECT_DELETE,
    PROJECT_MEMBERS,
    TARGET_READ,
    TARGET_WRITE,
    TARGET_DELETE,
    CAMPAIGN_READ,
    CAMPAIGN_WRITE,
    CAMPAIGN_DELETE,
    CAMPAIGN_EXECUTE,
    EXECUTION_READ,
    EXECUTION_WRITE,
    EXECUTION_CANCEL,
    FINDING_READ,
    FINDING_WRITE,
    FINDING_RESOLVE,
    EVIDENCE_READ,
    EVIDENCE_DOWNLOAD,
    EVIDENCE_EXPORT,
    EVIDENCE_LINEAGE,
    ATTACK_GRAPH_VIEW,
    REGRESSION_VIEW,
    REPORT_VIEW,
    KNOWLEDGE_VIEW,
    DIGITAL_TWIN_VIEW,
    RISK_GRAPH_VIEW,
    ANALYTICS_VIEW,
    AUDIT_LOG_VIEW,
)
# Aliases for backward compat expected by earlier __init__ (Tenant* naming)
from engine.model.errors import AuthorizationError, TenantIsolationError

TenantRole = Role
TenantContext = UserContext
EvidenceAccessRequest = AccessRequest
AuthorizationDecision = dict
EvidenceAuthorizationEngine = AuthorizationEngine
TenantIsolationEnforcer = AuthorizationEngine
EvidenceAuthorizationGuard = AuthorizationEngine

def create_tenant_context(*a, **kw):
    return UserContext(*a, **kw)

def check_tenant_isolation(*a, **kw):
    eng = get_authorization_engine()
    # thin wrapper
    return eng.authorize(*a, **kw)

def require_permission(*a, **kw):
    return has_permission(*a, **kw)

from engine.security.worker_isolation import (
    ResourceLimits,
    ResourceMonitor,
    ExecutionSandbox,
    WorkerIsolationManager,
    DEFAULT_LIMITS,
    STRICT_LIMITS,
    PERMISSIVE_LIMITS,
)
from engine.security.rate_limiting import (
    RateLimitConfig,
    QuotaConfig,
    TokenBucket,
    SlidingWindowRateLimiter,
    QuotaManager,
    QuotaBypassDetector,
    QuotaEnforcer,
    DEFAULT_RATE_LIMIT_CONFIG,
    DEFAULT_QUOTA_CONFIG,
    STRICT_RATE_LIMIT_CONFIG,
    STRICT_QUOTA_CONFIG,
    PERMISSIVE_RATE_LIMIT_CONFIG,
    PERMISSIVE_QUOTA_CONFIG,
    create_strict_enforcer,
    create_permissive_enforcer,
    create_default_enforcer,
    get_global_enforcer,
)

__all__ = [
    "AUDIT_GUARD_REJECT",
    "CaptureEnforcer",
    "FindingRecord",
    "FindingsGateway",
    "FindingSink",
    "InMemoryFindingSink",
    "ProductionGate",
    "SSRFPolicy",
    "SecretsVault",
    "classify_ip",
    "redact_mapping",
    "redact_text",
    "redact_any",
    "sanitize_api_response",
    "sanitize_error_message",
    "sanitize_log_record",
    "sanitize_model_output",
    "sanitize_tool_arguments",
    "validate_target_urls",
    "validate_url",
    "validate_evidence_chain",
    "EvidenceIntegrityEngine",
    "EvidenceRecord",
    "EvidenceTamperDetector",
    "SecureEvidenceStore",
    "AuthorizedEvidenceStore",
    "EvidencePermission",
    "TenantRole",
    "TenantContext",
    "EvidenceAccessRequest",
    "AuthorizationDecision",
    "EvidenceAuthorizationEngine",
    "TenantIsolationEnforcer",
    "EvidenceAuthorizationGuard",
    "create_tenant_context",
    "check_tenant_isolation",
    "require_permission",
    "AuthorizationError",
    "TenantIsolationError",
    "ResourceType",
    "Role",
    "UserContext",
    "ResourceContext",
    "AccessRequest",
    "AuthorizationEngine",
    "get_authorization_engine",
    "authenticate_user",
    "authorize_resource",
    "has_permission",
    "get_permissions",
    "ResourceLimits",
    "ResourceMonitor",
    "ExecutionSandbox",
    "WorkerIsolationManager",
    "DEFAULT_LIMITS",
    "STRICT_LIMITS",
    "PERMISSIVE_LIMITS",
    "RateLimitConfig",
    "QuotaConfig",
    "TokenBucket",
    "SlidingWindowRateLimiter",
    "QuotaManager",
    "QuotaBypassDetector",
    "QuotaEnforcer",
    "DEFAULT_RATE_LIMIT_CONFIG",
    "DEFAULT_QUOTA_CONFIG",
    "STRICT_RATE_LIMIT_CONFIG",
    "STRICT_QUOTA_CONFIG",
    "PERMISSIVE_RATE_LIMIT_CONFIG",
    "PERMISSIVE_QUOTA_CONFIG",
    "create_strict_enforcer",
    "create_permissive_enforcer",
    "create_default_enforcer",
    "get_global_enforcer",
]
