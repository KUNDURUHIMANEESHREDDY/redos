class EngineError(Exception):
    code = "ENGINE_ERROR"


class ConfigurationError(EngineError):
    code = "CONFIGURATION_ERROR"


class SSRFBlocked(ConfigurationError):
    code = "SSRF_BLOCKED"


class TargetError(EngineError):
    code = "TARGET_ERROR"


class TargetUnreachable(TargetError):
    code = "TARGET_UNREACHABLE"


class TargetAuthError(TargetError):
    code = "TARGET_AUTH_ERROR"


class TargetProtocolError(TargetError):
    code = "TARGET_PROTOCOL_ERROR"


class TargetTimeout(TargetError):
    code = "TARGET_TIMEOUT"


class ExecutionError(EngineError):
    code = "EXECUTION_ERROR"


class AttackCancelled(ExecutionError):
    code = "ATTACK_CANCELLED"


class AttackTimeout(ExecutionError):
    code = "ATTACK_TIMEOUT"


class PayloadError(ExecutionError):
    code = "PAYLOAD_ERROR"


class UnsupportedOperation(ExecutionError):
    code = "UNSUPPORTED_OPERATION"


class EvidenceError(EngineError):
    code = "EVIDENCE_ERROR"


class MockEvidenceRejected(EvidenceError):
    code = "MOCK_EVIDENCE_REJECTED"


class MissingSecret(ConfigurationError):
    code = "MISSING_SECRET"


class PluginError(ConfigurationError):
    code = "PLUGIN_ERROR"


class ReplayMismatch(EvidenceError):
    code = "REPLAY_MISMATCH"


class EvidenceIntegrityError(EngineError):
    code = "EVIDENCE_INTEGRITY_ERROR"


class EvidenceNotFoundError(EngineError):
    code = "EVIDENCE_NOT_FOUND"


class EvidenceTamperedError(EngineError):
    code = "EVIDENCE_TAMPERED"


class AuthorizationError(EngineError):
    code = "AUTHORIZATION_ERROR"


class TenantIsolationError(EngineError):
    code = "TENANT_ISOLATION_ERROR"


class SecurityViolation(EngineError):
    code = "SECURITY_VIOLATION"


class ResourceExhausted(EngineError):
    code = "RESOURCE_EXHAUSTED"

    def __init__(self, message: str, resource: str = "", limit: float | None = None, current: float | None = None):
        super().__init__(message)
        self.resource = resource
        self.limit = limit
        self.current = current


class QuotaExceeded(EngineError):
    code = "QUOTA_EXCEEDED"


class RateLimitExceeded(EngineError):
    code = "RATE_LIMIT_EXCEEDED"
