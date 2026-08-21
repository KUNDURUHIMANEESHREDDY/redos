import hashlib
import hmac
import json
from datetime import datetime
from typing import Any
from uuid import UUID
try:
    from motor.motor_asyncio import AsyncIOMotorDatabase
except ImportError:
    AsyncIOMotorDatabase = Any  # type: ignore
from pydantic import ValidationError
from security.models.evidence import Evidence, EvidenceType, EvidenceStatus, EvidenceIngestRequest
try:
    from security.database import get_database
except ImportError:
    get_database = lambda: None  # type: ignore
try:
    import structlog
    logger = structlog.get_logger()
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

from engine.model.errors import EvidenceTamperedError


def _canonical_hash(data: Any, algorithm: str = "sha256") -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")
    return hashlib.new(algorithm, canonical).hexdigest()


def _verify_hash(data: Any, expected: str | None, algorithm: str = "sha256") -> bool:
    if not expected:
        return False
    computed = _canonical_hash(data, algorithm)
    return hmac.compare_digest(computed, expected)


class EvidenceValidationError(Exception):
    def __init__(self, message: str, errors: list[str]):
        self.message = message
        self.errors = errors
        super().__init__(message)


class EvidenceIngestionBoundary:
    REQUIRED_FIELDS_BY_TYPE: dict[EvidenceType, list[str]] = {
        EvidenceType.NETWORK_TRAFFIC: ["src_ip", "dst_ip"],
        EvidenceType.LOG_ENTRY: ["message", "level"],
        EvidenceType.FILE_SYSTEM: ["path", "operation"],
        EvidenceType.PROCESS_TRACE: ["pid", "command"],
        EvidenceType.API_CALL: ["method", "path"],
        EvidenceType.USER_ACTION: ["user_id", "action"],
        EvidenceType.CONFIGURATION: ["config_type", "key"],
        EvidenceType.VULNERABILITY_SCAN: ["scanner", "vulnerability_id"],
    }

    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.collection = self.db.evidence

    async def ingest(self, request: EvidenceIngestRequest) -> Evidence:
        errors = self._validate_request(request)
        if errors:
            raise EvidenceValidationError(f"Evidence validation failed: {'; '.join(errors)}", errors)

        # Canonical serialization + cryptographic checksum stored with evidence
        content_hash = _canonical_hash(request.raw_data)
        tenant_id = (request.metadata or {}).get("tenant_id", "default-tenant")
        evidence = Evidence(
            execution_id=request.execution_id,
            type=request.type,
            source=request.source,
            timestamp=request.timestamp or datetime.utcnow(),
            raw_data=request.raw_data,
            metadata=request.metadata or {},
            tenant_id=tenant_id,
            content_hash=content_hash,
            content_hash_algorithm="sha256",
            status=EvidenceStatus.RAW,
        )
        await self.collection.insert_one(evidence.model_dump())
        logger.info("Evidence ingested", evidence_id=str(evidence.id), type=request.type.value)
        return evidence

    async def ingest_batch(self, requests: list[EvidenceIngestRequest]) -> list[Evidence]:
        all_errors: dict[int, list[str]] = {}
        valid_evidence: list[Evidence] = []

        for idx, request in enumerate(requests):
            errors = self._validate_request(request)
            if errors:
                all_errors[idx] = errors
            else:
                content_hash = _canonical_hash(request.raw_data)
                tenant_id = (request.metadata or {}).get("tenant_id", "default-tenant")
                evidence = Evidence(
                    execution_id=request.execution_id,
                    type=request.type,
                    source=request.source,
                    timestamp=request.timestamp or datetime.utcnow(),
                    raw_data=request.raw_data,
                    metadata=request.metadata or {},
                    tenant_id=tenant_id,
                    content_hash=content_hash,
                    content_hash_algorithm="sha256",
                    status=EvidenceStatus.RAW,
                )
                valid_evidence.append(evidence)

        if all_errors:
            raise EvidenceValidationError(
                f"Batch validation failed for {len(all_errors)} items",
                [f"Item {idx}: {errs}" for idx, errs in all_errors.items()]
            )

        if valid_evidence:
            await self.collection.insert_many([e.model_dump() for e in valid_evidence])

        logger.info("Batch evidence ingested", count=len(valid_evidence))
        return valid_evidence

    def _validate_request(self, request: EvidenceIngestRequest) -> list[str]:
        errors = []

        if not request.raw_data:
            errors.append("raw_data cannot be empty")
            return errors

        required_fields = self.REQUIRED_FIELDS_BY_TYPE.get(request.type, [])
        for field in required_fields:
            if field not in request.raw_data:
                errors.append(f"Missing required field for {request.type.value}: {field}")

        return errors

    async def get_by_id(self, evidence_id: UUID, tenant_id: str | None = None) -> Evidence | None:
        doc = await self.collection.find_one({"_id": str(evidence_id)})
        if not doc:
            return None
        evidence = Evidence(**doc)
        # Tenant isolation
        if tenant_id and evidence.tenant_id != tenant_id:
            raise PermissionError(f"Tenant {tenant_id} cannot access evidence {evidence_id}")
        # Integrity verification on every read
        if evidence.content_hash and not _verify_hash(evidence.raw_data, evidence.content_hash, evidence.content_hash_algorithm):
            raise EvidenceTamperedError(f"Evidence {evidence_id} failed integrity check - tampering detected")
        return evidence

    async def get_by_execution(self, execution_id: UUID, tenant_id: str | None = None) -> list[Evidence]:
        cursor = self.collection.find({"execution_id": str(execution_id)})
        out: list[Evidence] = []
        async for doc in cursor:
            evidence = Evidence(**doc)
            if tenant_id and evidence.tenant_id != tenant_id:
                continue
            if evidence.content_hash and not _verify_hash(evidence.raw_data, evidence.content_hash, evidence.content_hash_algorithm):
                raise EvidenceTamperedError(f"Evidence {evidence.id} failed integrity check - tampering detected")
            out.append(evidence)
        return out

    async def verify_evidence_integrity(self, evidence_id: UUID) -> tuple[bool, str]:
        doc = await self.collection.find_one({"_id": str(evidence_id)})
        if not doc:
            return False, "not found"
        evidence = Evidence(**doc)
        if not evidence.content_hash:
            return False, "missing hash"
        ok = _verify_hash(evidence.raw_data, evidence.content_hash, evidence.content_hash_algorithm)
        return (ok, "verified" if ok else "checksum mismatch")

    async def update_status(self, evidence_id: UUID, status: EvidenceStatus, errors: list[str] | None = None) -> Evidence | None:
        update = {"status": status.value, "updated_at": datetime.utcnow()}
        if errors is not None:
            update["validation_errors"] = errors
        doc = await self.collection.find_one_and_update(
            {"_id": str(evidence_id)},
            {"$set": update},
            return_document=True,
        )
        return Evidence(**doc) if doc else None


class EvidenceNormalizer:
    NORMALIZERS = {
        EvidenceType.NETWORK_TRAFFIC: "_normalize_network",
        EvidenceType.LOG_ENTRY: "_normalize_log",
        EvidenceType.FILE_SYSTEM: "_normalize_filesystem",
        EvidenceType.PROCESS_TRACE: "_normalize_process",
        EvidenceType.API_CALL: "_normalize_api",
        EvidenceType.USER_ACTION: "_normalize_user_action",
        EvidenceType.CONFIGURATION: "_normalize_config",
        EvidenceType.VULNERABILITY_SCAN: "_normalize_vuln_scan",
    }

    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.collection = self.db.evidence
        self.ingestion_boundary = EvidenceIngestionBoundary(db)

    async def normalize(self, evidence_id: UUID) -> Evidence | None:
        evidence = await self.ingestion_boundary.get_by_id(evidence_id)
        if not evidence:
            return None

        if evidence.status != EvidenceStatus.RAW and evidence.status != EvidenceStatus.VALIDATED:
            logger.warning("Evidence not in normalizable state", evidence_id=str(evidence_id), status=evidence.status.value)
            return evidence

        normalizer_method = self.NORMALIZERS.get(evidence.type)
        if not normalizer_method:
            logger.warning("No normalizer for evidence type", type=evidence.type.value)
            return await self.ingestion_boundary.update_status(evidence_id, EvidenceStatus.NORMALIZED)

        try:
            normalize_func = getattr(self, normalizer_method)
            normalized = await normalize_func(evidence.raw_data)
            updated = await self.collection.find_one_and_update(
                {"_id": str(evidence_id)},
                {
                    "$set": {
                        "normalized_data": normalized,
                        "status": EvidenceStatus.NORMALIZED.value,
                        "updated_at": datetime.utcnow(),
                    }
                },
                return_document=True,
            )
            logger.info("Evidence normalized", evidence_id=str(evidence_id))
            return Evidence(**updated) if updated else None
        except Exception as e:
            logger.error("Normalization failed", evidence_id=str(evidence_id), error=str(e))
            await self.ingestion_boundary.update_status(evidence_id, EvidenceStatus.VALIDATED, [str(e)])
            return None

    async def _normalize_network(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "src_ip": raw.get("src_ip"),
            "dst_ip": raw.get("dst_ip"),
            "src_port": raw.get("src_port"),
            "dst_port": raw.get("dst_port"),
            "protocol": raw.get("protocol"),
            "bytes_sent": raw.get("bytes_sent", 0),
            "bytes_received": raw.get("bytes_received", 0),
            "duration_ms": raw.get("duration_ms", 0),
            "flags": raw.get("flags", []),
            "payload_hash": raw.get("payload_hash"),
        }

    async def _normalize_log(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "level": raw.get("level", "info"),
            "message": raw.get("message", ""),
            "logger": raw.get("logger"),
            "thread": raw.get("thread"),
            "timestamp": raw.get("timestamp"),
            "fields": raw.get("fields", {}),
        }

    async def _normalize_filesystem(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "path": raw.get("path"),
            "operation": raw.get("operation"),
            "permissions": raw.get("permissions"),
            "owner": raw.get("owner"),
            "size": raw.get("size", 0),
            "hash": raw.get("hash"),
            "is_sensitive": raw.get("is_sensitive", False),
        }

    async def _normalize_process(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "pid": raw.get("pid"),
            "ppid": raw.get("ppid"),
            "command": raw.get("command"),
            "arguments": raw.get("arguments", []),
            "environment": raw.get("environment", {}),
            "user": raw.get("user"),
            "cwd": raw.get("cwd"),
            "start_time": raw.get("start_time"),
        }

    async def _normalize_api(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "method": raw.get("method"),
            "path": raw.get("path"),
            "query_params": raw.get("query_params", {}),
            "headers": raw.get("headers", {}),
            "request_body": raw.get("request_body"),
            "response_status": raw.get("response_status"),
            "response_body": raw.get("response_body"),
            "latency_ms": raw.get("latency_ms", 0),
        }

    async def _normalize_user_action(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "user_id": raw.get("user_id"),
            "action": raw.get("action"),
            "resource": raw.get("resource"),
            "resource_id": raw.get("resource_id"),
            "permissions": raw.get("permissions", []),
            "session_id": raw.get("session_id"),
            "ip_address": raw.get("ip_address"),
        }

    async def _normalize_config(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "config_type": raw.get("config_type"),
            "key": raw.get("key"),
            "value": raw.get("value"),
            "source": raw.get("source"),
            "is_secret": raw.get("is_secret", False),
        }

    async def _normalize_vuln_scan(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "scanner": raw.get("scanner"),
            "vulnerability_id": raw.get("vulnerability_id"),
            "title": raw.get("title"),
            "severity": raw.get("severity"),
            "cvss_score": raw.get("cvss_score"),
            "affected_component": raw.get("affected_component"),
            "fixed_version": raw.get("fixed_version"),
            "references": raw.get("references", []),
        }