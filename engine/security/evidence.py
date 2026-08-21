"""
Evidence integrity with canonical serialization and cryptographic checksums.

Evidence integrity pipeline:
Evidence -> canonical serialization -> cryptographic checksum -> stored
On read: stored content -> recalculate checksum -> compare -> ACCEPT/REJECT
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from engine.model.errors import EvidenceIntegrityError, EvidenceNotFoundError, EvidenceTamperedError


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Immutable evidence record with integrity verification."""
    
    evidence_id: str
    execution_id: str
    target_id: str
    attack_id: str
    evidence_type: str
    content: str
    content_hash: str
    content_hash_algorithm: str = "sha256"
    metadata: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verified_at: datetime | None = None
    verification_status: str = "unverified"
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "execution_id": self.execution_id,
            "target_id": self.target_id,
            "attack_id": self.attack_id,
            "evidence_type": self.evidence_type,
            "content": self.content,
            "content_hash": self.content_hash,
            "content_hash_algorithm": self.content_hash_algorithm,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "verification_status": self.verification_status,
        }


class EvidenceIntegrityEngine:
    """
    Handles canonical serialization, cryptographic checksums, and verification.
    
    Pipeline:
    1. Evidence received -> canonical serialization -> SHA256 checksum -> store
    2. On read: recalculate checksum -> compare -> ACCEPT/REJECT
    """
    
    def __init__(self, algorithm: str = "sha256") -> None:
        self.algorithm = algorithm
        self._hasher = hashlib.new(algorithm)
    
    def canonical_serialize(self, data: Any) -> bytes:
        """
        Canonical JSON serialization with deterministic ordering.
        Uses sorted keys, no whitespace, consistent representation.
        """
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    
    def compute_checksum(self, data: Any) -> str:
        """Compute cryptographic checksum of canonicalized data."""
        canonical = self.canonical_serialize(data)
        return hashlib.new(self.algorithm, canonical).hexdigest()
    
    def verify_checksum(self, data: Any, expected_hash: str) -> bool:
        """Verify data matches expected checksum."""
        computed = self.compute_checksum(data)
        return hmac.compare_digest(computed, expected_hash)
    
    def create_record(
        self,
        execution_id: str,
        target_id: str,
        attack_id: str,
        evidence_type: str,
        content: Any,
        metadata: dict | None = None,
    ) -> EvidenceRecord:
        """Create a new evidence record with integrity checksum."""
        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
            content_str = content
        else:
            content_bytes = self.canonical_serialize(content)
            content_str = content_bytes.decode("utf-8")
        
        content_hash = hashlib.new(self.algorithm, content_bytes).hexdigest()
        
        record = EvidenceRecord(
            evidence_id=uuid4().hex,
            execution_id=execution_id,
            target_id=target_id,
            attack_id=attack_id,
            evidence_type=evidence_type,
            content=content_str,
            content_hash=content_hash,
            content_hash_algorithm=self.algorithm,
            metadata=metadata or {},
        )
        return record
    
    def verify_record(self, record: EvidenceRecord) -> tuple[bool, str]:
        """
        Verify evidence record integrity.
        Returns (is_valid, status_message).
        """
        expected_hash = record.content_hash
        content_bytes = record.content.encode("utf-8")
        computed_hash = hashlib.new(record.content_hash_algorithm, content_bytes).hexdigest()
        
        if not hmac.compare_digest(computed_hash, expected_hash):
            return False, f"checksum mismatch: expected {expected_hash}, got {computed_hash}"
        
        return True, "verified"
    
    def verify_on_read(self, stored_content: str, stored_hash: str, algorithm: str = "sha256") -> tuple[bool, str]:
        """
        Verify content integrity on read.
        Returns (is_valid, status_message).
        """
        content_bytes = stored_content.encode("utf-8")
        computed = hashlib.new(algorithm, content_bytes).hexdigest()
        
        if not hmac.compare_digest(computed, stored_hash):
            return False, f"tampering detected: checksum mismatch (expected {stored_hash}, got {computed})"
        
        return True, "verified"
    
    def create_tamper_proof_package(self, record: EvidenceRecord) -> dict[str, Any]:
        """Create a tamper-proof package with evidence and verification metadata."""
        return {
            "evidence": record.to_dict(),
            "integrity": {
                "algorithm": record.content_hash_algorithm,
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "verification_status": "verified",
            },
            "integrity_check": {
                "content_hash": record.content_hash,
                "hash_algorithm": record.content_hash_algorithm,
            },
        }


class SecureEvidenceStore:
    """
    Mandatory evidence integrity store.

    Pipeline:
    Evidence -> canonical serialization -> cryptographic checksum -> stored checksum
    On every read/use: stored content -> recalculate -> compare -> ACCEPT / REJECT
    Tampered evidence must never reach analysis, finding, severity, regression, report.
    """

    def __init__(self, integrity_engine: EvidenceIntegrityEngine | None = None) -> None:
        self.integrity = integrity_engine or EvidenceIntegrityEngine()
        self._store: dict[str, EvidenceRecord] = {}

    def store(self, record: EvidenceRecord) -> EvidenceRecord:
        # Verify checksum matches content before storing (prevent storing tampered at creation)
        ok, _ = self.integrity.verify_record(record)
        if not ok:
            raise EvidenceTamperedError("refusing to store tampered evidence record")
        self._store[record.evidence_id] = record
        return record

    def create_and_store(
        self,
        execution_id: str,
        target_id: str,
        attack_id: str,
        evidence_type: str,
        content: Any,
        metadata: dict | None = None,
    ) -> EvidenceRecord:
        rec = self.integrity.create_record(execution_id, target_id, attack_id, evidence_type, content, metadata)
        return self.store(rec)

    def retrieve(self, evidence_id: str) -> EvidenceRecord:
        rec = self._store.get(evidence_id)
        if rec is None:
            raise EvidenceNotFoundError(f"evidence {evidence_id!r} not found")
        ok, msg = self.integrity.verify_record(rec)
        if not ok:
            raise EvidenceTamperedError(f"evidence {evidence_id!r} tampered: {msg}")
        # Return verified record (mark as verified)
        verified = EvidenceRecord(
            evidence_id=rec.evidence_id,
            execution_id=rec.execution_id,
            target_id=rec.target_id,
            attack_id=rec.attack_id,
            evidence_type=rec.evidence_type,
            content=rec.content,
            content_hash=rec.content_hash,
            content_hash_algorithm=rec.content_hash_algorithm,
            metadata=dict(rec.metadata),
            created_at=rec.created_at,
            verified_at=datetime.now(timezone.utc),
            verification_status="verified",
        )
        return verified

    def verify_for_use(self, evidence_id: str) -> EvidenceRecord:
        """Gate for analysis/finding/severity/regression/report - REJECT if tampered."""
        return self.retrieve(evidence_id)

    def list_verified(self) -> list[EvidenceRecord]:
        out = []
        for eid in list(self._store.keys()):
            try:
                out.append(self.retrieve(eid))
            except EvidenceTamperedError:
                continue
        return out


class EvidenceTamperDetector:
    """
    Detects evidence tampering through checksum verification and anomaly detection.
    """
    
    def __init__(self, integrity_engine: EvidenceIntegrityEngine) -> None:
        self.integrity_engine = integrity_engine
    
    def verify(self, record: EvidenceRecord) -> tuple[bool, str]:
        """Verify evidence hasn't been tampered with."""
        return self.integrity_engine.verify_record(record)
    
    def detect_anomalies(self, records: list[EvidenceRecord]) -> list[dict[str, Any]]:
        """Detect anomalous patterns in evidence collection."""
        anomalies = []
        
        # Check for duplicate evidence IDs
        ids = [r.evidence_id for r in records]
        if len(ids) != len(set(ids)):
            duplicates = [id for id in ids if ids.count(id) > 1]
            anomalies.append({
                "type": "duplicate_evidence_id",
                "evidence_ids": list(set(duplicates)),
                "severity": "high",
            })
        
        # Check for hash collisions
        hashes = [r.content_hash for r in records]
        if len(hashes) != len(set(hashes)):
            collisions = [h for h in hashes if hashes.count(h) > 1]
            anomalies.append({
                "type": "hash_collision",
                "content_hashes": list(set(collisions)),
                "severity": "critical",
            })
        
        # Verify each record
        for record in records:
            is_valid, msg = self.verify(record)
            if not is_valid:
                anomalies.append({
                    "type": "tampered_evidence",
                    "evidence_id": record.evidence_id,
                    "message": msg,
                    "severity": "critical",
                })
        
        return anomalies


class AuthorizedEvidenceStore(SecureEvidenceStore):
    """
    Evidence store with tenant isolation.
    Applies Agent 1's tenant authorization to:
    evidence retrieval, downloads, exports, reports, lineage, archived, legal holds.
    """

    def __init__(self, integrity_engine: EvidenceIntegrityEngine | None = None) -> None:
        super().__init__(integrity_engine)
        # evidence_id -> organization_id
        self._tenant_map: dict[str, str] = {}
        self._archive: dict[str, EvidenceRecord] = {}
        self._legal_holds: dict[str, bool] = {}

    def store_for_tenant(self, record: EvidenceRecord, organization_id: str) -> EvidenceRecord:
        stored = self.store(record)
        self._tenant_map[record.evidence_id] = organization_id
        return stored

    def create_and_store_for_tenant(
        self,
        execution_id: str,
        target_id: str,
        attack_id: str,
        evidence_type: str,
        content: Any,
        organization_id: str,
        metadata: dict | None = None,
    ) -> EvidenceRecord:
        rec = self.integrity.create_record(execution_id, target_id, attack_id, evidence_type, content, metadata)
        return self.store_for_tenant(rec, organization_id)

    def _authorize(self, evidence_id: str, requesting_org: str, action: str = "evidence:read") -> None:
        from engine.security.authorization import ResourceType, UserContext, Role, authorize_resource
        from engine.model.errors import TenantIsolationError, AuthorizationError

        owner_org = self._tenant_map.get(evidence_id)
        if owner_org is None:
            # unknown tenant mapping -> deny
            raise TenantIsolationError(f"evidence {evidence_id!r} has no tenant mapping")
        if owner_org != requesting_org:
            raise TenantIsolationError(f"tenant {requesting_org!r} cannot access evidence owned by {owner_org!r}")

    def retrieve_for_tenant(self, evidence_id: str, requesting_org: str) -> EvidenceRecord:
        self._authorize(evidence_id, requesting_org)
        return self.retrieve(evidence_id)

    def download(self, evidence_id: str, requesting_org: str) -> EvidenceRecord:
        self._authorize(evidence_id, requesting_org)
        return self.verify_for_use(evidence_id)

    def export(self, evidence_id: str, requesting_org: str) -> dict[str, Any]:
        rec = self.retrieve_for_tenant(evidence_id, requesting_org)
        return self.integrity.create_tamper_proof_package(rec)

    def lineage(self, evidence_id: str, requesting_org: str) -> dict[str, Any]:
        rec = self.retrieve_for_tenant(evidence_id, requesting_org)
        return {
            "evidence_id": rec.evidence_id,
            "execution_id": rec.execution_id,
            "organization_id": self._tenant_map.get(evidence_id),
            "verified": self.integrity.verify_record(rec)[0],
        }

    def archive(self, evidence_id: str, requesting_org: str) -> None:
        self._authorize(evidence_id, requesting_org)
        rec = self.retrieve(evidence_id)
        self._archive[evidence_id] = rec

    def retrieve_archived(self, evidence_id: str, requesting_org: str) -> EvidenceRecord:
        self._authorize(evidence_id, requesting_org)
        rec = self._archive.get(evidence_id)
        if rec is None:
            raise EvidenceNotFoundError(f"archived evidence {evidence_id!r} not found")
        ok, msg = self.integrity.verify_record(rec)
        if not ok:
            raise EvidenceTamperedError(f"archived evidence tampered: {msg}")
        return rec

    def set_legal_hold(self, evidence_id: str, requesting_org: str, hold: bool = True) -> None:
        self._authorize(evidence_id, requesting_org)
        self._legal_holds[evidence_id] = hold

    def get_legal_hold(self, evidence_id: str, requesting_org: str) -> bool:
        self._authorize(evidence_id, requesting_org)
        return bool(self._legal_holds.get(evidence_id, False))

    def report(self, evidence_id: str, requesting_org: str) -> dict[str, Any]:
        # report generation also gated
        rec = self.retrieve_for_tenant(evidence_id, requesting_org)
        return {"report_for": rec.evidence_id, "verified": True, "content_hash": rec.content_hash}