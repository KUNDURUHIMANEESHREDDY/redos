from __future__ import annotations

from typing import TYPE_CHECKING

from engine.model.attack import Provenance
from engine.model.errors import MockEvidenceRejected
from engine.model.events import EventTypes

if TYPE_CHECKING:
    from engine.model.execution import EvidenceChainValidation, ExecutionStatus, ObservedExecution

AUDIT_GUARD_REJECT = "guard.mock_evidence_rejected"


def validate_evidence_chain(execution: "ObservedExecution") -> "EvidenceChainValidation":
    from engine.model.execution import EvidenceChainValidation, ExecutionStatus
    import hashlib

    violations: list[str] = []
    if not execution.execution_id:
        violations.append("missing execution_id")
    if not execution.target_id:
        violations.append("missing target_id")
    if not execution.attack_id:
        violations.append("missing attack_id")
    if execution.started_at is None:
        violations.append("missing started_at")
    if execution.finished_at is None:
        violations.append("missing finished_at")
    if not execution.status.is_final():
        violations.append(f"execution not finalized: {execution.status.value}")
    if not execution.events:
        violations.append("no evidence events recorded")
    first_ts = None
    for event in execution.events:
        if event.type == EventTypes.EXECUTION_STARTED and event.timestamp is None:
            violations.append("execution_started event missing timestamp")
        if event.type in (EventTypes.MODEL_REQUEST, EventTypes.MODEL_RESPONSE, EventTypes.MODEL_INTERACTION, EventTypes.TOOL_CALL, EventTypes.RETRIEVAL):
            provenance = event.data.get("provenance")
            if provenance not in (Provenance.LIVE.value, "live"):
                violations.append(f"event {event.event_id} has non-live provenance: {provenance!r}")
        ts = event.timestamp
        if ts is not None:
            if first_ts is not None and ts < first_ts:
                violations.append(f"event timestamps out of order near {event.event_id}")
            first_ts = ts
        # Tamper check: if event data has content_hash, verify it
        if "content_hash" in event.data and "content" in event.data:
            expected = event.data["content_hash"]
            computed = hashlib.sha256(str(event.data["content"]).encode("utf-8")).hexdigest()
            if expected != computed:
                violations.append(f"event {event.event_id} tampered: content_hash mismatch")
    if execution.artifacts:
        for artifact in execution.artifacts:
            if not artifact.data.get("digest"):
                violations.append(f"artifact {artifact.data.get('artifact_id')} missing digest")
            else:
                # Verify artifact digest integrity
                aid = artifact.data.get("artifact_id", "")
                name = artifact.data.get("name", "")
                content = artifact.data.get("content", "")
                expected = artifact.data.get("digest")
                if content:  # only verify if content present (non-redacted)
                    computed = hashlib.sha256(f"{aid}:{name}:{content}".encode("utf-8")).hexdigest()
                    if computed != expected:
                        violations.append(f"artifact {aid} tampered: digest mismatch")
                # Check for tamper marker
                if artifact.data.get("tampered"):
                    violations.append(f"artifact {aid} marked tampered")
    return EvidenceChainValidation(valid=not violations, violations=tuple(violations))


def validate_evidence_for_processing(execution: "ObservedExecution") -> None:
    """Gate that must be called before analysis/finding/severity/regression/report.
    Raises MockEvidenceRejected if tampered."""
    validation = validate_evidence_chain(execution)
    if not validation.valid:
        raise MockEvidenceRejected("tampered evidence rejected for processing: " + "; ".join(validation.violations))


class ProductionGate:
    def validate(self, execution: "ObservedExecution") -> "EvidenceChainValidation":
        from engine.model.execution import EvidenceChainValidation

        validation = validate_evidence_chain(execution)
        if not validation.valid:
            raise MockEvidenceRejected("evidence chain invalid: " + "; ".join(validation.violations))
        return validation

    def audit_event(self, execution_id: str, reason: str) -> dict:
        return {
            "action": AUDIT_GUARD_REJECT,
            "execution_id": execution_id,
            "reason": reason,
            "subject": "production_gate",
        }