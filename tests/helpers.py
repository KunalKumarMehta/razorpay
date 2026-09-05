"""Reusable test helpers and fixtures for PayoutProof tests."""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from payoutproof.core.models import (
    ProcessingAuthorityRecord,
    PaymentIntent,
    EvidenceItem,
    Finding,
    RiskCaseState,
    PolicyEvaluationResult,
    CaseInvestigation,
    AuditEvent,
)
from payoutproof.core.enums import (
    TruthState,
    PolicyOutcome,
    IntentStatus,
    DestinationStatus,
    CasePhase,
    ProcessingAuthorityStatus,
)
from payoutproof.core.crypto import (
    sha256_hex,
    compute_intent_hash,
    compute_snapshot_hash,
    compute_audit_hash,
)
from payoutproof.audit.chain import GENESIS_HASH

# Explicit caller-provided distinct fixed secrets for test isolated execution
TEST_GRANT_SECRET = "test-grant-secret-at-least-32-chars-long-fixed"
TEST_AUDIT_CHECKPOINT_SECRET = "test-checkpoint-secret-32-chars-long-fixed"


def make_confirmed_intent(
    counterparty: str = "Kaveri Components",
    destination: str = "HDFC ••4821",
    amount: str = "425000",
    currency: str = "INR",
    purpose: str = "Tooling deposit",
    instruction_reference: Optional[str] = "VOICE-17",
    provenance: Optional[List[str]] = None,
    destination_status: DestinationStatus = DestinationStatus.UNAPPROVED,
    **overrides,
) -> PaymentIntent:
    """Create an authentic confirmed PaymentIntent with canonically computed intent_hash."""
    intent = PaymentIntent(
        counterparty=counterparty,
        destination=destination,
        destination_status=destination_status,
        amount=amount,
        currency=currency,
        purpose=purpose,
        instruction_reference=instruction_reference,
        provenance=provenance or ["VOICE-17: span 00:04"],
        status=IntentStatus.CONFIRMED,
        intent_hash=None,
    )
    h = compute_intent_hash(intent)
    return intent.model_copy(update={"intent_hash": h, **overrides})


def make_valid_authority_record(**overrides) -> ProcessingAuthorityRecord:
    """Create a fully complete, valid ProcessingAuthorityRecord for tests."""
    defaults = {
        "data_class": "SYNTHETIC_VOICE_AND_TEXT",
        "source": "WhatsApp_Business_Verified",
        "subject_category": "VENDOR",
        "submitter": "Payment Operator",
        "purpose": "Payment intent extraction and policy verification",
        "asserted_authority_ref": "FIN-POLICY-2026-AUTH-01",
        "permitted_uses": ["PAYMENT_INTENT_EXTRACTION", "POLICY_GATE_EVALUATION"],
        "processing_route": "LOCAL_ONLY_SECURE_PIPELINE",
        "redaction_declaration": "SYNTHETIC_DATA_NO_REAL_PII",
        "retention_days": 7,
        "legal_hold": False,
        "restrictions": ["NO_EXTERNAL_TRANSMISSION", "NO_MODEL_TRAINING"],
        "is_valid": True,
    }
    defaults.update(overrides)
    return ProcessingAuthorityRecord(**defaults)


def make_valid_evidence_payload(
    content: str | bytes = "Transfer INR 4,25,000 to Kaveri Components HDFC 4821 for tooling deposit.",
    mime_type: str = "text/plain",
    title: str = "Urgent voice note + message",
    filename: str = "instruction.txt",
    **overrides,
) -> Dict[str, Any]:
    """Create a valid evidence payload dict."""
    payload = {
        "content": content,
        "mime_type": mime_type,
        "title": title,
        "filename": filename,
    }
    payload.update(overrides)
    return payload


def make_authorized_bundle_action(
    case_id: str = "RC-TEST-001",
    authority: Optional[ProcessingAuthorityRecord | Dict[str, Any]] = None,
    evidence: Optional[Dict[str, Any]] = None,
    title: Optional[str] = None,
    **payload_overrides,
) -> Dict[str, Any]:
    """Create a reusable authorized-admission action with typed PAR and evidence."""
    auth = authority if authority is not None else make_valid_authority_record()
    ev = evidence if evidence is not None else make_valid_evidence_payload()
    payload = {
        "case_id": case_id,
        "processing_authority": auth,
        "evidence": ev,
        "title": title or ev.get("title", "Urgent voice note + message"),
    }
    payload.update(payload_overrides)
    return {
        "type": "ADMIT_AUTHORIZED_BUNDLE",
        "payload": payload,
    }


def make_admitted_case_state(
    case_id: str = "RC-TEST-001",
    intent: Optional[PaymentIntent] = None,
    findings: Optional[List[Finding]] = None,
    authority: Optional[ProcessingAuthorityRecord] = None,
    **overrides,
) -> RiskCaseState:
    """Create a canonical admitted RiskCaseState with valid authority and evidence."""
    auth = authority or make_valid_authority_record()
    content_str = "Transfer INR 4,25,000 to Kaveri Components HDFC 4821 for tooling deposit."
    ev_item = EvidenceItem(
        id=f"EV-{case_id}-01",
        item_type="VOICE_AND_TEXT_BUNDLE",
        title="Urgent voice note + message",
        content_hash=sha256_hex(content_str.encode("utf-8")),
        finding="admitted",
        truth_state=TruthState.SUPPORTED,
        metadata={
            "mime_type": "text/plain",
            "size_bytes": len(content_str.encode("utf-8")),
            "filename": "instruction.txt",
            "data_class": auth.data_class,
            "processing_route": auth.processing_route,
            "redaction_declaration": auth.redaction_declaration,
            "retention_days": auth.retention_days,
        },
    )
    defaults = {
        "case_id": case_id,
        "case_version": 1,
        "tenant_id": "tenant_default",
        "phase": CasePhase.INVESTIGATION,
        "processing_authority": ProcessingAuthorityStatus.VALID,
        "authority_record": auth,
        "request_bundle_status": "ADMITTED",
        "evidence": [ev_item],
        "intent": intent or PaymentIntent(),
        "findings": findings or [],
        "investigation": CaseInvestigation(model_status="NOT_RUN"),
        "policy": PolicyEvaluationResult(),
    }
    if "audit" not in overrides:
        now_iso = datetime.now(timezone.utc).isoformat()
        initial_ev = AuditEvent(
            seq=1,
            case_id=case_id,
            event_type="EVIDENCE_ADMISSION_STARTED",
            summary="Case initialized",
            actor="PayoutProof",
            prev_hash=GENESIS_HASH,
            current_hash=compute_audit_hash(
                prev_hash=GENESIS_HASH,
                seq=1,
                event_type="EVIDENCE_ADMISSION_STARTED",
                summary="Case initialized",
                actor="PayoutProof",
                timestamp=now_iso,
                details={"tenant_id": defaults["tenant_id"]},
            ),
            timestamp=now_iso,
            details={"tenant_id": defaults["tenant_id"]},
        )
        defaults["audit"] = [initial_ev]
    defaults.update(overrides)
    state = RiskCaseState(**defaults)
    if state.policy.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF and not state.policy.evaluated_snapshot_hash:
        snap_hash = compute_snapshot_hash(state)
        state = state.model_copy(update={"policy": state.policy.model_copy(update={"evaluated_snapshot_hash": snap_hash})})
    return state
