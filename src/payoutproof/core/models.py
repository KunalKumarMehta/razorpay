"""Pydantic schemas and typed domain models for PayoutProof."""

from __future__ import annotations
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict

from payoutproof.core.enums import (
    TruthState,
    PolicyOutcome,
    CasePhase,
    IntentStatus,
    DestinationStatus,
    GrantStatus,
    HandoffStatus,
    ProcessingAuthorityStatus,
    AdapterDecision,
    ReasonCode,
    AuditTrustState,
    DestinationRecordStatus,
)


class ProcessingAuthorityRecord(BaseModel):
    """Case-scoped declaration of authority and consent basis for submitted evidence."""
    model_config = ConfigDict(frozen=True)

    data_class: str = Field(..., description="Classification of evidence data (e.g., 'VOICE_NOTE', 'MESSAGE')")
    source: str = Field(..., description="Originating channel or source")
    subject_category: str = Field(..., description="Category of the data subject (e.g., 'VENDOR', 'INTERNAL_OPERATOR')")
    submitter: str = Field(..., description="Identity/role of submitter")
    purpose: str = Field(..., description="Specific permitted purpose for processing")
    asserted_authority_ref: str = Field(..., description="Reference to policy or explicit consent record")
    permitted_uses: List[str] = Field(..., description="Allowlisted processing uses")
    processing_route: str = Field(..., description="Declared processing route (e.g. 'LOCAL_ONLY')")
    redaction_declaration: str = Field(..., description="Declaration of redaction and sanitization applied")
    retention_days: int = Field(..., gt=0, le=365, description="Declared retention lifecycle in days (positive bounded)")
    legal_hold: bool = Field(..., description="Whether data is subject to legal hold")
    restrictions: List[str] = Field(..., description="Any restrictions on processing")
    is_valid: bool = Field(..., description="Whether authority criteria are met")


class PendingApprovalItem:
    """A pending payout review item in the downstream maker-checker approval rail."""
    def __init__(
        self,
        item_id: str,
        case_id: str,
        counterparty: str,
        destination: str,
        amount: str,
        currency: str,
        purpose: str,
        grant_id: str,
        idempotency_key: str,
        created_at: str,
        status: str = "PENDING_FINANCE_APPROVAL",
        organization_id: Optional[str] = None,
    ):
        self.item_id = item_id
        self.case_id = case_id
        self.counterparty = counterparty
        self.destination = destination
        self.amount = amount
        self.currency = currency
        self.purpose = purpose
        self.grant_id = grant_id
        self.idempotency_key = idempotency_key
        self.created_at = created_at
        self.status = status
        self.organization_id = organization_id



class PaymentIntent(BaseModel):
    """Authoritative Payment Intent binding counterparty, destination, amount, and purpose."""
    model_config = ConfigDict(frozen=True)

    counterparty: Optional[str] = None
    destination: Optional[str] = None
    destination_status: DestinationStatus = DestinationStatus.UNAPPROVED
    amount: Optional[str] = None  # Canonical integer amount in INR subunits (e.g. "425000" for ₹4,25,000)
    currency: Optional[str] = "INR"
    purpose: Optional[str] = None
    instruction_reference: Optional[str] = None
    provenance: List[str] = Field(default_factory=list)
    status: IntentStatus = IntentStatus.NOT_EXTRACTED
    intent_hash: Optional[str] = None

    def canonical_string(self) -> str:
        """Deterministic canonical representation for hashing."""
        return "|".join([
            str(self.counterparty or ""),
            str(self.destination or ""),
            str(self.amount or ""),
            str(self.currency or ""),
            str(self.purpose or ""),
            str(self.instruction_reference or ""),
        ])


class EvidenceItem(BaseModel):
    """Admitted evidence record."""
    model_config = ConfigDict(frozen=True)

    id: str
    item_type: str
    title: str
    content_hash: str
    finding: str
    truth_state: TruthState
    admitted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Provenance-linked finding derived from investigation."""
    model_config = ConfigDict(frozen=True)

    name: str
    truth_state: TruthState
    detail: str
    evidence_ref: Optional[str] = None
    organization_id: Optional[str] = None


class DestinationApprovalSnapshot(BaseModel):
    """Frozen hydrated view of one Approved Destination record bound into a case.

    Captured at hydration time from the destination registry — before Policy
    Gate evaluation — and never mutated afterwards. It stores the *raw* window
    fields (status, valid_from, valid_to), never a precomputed "is approved"
    boolean: effectiveness is computed by the Policy Gate against its own
    evaluation_time, so replaying the same snapshot at the same instant yields
    the same outcome regardless of when hydration happened.
    """
    model_config = ConfigDict(frozen=True)

    destination_id: str
    organization_id: str
    tenant_id: str
    counterparty: str
    destination: str
    destination_type: str
    status: DestinationRecordStatus = DestinationRecordStatus.CREATED
    valid_from: str
    valid_to: Optional[str] = None
    policy_config_id: str
    policy_config_hash: str
    record_hash: str
    snapshot_captured_at: str

    def is_effective_at(self, at: datetime) -> bool:
        """Half-open [valid_from, valid_to) effectiveness at an aware instant.

        Effectiveness = status ACTIVE AND valid_from <= at AND (valid_to IS
        NULL OR at < valid_to). Timestamps are parsed as datetimes, never
        string-compared; a naive `at` is treated as UTC. A naive or malformed
        stored window is fail-closed (not effective), never an exception.
        """
        if self.status != DestinationRecordStatus.ACTIVE:
            return False
        try:
            if at.tzinfo is None:
                at = at.replace(tzinfo=timezone.utc)
            start = datetime.fromisoformat(self.valid_from)
            if start.tzinfo is None:
                return False
            if at < start:
                return False
            if self.valid_to is not None:
                end = datetime.fromisoformat(self.valid_to)
                if end.tzinfo is None:
                    return False
                if at >= end:
                    return False
            return True
        except (ValueError, TypeError):
            return False


class ApprovedDestinationRecord(BaseModel):
    """Durable effective-dated Approved Destination record (Issue #9).

    The registry row model: one counterparty/destination approval accepted
    under the organization's finance policy, with an explicit approval window
    and the immutable policy configuration it was approved under. `status` is
    the operator-driven lifecycle; effectiveness at a time is computed by
    ``is_effective_at`` (an ACTIVE-but-expired window is simply non-effective
    — no scheduler mutates rows on window expiry, preserving the audit chain).
    """
    model_config = ConfigDict(frozen=True)

    destination_id: str
    tenant_id: str
    organization_id: str
    counterparty: str
    destination: str
    destination_type: str
    status: DestinationRecordStatus = DestinationRecordStatus.CREATED
    valid_from: str
    valid_to: Optional[str] = None
    policy_config_id: str
    policy_config_hash: str
    record_hash: str
    created_at: str
    updated_at: str
    retired_at: Optional[str] = None

    def is_effective_at(self, at: datetime) -> bool:
        """Half-open [valid_from, valid_to) effectiveness at an aware instant.

        Same semantics as ``DestinationApprovalSnapshot.is_effective_at``:
        timestamps are parsed (never string-compared), naive stored values are
        fail-closed, and a naive `at` is treated as UTC.
        """
        if self.status != DestinationRecordStatus.ACTIVE:
            return False
        try:
            if at.tzinfo is None:
                at = at.replace(tzinfo=timezone.utc)
            start = datetime.fromisoformat(self.valid_from)
            if start.tzinfo is None:
                return False
            if at < start:
                return False
            if self.valid_to is not None:
                end = datetime.fromisoformat(self.valid_to)
                if end.tzinfo is None:
                    return False
                if at >= end:
                    return False
            return True
        except (ValueError, TypeError):
            return False


class PolicyEvaluationResult(BaseModel):
    """Deterministic result produced by the Policy Gate."""
    model_config = ConfigDict(frozen=True)

    outcome: Optional[PolicyOutcome] = None
    reasons: List[ReasonCode] = Field(default_factory=list)
    next_steps: List[str] = Field(default_factory=list)
    evaluated_intent_hash: Optional[str] = None
    evaluated_snapshot_hash: Optional[str] = None
    policy_version: str = "PP-POLICY-V1"
    organization_id: Optional[str] = None
    evaluated_at: Optional[str] = None
    expires_at: Optional[str] = None
    # Issue #9 provenance (additive, optional): the exact immutable policy
    # configuration and effective destination approval state used. Absent on
    # legacy evaluations, which keeps every persisted state_json loadable.
    policy_config_id: Optional[str] = None
    policy_config_hash: Optional[str] = None
    destination_snapshot: Optional[Dict[str, Any]] = None


class HandoffGrant(BaseModel):
    """Single-use, expiring HMAC-signed authorization for handoff."""
    model_config = ConfigDict(frozen=True)

    grant_id: str
    tenant_id: str
    organization_id: Optional[str] = None
    case_id: str
    bound_intent_hash: str
    bound_snapshot_hash: str
    policy_version: str
    outcome: PolicyOutcome
    nonce: str
    issued_at: str
    expires_at: str
    signature: str
    status: GrantStatus = GrantStatus.ACTIVE
    used: bool = False
    key_id: Optional[str] = None


class HandoffRecord(BaseModel):
    """Operational handoff state into the downstream rail."""
    model_config = ConfigDict(frozen=True)

    status: HandoffStatus = HandoffStatus.NOT_STARTED
    idempotency_key: Optional[str] = None
    attempts: int = 0
    last_adapter_decision: Optional[AdapterDecision] = None
    pending_item_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class AuditEvent(BaseModel):
    """Tamper-evident append-only audit event in a SHA-256 hash chain."""
    model_config = ConfigDict(frozen=True)

    seq: int
    case_id: Optional[str] = None
    event_type: str
    summary: str
    actor: str
    prev_hash: str
    current_hash: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)


class CaseInvestigation(BaseModel):
    """Investigation status and diagnostics."""
    model_config = ConfigDict(frozen=True)

    model_status: str = "NOT_RUN"
    attempt: int = 0
    asr_confidence: Optional[float] = None
    extraction_latency_ms: Optional[float] = None
    language_stratum: Optional[str] = None


class RiskCaseState(BaseModel):
    """Full authoritative state of a Risk Case."""
    model_config = ConfigDict(frozen=True)

    case_id: Optional[str] = None
    case_version: int = 0
    tenant_id: str = "tenant_default"
    organization_id: Optional[str] = None
    phase: CasePhase = CasePhase.EVIDENCE_ADMISSION
    processing_authority: ProcessingAuthorityStatus = ProcessingAuthorityStatus.NOT_CHECKED
    authority_record: Optional[ProcessingAuthorityRecord] = None
    request_bundle_status: str = "NOT_ADMITTED"
    intent: PaymentIntent = Field(default_factory=PaymentIntent)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    investigation: CaseInvestigation = Field(default_factory=CaseInvestigation)
    policy: PolicyEvaluationResult = Field(default_factory=PolicyEvaluationResult)
    grant: Optional[HandoffGrant] = None
    handoff: HandoffRecord = Field(default_factory=HandoffRecord)
    # Issue #9: frozen hydrated destination approval snapshot. Optional with a
    # None default — legacy state_json without this key must stay loadable and
    # re-savable, so the field can never be required. Excluded from
    # compute_snapshot_hash (an explicit canonical projection) so in-flight
    # grant bindings stay byte-identical; provenance is additive only.
    destination_approval: Optional[DestinationApprovalSnapshot] = None
    last_change: str = "Case initialized; awaiting processing authority check."
    audit: List[AuditEvent] = Field(default_factory=list)

    @property
    def processing_authority_record(self) -> Optional[ProcessingAuthorityRecord]:
        """Accessor alias for authority_record."""
        return self.authority_record


class CaseAuditCheckpoint(BaseModel):
    """Authenticated authoritative audit checkpoint for a case."""
    model_config = ConfigDict(frozen=True)

    case_id: str
    event_count: int
    tip_hash: str
    trust_state: AuditTrustState = AuditTrustState.TRUSTED
    checkpoint_mac: str
    updated_at: str
    key_id: Optional[str] = None
