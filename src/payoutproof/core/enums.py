"""Core enumeration types for PayoutProof."""

from enum import Enum


class TruthState(str, Enum):
    """Five-valued truth state for evidence findings."""
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    NOT_OBSERVED = "not_observed"
    INSUFFICIENT_QUALITY = "insufficient_quality"
    NOT_EVALUATED = "not_evaluated"


class PolicyOutcome(str, Enum):
    """Deterministic Policy Gate outcomes."""
    BLOCKED = "BLOCKED"
    HOLD = "HOLD"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    ELIGIBLE_FOR_HANDOFF = "ELIGIBLE_FOR_HANDOFF"


class CasePhase(str, Enum):
    """Authoritative lifecycle phases of a Risk Case."""
    EVIDENCE_ADMISSION = "EVIDENCE_ADMISSION"
    ADMISSION_REJECTED = "ADMISSION_REJECTED"
    INVESTIGATION = "INVESTIGATION"
    OPERATOR_INTERVENTION = "OPERATOR_INTERVENTION"
    READY_FOR_HUMAN_HANDOFF = "READY_FOR_HUMAN_HANDOFF"
    HANDOFF_IN_PROGRESS = "HANDOFF_IN_PROGRESS"
    COMPLETE = "COMPLETE"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


class IntentStatus(str, Enum):
    """Payment Intent binding status."""
    NOT_EXTRACTED = "NOT_EXTRACTED"
    EXTRACTED = "EXTRACTED"
    CONFIRMED = "CONFIRMED"
    INVALIDATED = "INVALIDATED"


class DestinationStatus(str, Enum):
    """Status of payout destination account."""
    UNAPPROVED = "UNAPPROVED"
    APPROVED_FOR_COUNTERPARTY = "APPROVED_FOR_COUNTERPARTY"
    SUSPICIOUS_OR_CHANGED = "SUSPICIOUS_OR_CHANGED"


class GrantStatus(str, Enum):
    """Handoff Grant lifecycle status."""
    NOT_ISSUED = "NOT_ISSUED"
    ACTIVE = "ACTIVE"
    CONSUMED = "CONSUMED"
    INVALIDATED = "INVALIDATED"
    EXPIRED = "EXPIRED"
    SUSPENDED_FOR_RECONCILIATION = "SUSPENDED_FOR_RECONCILIATION"


class HandoffStatus(str, Enum):
    """Handoff operational rail status."""
    NOT_STARTED = "NOT_STARTED"
    PENDING = "PENDING"
    PENDING_IN_APPROVAL_RAIL = "PENDING_IN_APPROVAL_RAIL"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    FAILED = "FAILED"


class ProcessingAuthorityStatus(str, Enum):
    """Status of submitted Processing Authority Record."""
    NOT_CHECKED = "NOT_CHECKED"
    VALID = "VALID"
    INCOMPLETE = "INCOMPLETE"
    REJECTED = "REJECTED"


class AdapterDecision(str, Enum):
    """Deterministic decisions returned by the Action Adapter."""
    FRESH_HUMAN_GESTURE_ACCEPTED = "FRESH_HUMAN_GESTURE_ACCEPTED"
    PENDING_ITEM_CREATED = "PENDING_ITEM_CREATED"
    REPLAY_REJECTED = "REPLAY_REJECTED"
    DOWNSTREAM_STATUS_UNKNOWN_NO_RETRY = "DOWNSTREAM_STATUS_UNKNOWN_NO_RETRY"
    RECOVERY_INTEGRITY_FAILURE_NO_RETRY = "RECOVERY_INTEGRITY_FAILURE_NO_RETRY"
    GRANT_INVALID_OR_EXPIRED = "GRANT_INVALID_OR_EXPIRED"
    INTENT_MISMATCH = "INTENT_MISMATCH"


class ReasonCode(str, Enum):
    """Frozen canonical reason codes."""
    REQUIRED_EVIDENCE_SATISFIED = "REQUIRED_EVIDENCE_SATISFIED"
    EXACT_INTENT_FROZEN = "EXACT_INTENT_FROZEN"
    UNAPPROVED_DESTINATION = "UNAPPROVED_DESTINATION"
    INDEPENDENT_VERIFICATION_MISSING = "INDEPENDENT_VERIFICATION_MISSING"
    MATERIAL_EVIDENCE_CONTRADICTION = "MATERIAL_EVIDENCE_CONTRADICTION"
    CANONICAL_SNAPSHOT_INTEGRITY_FAILED = "CANONICAL_SNAPSHOT_INTEGRITY_FAILED"
    MATERIAL_INTENT_CHANGED = "MATERIAL_INTENT_CHANGED"
    PREVIOUS_EVALUATION_INVALIDATED = "PREVIOUS_EVALUATION_INVALIDATED"
    REQUIRED_SIGNAL_UNAVAILABLE = "REQUIRED_SIGNAL_UNAVAILABLE"
    MODEL_FAILURE = "MODEL_FAILURE"
    ADMISSION_AUTHORITY_INCOMPLETE = "ADMISSION_AUTHORITY_INCOMPLETE"
    MALFORMED_INPUT = "MALFORMED_INPUT"
    PROHIBITED_INPUT = "PROHIBITED_INPUT"
    UNAUTHORIZED_ACTOR = "UNAUTHORIZED_ACTOR"


class FindingName(str, Enum):
    """Canonical domain names for investigation and step-up findings."""
    INDEPENDENT_CALLBACK = "Independent callback"
    DESTINATION_APPROVAL = "Destination approval"
    DESTINATION_CONSISTENCY = "Destination consistency"
    DESTINATION_RELATIONSHIP = "Destination relationship"
    INSTRUCTION_CONSISTENCY = "Instruction consistency"
    AASIST_SYNTHETIC_SCORE = "AASIST synthetic speech check"


class DemoFakeAdapterMode(str, Enum):
    """Documented local-demo-only fake adapter simulation modes."""
    SIMULATE_AMBIGUITY = "SIMULATE_AMBIGUITY"


class AuditTrustState(str, Enum):
    """Trust states for case audit checkpoints."""
    TRUSTED = "TRUSTED"
    LEGACY_UNTRUSTED = "LEGACY_UNTRUSTED"


class MembershipRole(str, Enum):
    """Organization-scoped member roles.

    No role confers any Money Action authority: administration is strictly
    membership-scoped. Roles mirror CONTEXT.md where the glossary anchors
    them (Payment Operator, Finance Control Owner); Tenant Administrator and
    Viewer extend the vocabulary for Issue #8 and are flagged for domain
    ratification via /domain-modeling rather than coined silently.
    """
    TENANT_ADMINISTRATOR = "TENANT_ADMINISTRATOR"
    PAYMENT_OPERATOR = "PAYMENT_OPERATOR"
    FINANCE_CONTROL_OWNER = "FINANCE_CONTROL_OWNER"
    VIEWER = "VIEWER"


class MembershipStatus(str, Enum):
    """Lifecycle status of an organization member row."""
    ACTIVE = "ACTIVE"
    REMOVED = "REMOVED"


class InvitationStatus(str, Enum):
    """Lifecycle status of a single-use membership invitation."""
    PENDING = "PENDING"
    ACCEPTED = "ACCEPTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class MembershipAuditEventType(str, Enum):
    """Event types for the organization-keyed membership audit chain."""
    MEMBER_INVITED = "MEMBER_INVITED"
    INVITATION_REVOKED = "INVITATION_REVOKED"
    MEMBER_ADDED = "MEMBER_ADDED"
    MEMBER_ROLE_CHANGED = "MEMBER_ROLE_CHANGED"
    MEMBER_REMOVED = "MEMBER_REMOVED"
