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


class PolicyConfigStatus(str, Enum):
    """Lifecycle status of an immutable policy configuration version.

    Mirrors the grant lattice: DRAFT may only become ACTIVE, ACTIVE may only
    become RETIRED, and RETIRED is terminal. Once ACTIVE, the config's
    thresholds and stopping rules can never be edited — a change mints a new
    version row (insert-only storage).
    """
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


class DestinationRecordStatus(str, Enum):
    """Durable approval-lifecycle status of an Approved Destination record.

    CREATED -> ACTIVE -> RETIRED, irreversible, with one documented deviation
    from the grant lattice: CREATED -> RETIRED is allowed so an operator can
    cancel a scheduled approval before its valid_from goes live. RETIRED is
    terminal; re-approving a retired destination means creating a new record.

    This is the operator-driven approval lifecycle, NOT effectiveness: an
    ACTIVE record with a future valid_from or a past valid_to is not effective
    at a given time. Nothing auto-mutates these rows on window expiry.
    """
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


class DestinationAuditEventType(str, Enum):
    """Event types for the destination-keyed audit chain.

    A tamper detection is an event, not a rejection: the row is quarantined
    (RETIRED-like refusal to serve) rather than silently dropped, preserving
    the append-only history for investigation.
    """
    DESTINATION_CREATED = "DESTINATION_CREATED"
    DESTINATION_ACTIVATED = "DESTINATION_ACTIVATED"
    DESTINATION_RETIRED = "DESTINATION_RETIRED"
    DESTINATION_CONFIG_TAMPER_DETECTED = "DESTINATION_CONFIG_TAMPER_DETECTED"


class PolicyConfigAuditEventType(str, Enum):
    """Event types for the organization-keyed policy configuration audit chain.

    Covers both policy-version lifecycle events and the organization-level
    mirror of destination-approval lifecycle events (the destination-keyed
    destination_audit_events chain remains the per-destination authority;
    these org-keyed copies give an organization one contiguous ledger of
    everything decided under its finance policy).
    """
    POLICY_VERSION_CREATED = "POLICY_VERSION_CREATED"
    POLICY_VERSION_ACTIVATED = "POLICY_VERSION_ACTIVATED"
    POLICY_VERSION_RETIRED = "POLICY_VERSION_RETIRED"
    DESTINATION_APPROVAL_CREATED = "DESTINATION_APPROVAL_CREATED"
    DESTINATION_APPROVAL_ACTIVATED = "DESTINATION_APPROVAL_ACTIVATED"
    DESTINATION_APPROVAL_RETIRED = "DESTINATION_APPROVAL_RETIRED"
    POLICY_CONFIG_TAMPER_DETECTED = "POLICY_CONFIG_TAMPER_DETECTED"
