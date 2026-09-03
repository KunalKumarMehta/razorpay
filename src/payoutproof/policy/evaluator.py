"""Deterministic Policy Gate evaluator."""

from datetime import datetime, timezone, timedelta
from typing import Any, List, Optional
from payoutproof.core.models import RiskCaseState, PolicyEvaluationResult
from payoutproof.core.enums import (
    PolicyOutcome,
    ReasonCode,
    TruthState,
    IntentStatus,
    DestinationStatus,
    FindingName,
    CasePhase,
    ProcessingAuthorityStatus,
    GrantStatus,
    AdapterDecision,
)
from payoutproof.core.crypto import compute_intent_hash, compute_snapshot_hash
from payoutproof.core.providers import ClockProvider

POLICY_VERSION = "PP-POLICY-V1"
GRANT_TTL_SECONDS = 300  # 5 minutes


class PolicyGate:
    """Pure deterministic Policy Gate evaluator.

    Evaluates a frozen RiskCaseState against explicit deterministic rules.
    Performs no network calls, no model calls, no free-text parsing, and no data repairs.
    """

    @classmethod
    def evaluate(
        cls,
        state: RiskCaseState,
        policy_version: str = POLICY_VERSION,
        evaluation_time: Optional[datetime] = None,
        clock: Optional[ClockProvider] = None,
    ) -> PolicyEvaluationResult:
        """Evaluate case snapshot and return deterministic PolicyEvaluationResult."""
        if evaluation_time is not None:
            eval_dt = evaluation_time
        elif clock is not None:
            eval_dt = clock.now()
        else:
            eval_dt = datetime.now(timezone.utc)
        now_iso = eval_dt.isoformat()
        expires_iso = (eval_dt + timedelta(seconds=GRANT_TTL_SECONDS)).isoformat()

        def result(**fields: Any) -> PolicyEvaluationResult:
            """Build a result stamped with the case's organization identity and policy version."""
            fields.setdefault("policy_version", policy_version)
            fields.setdefault("organization_id", state.organization_id)
            return PolicyEvaluationResult(**fields)

        # 1. Check for integrity failures / structural corruption (BLOCKED)
        if state.request_bundle_status == "TAMPERED":
            return result(
                outcome=PolicyOutcome.BLOCKED,
                reasons=[ReasonCode.CANONICAL_SNAPSHOT_INTEGRITY_FAILED],
                next_steps=["Reject this snapshot", "Rebuild from admitted evidence under a fresh case version"],
                evaluated_intent_hash=None,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # 2. Check for non-admitted, rejected, or missing/invalid processing authority
        is_admission_valid = (
            state.request_bundle_status == "ADMITTED"
            and state.phase != CasePhase.ADMISSION_REJECTED
            and state.processing_authority == ProcessingAuthorityStatus.VALID
            and state.authority_record is not None
            and state.authority_record.is_valid
            and len(state.evidence) > 0
        )
        if not is_admission_valid:
            return result(
                outcome=None,
                reasons=[ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE],
                next_steps=[
                    "Submit a complete Processing Authority Record and valid evidence payload",
                    "Complete evidence admission before policy evaluation",
                ],
                evaluated_intent_hash=None,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # 2. Check for investigation failure / unusable media / schema failure (HOLD)
        # A strict-schema violation is a required-signal problem: the model run
        # produced no usable structured signal, so it holds without asserting a
        # model decode failure it did not observe.
        if state.investigation.model_status == "FAILED_SCHEMA_ERROR":
            return result(
                outcome=PolicyOutcome.HOLD,
                reasons=[ReasonCode.REQUIRED_SIGNAL_UNAVAILABLE],
                next_steps=["Request a corrected instruction and rerun extraction", "Do not create a payout"],
                evaluated_intent_hash=None,
                evaluated_at=now_iso,
                expires_at=None,
            )

        if state.investigation.model_status in ("FAILED_UNUSABLE_AUDIO", "FAILED_TIMEOUT"):
            return result(
                outcome=PolicyOutcome.HOLD,
                reasons=[ReasonCode.REQUIRED_SIGNAL_UNAVAILABLE, ReasonCode.MODEL_FAILURE],
                next_steps=["Ask for a readable text instruction or clearer recording", "Do not create a payout"],
                evaluated_intent_hash=None,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # 3. Check for unconfirmed intent or material intent invalidation (HOLD)
        if state.intent.status == IntentStatus.INVALIDATED:
            return result(
                outcome=PolicyOutcome.HOLD,
                reasons=[ReasonCode.MATERIAL_INTENT_CHANGED, ReasonCode.PREVIOUS_EVALUATION_INVALIDATED],
                next_steps=["Confirm the edited Payment Intent", "Run a fresh Policy Gate evaluation"],
                evaluated_intent_hash=None,
                evaluated_at=now_iso,
                expires_at=None,
            )

        if state.intent.status != IntentStatus.CONFIRMED or not state.intent.intent_hash:
            return result(
                outcome=PolicyOutcome.HOLD,
                reasons=[ReasonCode.REQUIRED_SIGNAL_UNAVAILABLE],
                next_steps=["Payment Operator confirms every material field"],
                evaluated_intent_hash=None,
                evaluated_at=now_iso,
                expires_at=None,
            )

        recomputed_intent_hash = compute_intent_hash(state.intent)
        if recomputed_intent_hash != state.intent.intent_hash:
            return result(
                outcome=PolicyOutcome.HOLD,
                reasons=[ReasonCode.MATERIAL_INTENT_CHANGED],
                next_steps=["Confirm the edited Payment Intent", "Run a fresh Policy Gate evaluation"],
                evaluated_intent_hash=None,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # 4. Check for contradictory findings (HOLD)
        has_contradiction = any(f.truth_state == TruthState.CONTRADICTED for f in state.findings)
        if has_contradiction:
            return result(
                outcome=PolicyOutcome.HOLD,
                reasons=[ReasonCode.MATERIAL_EVIDENCE_CONTRADICTION],
                next_steps=["Resolve the conflicting destination outside PayoutProof", "Finance Control Owner reviews the conflicting destinations"],
                evaluated_intent_hash=state.intent.intent_hash,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # 5. Check for replay rejection or consumed/replayed grant (HOLD)
        is_replayed = (
            state.handoff is not None
            and state.handoff.last_adapter_decision == AdapterDecision.REPLAY_REJECTED
        )
        is_consumed_unusable_grant = (
            state.grant is not None
            and (state.grant.status == GrantStatus.CONSUMED or state.grant.used)
            and not (
                state.phase == CasePhase.COMPLETE
                and state.handoff is not None
                and state.handoff.last_adapter_decision == AdapterDecision.PENDING_ITEM_CREATED
            )
        )
        if is_replayed or is_consumed_unusable_grant:
            return result(
                outcome=PolicyOutcome.HOLD,
                reasons=[ReasonCode.REQUIRED_SIGNAL_UNAVAILABLE],
                next_steps=[
                    "Replay rejected: a previously consumed Handoff Grant cannot be reused",
                    "Do not retry handoff",
                ],
                evaluated_intent_hash=None,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # 6. Check step-up evidence: independent callback & destination approval
        has_callback = any(
            f.name in (FindingName.INDEPENDENT_CALLBACK.value, "Independent callback", "independent_callback")
            and f.truth_state == TruthState.SUPPORTED
            for f in state.findings
        )

        # An approved destination is valid only inside its own organization: the
        # approval was accepted under that organization's finance policy. Legacy
        # un-scoped approvals (organization_id None) satisfy only un-scoped cases.
        has_destination_approval = any(
            f.name in (FindingName.DESTINATION_APPROVAL.value, "Destination approval", "destination_approval")
            and f.truth_state == TruthState.SUPPORTED
            and f.organization_id == state.organization_id
            for f in state.findings
        ) or state.intent.destination_status == DestinationStatus.APPROVED_FOR_COUNTERPARTY

        if not has_callback and not has_destination_approval:
            return result(
                outcome=PolicyOutcome.STEP_UP_REQUIRED,
                reasons=[ReasonCode.UNAPPROVED_DESTINATION, ReasonCode.INDEPENDENT_VERIFICATION_MISSING],
                next_steps=[
                    "Call the counterparty using a known number and confirm the exact intent",
                    "Complete the separate policy-governed destination-approval process",
                ],
                evaluated_intent_hash=state.intent.intent_hash,
                evaluated_at=now_iso,
                expires_at=None,
            )

        if not has_callback:
            return result(
                outcome=PolicyOutcome.STEP_UP_REQUIRED,
                reasons=[ReasonCode.INDEPENDENT_VERIFICATION_MISSING],
                next_steps=["Call the counterparty using a known number and confirm the exact intent"],
                evaluated_intent_hash=state.intent.intent_hash,
                evaluated_at=now_iso,
                expires_at=None,
            )

        if not has_destination_approval:
            return result(
                outcome=PolicyOutcome.STEP_UP_REQUIRED,
                reasons=[ReasonCode.UNAPPROVED_DESTINATION],
                next_steps=["Complete the separate policy-governed destination-approval process"],
                evaluated_intent_hash=state.intent.intent_hash,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # 7. All requirements satisfied -> ELIGIBLE_FOR_HANDOFF
        return result(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            reasons=[ReasonCode.REQUIRED_EVIDENCE_SATISFIED, ReasonCode.EXACT_INTENT_FROZEN],
            next_steps=["Payment Operator may freshly initiate handoff into the existing approval rail"],
            evaluated_intent_hash=state.intent.intent_hash,
            evaluated_snapshot_hash=compute_snapshot_hash(state),
            evaluated_at=now_iso,
            expires_at=expires_iso,
        )
