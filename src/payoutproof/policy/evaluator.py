"""Deterministic Policy Gate evaluator."""

from datetime import datetime, timezone, timedelta
from typing import List, Optional
from payoutproof.core.models import RiskCaseState, PolicyEvaluationResult
from payoutproof.core.enums import (
    PolicyOutcome,
    ReasonCode,
    TruthState,
    IntentStatus,
    DestinationStatus,
    FindingName,
)

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
    ) -> PolicyEvaluationResult:
        """Evaluate case snapshot and return deterministic PolicyEvaluationResult."""
        eval_dt = evaluation_time or datetime.now(timezone.utc)
        now_iso = eval_dt.isoformat()
        expires_iso = (eval_dt + timedelta(seconds=GRANT_TTL_SECONDS)).isoformat()

        # 1. Check for integrity failures / structural corruption (BLOCKED)
        if state.request_bundle_status == "TAMPERED":
            return PolicyEvaluationResult(
                outcome=PolicyOutcome.BLOCKED,
                reasons=[ReasonCode.CANONICAL_SNAPSHOT_INTEGRITY_FAILED],
                next_steps=["Reject this snapshot", "Rebuild from admitted evidence under a fresh case version"],
                evaluated_intent_hash=None,
                policy_version=policy_version,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # 2. Check for investigation failure / unusable media / schema failure (HOLD)
        if state.investigation.model_status in ("FAILED_UNUSABLE_AUDIO", "FAILED_SCHEMA_ERROR", "FAILED_TIMEOUT"):
            return PolicyEvaluationResult(
                outcome=PolicyOutcome.HOLD,
                reasons=[ReasonCode.REQUIRED_SIGNAL_UNAVAILABLE, ReasonCode.MODEL_FAILURE],
                next_steps=["Ask for a readable text instruction or clearer recording", "Do not create a payout"],
                evaluated_intent_hash=None,
                policy_version=policy_version,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # 3. Check for unconfirmed intent or material intent invalidation (HOLD)
        if state.intent.status == IntentStatus.INVALIDATED:
            return PolicyEvaluationResult(
                outcome=PolicyOutcome.HOLD,
                reasons=[ReasonCode.MATERIAL_INTENT_CHANGED, ReasonCode.PREVIOUS_EVALUATION_INVALIDATED],
                next_steps=["Confirm the edited Payment Intent", "Run a fresh Policy Gate evaluation"],
                evaluated_intent_hash=None,
                policy_version=policy_version,
                evaluated_at=now_iso,
                expires_at=None,
            )

        if state.intent.status != IntentStatus.CONFIRMED or not state.intent.intent_hash:
            return PolicyEvaluationResult(
                outcome=PolicyOutcome.HOLD,
                reasons=[ReasonCode.REQUIRED_SIGNAL_UNAVAILABLE],
                next_steps=["Payment Operator confirms every material field"],
                evaluated_intent_hash=None,
                policy_version=policy_version,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # 4. Check for contradictory findings (HOLD)
        has_contradiction = any(f.truth_state == TruthState.CONTRADICTED for f in state.findings)
        if has_contradiction:
            return PolicyEvaluationResult(
                outcome=PolicyOutcome.HOLD,
                reasons=[ReasonCode.MATERIAL_EVIDENCE_CONTRADICTION],
                next_steps=["Resolve the conflicting destination outside PayoutProof", "Finance Control Owner reviews the conflicting destinations"],
                evaluated_intent_hash=state.intent.intent_hash,
                policy_version=policy_version,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # 5. Check step-up evidence: independent callback & destination approval
        has_callback = any(
            f.name in (FindingName.INDEPENDENT_CALLBACK.value, "Independent callback", "independent_callback")
            and f.truth_state == TruthState.SUPPORTED
            for f in state.findings
        )
        has_destination_approval = any(
            f.name in (FindingName.DESTINATION_APPROVAL.value, "Destination approval", "destination_approval")
            and f.truth_state == TruthState.SUPPORTED
            for f in state.findings
        ) or state.intent.destination_status == DestinationStatus.APPROVED_FOR_COUNTERPARTY

        if not has_callback and not has_destination_approval:
            return PolicyEvaluationResult(
                outcome=PolicyOutcome.STEP_UP_REQUIRED,
                reasons=[ReasonCode.UNAPPROVED_DESTINATION, ReasonCode.INDEPENDENT_VERIFICATION_MISSING],
                next_steps=[
                    "Call the counterparty using a known number and confirm the exact intent",
                    "Complete the separate policy-governed destination-approval process",
                ],
                evaluated_intent_hash=state.intent.intent_hash,
                policy_version=policy_version,
                evaluated_at=now_iso,
                expires_at=None,
            )

        if not has_callback:
            return PolicyEvaluationResult(
                outcome=PolicyOutcome.STEP_UP_REQUIRED,
                reasons=[ReasonCode.INDEPENDENT_VERIFICATION_MISSING],
                next_steps=["Call the counterparty using a known number and confirm the exact intent"],
                evaluated_intent_hash=state.intent.intent_hash,
                policy_version=policy_version,
                evaluated_at=now_iso,
                expires_at=None,
            )

        if not has_destination_approval:
            return PolicyEvaluationResult(
                outcome=PolicyOutcome.STEP_UP_REQUIRED,
                reasons=[ReasonCode.UNAPPROVED_DESTINATION],
                next_steps=["Complete the separate policy-governed destination-approval process"],
                evaluated_intent_hash=state.intent.intent_hash,
                policy_version=policy_version,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # 6. All requirements satisfied -> ELIGIBLE_FOR_HANDOFF
        return PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            reasons=[ReasonCode.REQUIRED_EVIDENCE_SATISFIED, ReasonCode.EXACT_INTENT_FROZEN],
            next_steps=["Payment Operator may freshly initiate handoff into the existing approval rail"],
            evaluated_intent_hash=state.intent.intent_hash,
            policy_version=policy_version,
            evaluated_at=now_iso,
            expires_at=expires_iso,
        )
