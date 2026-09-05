"""Deterministic Policy Gate evaluator."""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from payoutproof.core.models import (
    DestinationApprovalSnapshot,
    RiskCaseState,
    PolicyEvaluationResult,
)
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

    Issue #9 provenance (both parameters optional, additive, and defaulting
    to None so every pre-existing caller keeps byte-identical outcomes):

    - ``policy_config`` — the organization's resolved immutable policy
      configuration version. When supplied, its version label, grant TTL, and
      step-up rules drive the evaluation and its identity is recorded on the
      result; when absent, the in-code defaults below apply exactly as
      before and the result carries no config provenance.
    - ``destination_snapshot`` — the frozen hydrated Approved Destination
      view captured before evaluation. When the resolved config requires an
      approved destination, the snapshot must exist and be effective at the
      evaluation instant, or the evaluation fails closed to
      STEP_UP_REQUIRED with reason DESTINATION_NOT_APPROVED.
    """

    @classmethod
    def evaluate(
        cls,
        state: RiskCaseState,
        policy_version: str = POLICY_VERSION,
        evaluation_time: Optional[datetime] = None,
        clock: Optional[ClockProvider] = None,
        policy_config: Optional[Any] = None,
        destination_snapshot: Optional[DestinationApprovalSnapshot] = None,
    ) -> PolicyEvaluationResult:
        """Evaluate case snapshot and return deterministic PolicyEvaluationResult.

        The optional Issue #9 parameters never change a legacy call's result:
        a caller passing neither gets exactly the pre-existing in-code rules,
        thresholds, reasons, and next steps. A caller supplying a
        ``policy_config`` gets its grant TTL and step-up rules instead, with
        the config's identity and hash (and the destination snapshot, when
        one was resolved) recorded on the result for durable provenance.
        """
        # A supplied PolicyConfig carries its own version identity; an absent
        # one keeps the caller-supplied (default PP-POLICY-V1) label so legacy
        # grants and persisted state_json stay byte-identical.
        resolved_version = getattr(policy_config, "version_id", None) or policy_version
        resolved_config = policy_config
        if resolved_config is None:
            from payoutproof.policy.config import default_active_config

            # The implicit default mirrors today's in-code rules exactly
            # (same TTL, same require-callback/require-destination posture),
            # so the rule application below has one code path and legacy
            # callers are provably unaffected.
            resolved_config = default_active_config(state.organization_id)

        if evaluation_time is not None:
            eval_dt = evaluation_time
        elif clock is not None:
            eval_dt = clock.now()
        else:
            eval_dt = datetime.now(timezone.utc)
        now_iso = eval_dt.isoformat()

        ttl_seconds = getattr(resolved_config, "grant_ttl_seconds", None)
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds < 1:
            ttl_seconds = GRANT_TTL_SECONDS
        expires_iso = (eval_dt + timedelta(seconds=ttl_seconds)).isoformat()

        step_up_rules = getattr(resolved_config, "step_up_rules", None)
        require_callback_rule = bool(getattr(step_up_rules, "require_independent_callback", True))
        require_destination_rule = bool(getattr(step_up_rules, "require_approved_destination", True))

        # Issue #9 provenance rides every result this evaluation produces.
        # It is None when the caller supplied no config (legacy call), so
        # persisted legacy results remain exactly as they were.
        config_id = getattr(policy_config, "config_id", None) if policy_config is not None else None
        config_hash = getattr(policy_config, "content_hash", None) if policy_config is not None else None
        snapshot_dict: Optional[Dict[str, Any]] = (
            destination_snapshot.model_dump() if destination_snapshot is not None else None
        )

        def result(**fields: Any) -> PolicyEvaluationResult:
            """Build a result stamped with the case's organization identity and policy version."""
            fields.setdefault("policy_version", resolved_version)
            fields.setdefault("organization_id", state.organization_id)
            fields.setdefault("policy_config_id", config_id)
            fields.setdefault("policy_config_hash", config_hash)
            fields.setdefault("destination_snapshot", snapshot_dict)
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

        # 6.5 Issue #9 effective-dated destination approval. Only a caller
        # that supplied a policy_config opts into the snapshot authority — a
        # legacy call (policy_config=None) keeps the findings-based rules
        # below byte-identical, whatever the implicit default would say.
        # When the resolved config requires an approved destination, the
        # frozen hydrated snapshot is the authority, not the case's own
        # findings: it must exist and be effective at THIS evaluation instant
        # (half-open [valid_from, valid_to), computed from parsed datetimes),
        # or the evaluation fails closed to STEP_UP_REQUIRED — an expired,
        # scheduled, retired, or missing approval never satisfies policy.
        snapshot_effective = (
            destination_snapshot is not None and destination_snapshot.is_effective_at(eval_dt)
        )
        if policy_config is not None and require_destination_rule and not snapshot_effective:
            return result(
                outcome=PolicyOutcome.STEP_UP_REQUIRED,
                reasons=[ReasonCode.UNAPPROVED_DESTINATION],
                next_steps=[
                    "Complete the separate policy-governed destination-approval process: "
                    "activate a record whose effective window covers this evaluation",
                ],
                evaluated_intent_hash=state.intent.intent_hash,
                evaluated_at=now_iso,
                expires_at=None,
            )

        # An effective registry snapshot is destination approval by
        # definition — it overrides the case's own findings (which record
        # observations, not registry state).
        if snapshot_effective:
            has_destination_approval = True

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

        if require_callback_rule and not has_callback:
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
