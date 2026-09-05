"""Independent declarative Policy Oracle for ground truth computation."""

from typing import Dict, Any, List, Optional, Tuple
from payoutproof.core.enums import PolicyOutcome, ReasonCode
from payoutproof.simulator.generator import EvaluationCase


class PolicyOracle:
    """Structurally independent declarative policy oracle.

    Computes ground truth outcome and required protective intervention
    directly from simulator case definitions without invoking runtime state machines.
    """

    @staticmethod
    def evaluate_expected(case: EvaluationCase) -> Tuple[Optional[PolicyOutcome], List[str]]:
        """Compute expected gold outcome and expected reason codes.

        Decides every scenario from its declared truth flags only; it never
        inspects product output. Material-intent inconsistencies (CAT1) hold
        because the intent itself is unreliable, and schema failures (CAT6)
        hold with the required signal unavailable — distinct from unusable
        audio, which is additionally a model failure. An admission-rejected
        case never reaches policy evaluation, so it has no expected policy
        outcome either: None, matching the product's Admission Rejection —
        never a false BLOCKED.
        """
        if case.is_unauthorized:
            return None, ["ADMISSION_AUTHORITY_INCOMPLETE"]

        if case.is_tampered:
            return PolicyOutcome.BLOCKED, ["CANONICAL_SNAPSHOT_INTEGRITY_FAILED"]

        if case.has_material_intent_error:
            return PolicyOutcome.HOLD, ["MATERIAL_INTENT_CHANGED"]

        if case.is_schema_failure:
            return PolicyOutcome.HOLD, ["REQUIRED_SIGNAL_UNAVAILABLE"]

        if case.is_unusable_audio:
            return PolicyOutcome.HOLD, ["REQUIRED_SIGNAL_UNAVAILABLE", "MODEL_FAILURE"]

        if case.has_contradiction:
            return PolicyOutcome.HOLD, ["MATERIAL_EVIDENCE_CONTRADICTION"]

        if case.mutate_amount_after_grant:
            return PolicyOutcome.HOLD, ["PREVIOUS_EVALUATION_INVALIDATED"]

        if case.replay_grant_after_storage_restart:
            return PolicyOutcome.HOLD, ["REQUIRED_SIGNAL_UNAVAILABLE"]

        if not case.has_callback and not case.has_destination_approval:
            return PolicyOutcome.STEP_UP_REQUIRED, ["UNAPPROVED_DESTINATION", "INDEPENDENT_VERIFICATION_MISSING"]

        if not case.has_callback:
            return PolicyOutcome.STEP_UP_REQUIRED, ["INDEPENDENT_VERIFICATION_MISSING"]

        if not case.has_destination_approval:
            return PolicyOutcome.STEP_UP_REQUIRED, ["UNAPPROVED_DESTINATION"]

        return PolicyOutcome.ELIGIBLE_FOR_HANDOFF, ["REQUIRED_EVIDENCE_SATISFIED", "EXACT_INTENT_FROZEN"]

    @staticmethod
    def is_protective_intervention_required(gold_outcome: PolicyOutcome) -> bool:
        """Protective Intervention Required means gold HOLD or STEP_UP_REQUIRED."""
        return gold_outcome in (PolicyOutcome.HOLD, PolicyOutcome.STEP_UP_REQUIRED)

    @staticmethod
    def expected_intent_binding(case: EvaluationCase) -> bool:
        """Compute whether intent binding is independently expected to succeed."""
        if hasattr(case, "expected_intent_binding_correct"):
            return bool(case.expected_intent_binding_correct)
        return not (
            case.is_unauthorized
            or case.is_unusable_audio
            or case.has_material_intent_error
            or case.is_schema_failure
            or case.mutate_amount_after_grant
        )
