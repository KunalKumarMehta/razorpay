"""Independent declarative Policy Oracle for ground truth computation."""

from typing import Dict, Any, List, Tuple
from payoutproof.core.enums import PolicyOutcome, ReasonCode
from payoutproof.simulator.generator import EvaluationCase


class PolicyOracle:
    """Structurally independent declarative policy oracle.

    Computes ground truth outcome and required protective intervention
    directly from simulator case definitions without invoking runtime state machines.
    """

    @staticmethod
    def evaluate_expected(case: EvaluationCase) -> Tuple[PolicyOutcome, List[str]]:
        """Compute expected gold outcome and expected reason codes."""
        if case.is_tampered or case.is_unauthorized:
            return PolicyOutcome.BLOCKED, ["CANONICAL_SNAPSHOT_INTEGRITY_FAILED"]

        if case.is_unusable_audio:
            return PolicyOutcome.HOLD, ["REQUIRED_SIGNAL_UNAVAILABLE", "MODEL_FAILURE"]

        if case.has_contradiction:
            return PolicyOutcome.HOLD, ["MATERIAL_EVIDENCE_CONTRADICTION"]

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
