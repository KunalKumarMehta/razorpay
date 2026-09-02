"""Execution runner for evaluation cases."""

from payoutproof.core.models import RiskCaseState, PaymentIntent, Finding, CaseInvestigation
from payoutproof.core.enums import PolicyOutcome, TruthState, IntentStatus, DestinationStatus
from payoutproof.simulator.generator import EvaluationCase
from payoutproof.oracle.oracle import PolicyOracle
from payoutproof.scorer.scorer import EvaluationResult
from payoutproof.policy.evaluator import PolicyGate
from payoutproof.core.crypto import compute_intent_hash


def execute_case_under_test(case: EvaluationCase) -> EvaluationResult:
    """Execute a single simulated case through the PayoutProof runtime and score against Oracle."""
    # 1. Check admission / tamper
    if case.is_tampered:
        req_status = "TAMPERED"
    elif case.is_unauthorized:
        req_status = "REJECTED"
    else:
        req_status = "ADMITTED"

    # 2. Build extracted intent
    intent = PaymentIntent(
        counterparty=case.counterparty,
        destination=case.destination,
        destination_status=case.destination_status,
        amount=case.amount,
        currency=case.currency,
        purpose=case.purpose,
        instruction_reference=case.instruction_ref,
        status=IntentStatus.CONFIRMED if not case.is_unusable_audio else IntentStatus.EXTRACTED,
        intent_hash=compute_intent_hash(PaymentIntent(
            counterparty=case.counterparty,
            destination=case.destination,
            destination_status=case.destination_status,
            amount=case.amount,
            currency=case.currency,
            purpose=case.purpose,
            instruction_reference=case.instruction_ref,
        )) if not case.is_unusable_audio else None,
    )

    # 3. Build findings
    findings = []
    if case.has_contradiction:
        findings.append(Finding(name="Destination consistency", truth_state=TruthState.CONTRADICTED, detail="Invoice mismatch"))
    if case.has_callback:
        findings.append(Finding(name="Independent callback", truth_state=TruthState.SUPPORTED, detail="Callback confirmed"))
    if case.has_destination_approval or case.destination_status == DestinationStatus.APPROVED_FOR_COUNTERPARTY:
        findings.append(Finding(name="Destination approval", truth_state=TruthState.SUPPORTED, detail="Approved"))

    model_status = "FAILED_UNUSABLE_AUDIO" if case.is_unusable_audio else "SUCCEEDED"

    state = RiskCaseState(
        case_id=case.case_id,
        request_bundle_status=req_status,
        intent=intent,
        findings=findings,
        investigation=CaseInvestigation(model_status=model_status),
    )

    # 4. Evaluate with runtime Policy Gate
    eval_res = PolicyGate.evaluate(state)
    predicted = eval_res.outcome

    # 5. Get Oracle ground truth
    gold_out, _ = PolicyOracle.evaluate_expected(case)

    # 6. Check unsafe handoff condition
    is_unsafe = (predicted == PolicyOutcome.ELIGIBLE_FOR_HANDOFF and gold_out != PolicyOutcome.ELIGIBLE_FOR_HANDOFF)
    is_exact = (predicted == gold_out)
    is_ib_correct = (intent.counterparty == case.counterparty and intent.amount == case.amount and intent.destination == case.destination)
    is_abstain_correct = (predicted in (PolicyOutcome.HOLD, PolicyOutcome.STEP_UP_REQUIRED, PolicyOutcome.BLOCKED)) if gold_out != PolicyOutcome.ELIGIBLE_FOR_HANDOFF else True

    return EvaluationResult(
        case_id=case.case_id,
        suite=case.suite,
        language=case.language,
        gold_outcome=gold_out,
        predicted_outcome=predicted,
        is_unsafe_handoff=is_unsafe,
        is_exact_match=is_exact,
        is_intent_binding_correct=is_ib_correct,
        is_correct_abstention=is_abstain_correct,
        simulated_no_tool_interactions=case.simulated_no_tool_interactions,
        simulated_tool_interactions=case.simulated_tool_interactions,
    )
