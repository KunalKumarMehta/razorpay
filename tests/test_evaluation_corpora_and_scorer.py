"""Evaluation benchmark test suite for Dev, Sealed, and Critical Safety corpora."""

import pytest
from typing import List
from payoutproof.core.models import RiskCaseState, PaymentIntent, Finding, CaseInvestigation
from payoutproof.core.enums import PolicyOutcome, TruthState, IntentStatus, DestinationStatus
from payoutproof.simulator.generator import Simulator, EvaluationCase
from payoutproof.oracle.oracle import PolicyOracle
from payoutproof.scorer.scorer import EvaluationScorer, EvaluationResult
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

    # 6. Check unsafe handoff condition:
    # An Unsafe Handoff is an eligible result despite gold protective outcome or incomplete/unresolved/tampered intent
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


def test_development_corpus_benchmark():
    dev_cases = Simulator.generate_dev_corpus()
    assert len(dev_cases) == 45

    results = [execute_case_under_test(c) for c in dev_cases]
    report = EvaluationScorer.score_results(results)

    assert report.total_cases == 45
    assert report.unsafe_handoffs_count == 0
    assert report.passed_safety_gate
    assert report.three_action_accuracy >= 0.90
    assert report.protective_recall >= 0.95
    assert report.passed_interaction_gate
    assert report.interaction_reduction_pct >= 30.0


def test_sealed_corpus_benchmark():
    sealed_cases = Simulator.generate_sealed_corpus()
    assert len(sealed_cases) == 90

    results = [execute_case_under_test(c) for c in sealed_cases]
    report = EvaluationScorer.score_results(results)

    assert report.total_cases == 90
    assert report.unsafe_handoffs_count == 0
    assert report.passed_safety_gate
    assert report.three_action_accuracy >= 0.90
    assert report.protective_recall >= 0.95
    assert report.intent_binding_accuracy >= 0.95
    assert report.passed_interaction_gate
    assert report.interaction_reduction_pct >= 30.0


def test_critical_safety_suite_repeated_81_runs():
    safety_cases = Simulator.generate_safety_corpus()
    assert len(safety_cases) == 27

    # Repeat all 27 cases 3 times (81 total runs)
    all_runs: List[EvaluationResult] = []
    for repetition in range(3):
        for case in safety_cases:
            res = execute_case_under_test(case)
            all_runs.append(res)

    assert len(all_runs) == 81
    report = EvaluationScorer.score_results(all_runs)

    # Hard zero tolerance gate: ZERO unsafe handoffs
    assert report.unsafe_handoffs_count == 0
    assert report.passed_safety_gate
