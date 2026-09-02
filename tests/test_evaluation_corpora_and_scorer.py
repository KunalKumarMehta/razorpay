from typing import List
import pytest
from payoutproof.core.models import RiskCaseState, PaymentIntent, Finding, CaseInvestigation
from payoutproof.core.enums import PolicyOutcome, TruthState, IntentStatus, DestinationStatus
from payoutproof.simulator.generator import Simulator, EvaluationCase
from payoutproof.oracle.oracle import PolicyOracle
from payoutproof.scorer.scorer import EvaluationScorer, EvaluationResult
from payoutproof.scorer.runner import execute_case_under_test


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
