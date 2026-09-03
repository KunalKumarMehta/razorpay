"""Tests for Issue #23: Correct Intent Binding Correctness scoring.

Verifies:
1. Every Evaluation Case declares expected binding correctness independently of runtime output.
2. A correctly rejected invalid or unsupported binding counts as correct rather than as a failed valid binding.
3. Answer metadata cannot enter the product execution boundary (RuntimeCaseInput excludes expected binding).
4. Existing synthetic suites rerun with the corrected metric and preserve complete per-case diagnostics.
"""

import pytest

from payoutproof.simulator.generator import Simulator, EvaluationCase, RuntimeCaseInput
from payoutproof.oracle.oracle import PolicyOracle
from payoutproof.scorer.runner import execute_runtime_case, execute_case_under_test
from payoutproof.scorer.service import EvaluationExecutionService
from payoutproof.core.enums import PolicyOutcome


def test_every_evaluation_case_declares_expected_binding_correctness():
    """Simulator cases declare expected_intent_binding_correct independently of runtime."""
    dev_cases = Simulator.generate_dev_corpus()
    for case in dev_cases:
        assert isinstance(case.expected_intent_binding_correct, bool)
        assert case.expected_intent_binding_correct is True

    sealed_cases = Simulator.generate_sealed_corpus()
    for case in sealed_cases:
        assert isinstance(case.expected_intent_binding_correct, bool)
        assert case.expected_intent_binding_correct is True

    safety_cases = Simulator.generate_safety_corpus()
    for case in safety_cases:
        assert isinstance(case.expected_intent_binding_correct, bool)
        if case.has_material_intent_error or case.is_unusable_audio or case.is_schema_failure or case.mutate_amount_after_grant:
            assert case.expected_intent_binding_correct is False, (
                f"Adversarial case {case.case_id} in {case.category} must expect no valid binding"
            )
        elif not case.is_unauthorized:
            assert case.expected_intent_binding_correct is True, (
                f"Valid intent case {case.case_id} in {case.category} must expect valid binding"
            )


def test_answer_metadata_isolation_at_runtime_boundary():
    """RuntimeCaseInput never includes expected_intent_binding_correct or evaluator truth."""
    dev_cases = Simulator.generate_dev_corpus()
    case = dev_cases[0]
    runtime_input = case.to_runtime_input()

    assert not hasattr(runtime_input, "expected_intent_binding_correct")
    assert not hasattr(runtime_input, "gold_outcome")
    assert not hasattr(runtime_input, "expected_reasons")
    assert not hasattr(runtime_input, "suite")
    assert not hasattr(runtime_input, "category")


def test_correctly_rejected_adversarial_binding_counts_as_correct():
    """Adversarial intent correctly rejected by product scores as correct binding behavior."""
    safety_cases = Simulator.generate_safety_corpus()
    cat1_case = next(c for c in safety_cases if c.category == "CAT1_MATERIAL_INTENT_ERROR")

    # 1. Product execution: runtime observed binding is False (because intent was invalidated/hash-mismatched)
    diagnostics = execute_runtime_case(cat1_case.to_runtime_input())
    assert diagnostics.is_intent_binding_correct is False

    # 2. Scored evaluation: expected is False, observed is False -> matches expectation -> scored correct!
    result = execute_case_under_test(cat1_case)
    assert result.is_intent_binding_correct is True
    assert result.observed_intent_binding is False
    assert result.expected_intent_binding is False


def test_safety_suite_intent_binding_meets_predeclared_target():
    """Full SAFETY suite scores >= 95% Intent Binding Correctness with per-case diagnostics."""
    report = EvaluationExecutionService.run_suite("SAFETY")

    # Target gate is >= 95.0%
    assert report.intent_binding_accuracy >= 0.95
    assert report.intent_binding_accuracy == 1.0
    assert report.passed_safety_gate is True

    # Per-case audit diagnostics are preserved
    assert len(report.execution_records) == 81
    for rec in report.execution_records:
        assert hasattr(rec, "observed_intent_binding")
        assert hasattr(rec, "expected_intent_binding")
        assert rec.is_intent_binding_correct is True
