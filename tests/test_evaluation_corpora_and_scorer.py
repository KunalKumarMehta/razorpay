import copy
import inspect
from pathlib import Path
import pickle
import tempfile
from typing import List
import pydantic
import pytest
from payoutproof.core.models import RiskCaseState, PaymentIntent, Finding, CaseInvestigation
from payoutproof.core.enums import (
    PolicyOutcome,
    TruthState,
    IntentStatus,
    DestinationStatus,
    CasePhase,
    GrantStatus,
    AdapterDecision,
    ReasonCode,
    HandoffStatus,
)
from payoutproof.core.crypto import compute_intent_hash
from payoutproof.simulator.generator import Simulator, EvaluationCase, RuntimeCaseInput
from payoutproof.oracle.oracle import PolicyOracle
from payoutproof.policy.evaluator import PolicyGate
from payoutproof.scorer.scorer import EvaluationScorer, EvaluationResult
from payoutproof.scorer.runner import execute_case_under_test, execute_runtime_case, RuntimeCaseDiagnostics
from payoutproof.scorer import runner as runner_module
from payoutproof.scorer.service import (
    EvaluationExecutionService,
    SuiteExecutionReport,
    RepetitionAuditRecord,
    ExecutionAuditRecord,
    SYNTHETIC_SCOPE_DECLARATION,
    _FrozenDict,
)
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.storage.db import Database
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter


def test_development_corpus_benchmark():
    report = EvaluationExecutionService.run_suite("dev")

    assert report.total_cases == 45
    assert report.total_executions == 45
    assert report.repetition_count == 1
    assert report.base_case_count == 45
    assert report.product_boundary_call_count == 45
    assert report.unsafe_handoffs_count == 0
    assert report.exact_mismatches_count == 0
    assert report.mismatched_execution_ids == ()
    assert report.passed_safety_gate
    assert report.three_action_accuracy >= 0.90
    assert report.protective_recall >= 0.95
    assert report.passed_interaction_gate
    assert report.interaction_reduction_pct >= 30.0
    assert report.scope_declaration == SYNTHETIC_SCOPE_DECLARATION


def test_sealed_corpus_benchmark():
    report = EvaluationExecutionService.run_suite("sealed")

    assert report.total_cases == 90
    assert report.total_executions == 90
    assert report.repetition_count == 1
    assert report.base_case_count == 90
    assert report.product_boundary_call_count == 90
    assert report.unsafe_handoffs_count == 0
    assert report.exact_mismatches_count == 0
    assert report.mismatched_execution_ids == ()
    assert report.passed_safety_gate
    assert report.three_action_accuracy >= 0.90
    assert report.protective_recall >= 0.95
    assert report.intent_binding_accuracy >= 0.95
    assert report.passed_interaction_gate
    assert report.interaction_reduction_pct >= 30.0
    assert report.scope_declaration == SYNTHETIC_SCOPE_DECLARATION


def test_critical_safety_suite_repeated_81_runs():
    report = EvaluationExecutionService.run_suite("safety")

    assert report.total_cases == 81
    assert report.total_executions == 81
    assert report.repetition_count == 3
    assert report.base_case_count == 27
    assert report.product_boundary_call_count == 81
    assert report.unsafe_handoffs_count == 0
    assert report.exact_mismatches_count == 0
    assert report.mismatched_execution_ids == ()
    assert report.passed_safety_gate
    assert report.scope_declaration == SYNTHETIC_SCOPE_DECLARATION



# ---------------------------------------------------------------------------
# P0-4A1: runtime input isolation
# ---------------------------------------------------------------------------


def test_runtime_input_excludes_evaluator_truth():
    dev_cases = Simulator.generate_dev_corpus()
    runtime_input = dev_cases[0].to_runtime_input()

    assert isinstance(runtime_input, RuntimeCaseInput)
    assert runtime_input.model_config.get("frozen") is True

    dumped = runtime_input.model_dump()

    # Runtime stimulus must not carry evaluator metadata or answer labels.
    forbidden = [
        "category",
        "gold_outcome",
        "expected_reasons",
        "suite",
        "scenario_description",
        "speaker_profile",
        "simulated_no_tool_interactions",
        "simulated_tool_interactions",
    ]
    for key in forbidden:
        assert key not in dumped, f"runtime input leaks evaluator field: {key}"

    # All runtime-observable stimulus fields survive the projection.
    assert dumped["case_id"] == dev_cases[0].case_id
    assert dumped["counterparty"] == dev_cases[0].counterparty
    assert dumped["destination"] == dev_cases[0].destination
    assert dumped["amount"] == dev_cases[0].amount
    assert dumped["purpose"] == dev_cases[0].purpose
    assert dumped["instruction_ref"] == dev_cases[0].instruction_ref
    assert dumped["has_callback"] == dev_cases[0].has_callback
    assert dumped["is_tampered"] == dev_cases[0].is_tampered
    assert dumped["mutate_amount_after_grant"] == dev_cases[0].mutate_amount_after_grant
    assert dumped["replay_grant_after_storage_restart"] == dev_cases[0].replay_grant_after_storage_restart


def test_runtime_input_is_frozen():
    runtime_input = Simulator.generate_dev_corpus()[0].to_runtime_input()
    with pytest.raises(pydantic.ValidationError):
        runtime_input.amount = "999999"


def test_execute_runtime_case_rejects_evaluator_case():
    case = Simulator.generate_dev_corpus()[0]
    with pytest.raises(TypeError):
        execute_runtime_case(case)


def test_execute_runtime_case_returns_no_truth_fields():
    diagnostics = execute_runtime_case(Simulator.generate_dev_corpus()[0].to_runtime_input())
    assert isinstance(diagnostics, RuntimeCaseDiagnostics)

    dumped = diagnostics.model_dump()
    for key in ("gold_outcome", "expected_reasons", "category", "is_exact_match"):
        assert key not in dumped, f"diagnostics leaks truth field: {key}"
    assert diagnostics.predicted_outcome in (
        PolicyOutcome.HOLD,
        PolicyOutcome.STEP_UP_REQUIRED,
        PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
        PolicyOutcome.BLOCKED,
    )


def test_product_boundary_source_has_no_oracle_or_answer_reference():
    """Source inspection: execution boundary and its helpers never mention truth/answers."""
    boundary_symbols = [
        runner_module.RuntimeCaseDiagnostics,
        runner_module._build_authority_record,
        runner_module._build_runtime_state,
        runner_module._execute_mutation_after_grant,
        runner_module._execute_replay_after_storage_restart,
        runner_module.execute_runtime_case,
    ]
    forbidden_tokens = (
        "PolicyOracle",
        "gold_outcome",
        "expected_reasons",
    )
    for symbol in boundary_symbols:
        source = inspect.getsource(symbol)
        for token in forbidden_tokens:
            assert token not in source, (
                f"{symbol.__name__} references {token}: product boundary must not depend on truth"
            )

    # No module-level oracle import exists; the scorer wrapper imports it
    # locally and runs only after execution has returned.
    assert not hasattr(runner_module, "PolicyOracle")
    module_source = inspect.getsource(runner_module)
    module_level_oracle_imports = [
        line for line in module_source.splitlines()
        if line.startswith("from") and "oracle" in line
    ]
    assert module_level_oracle_imports == [], "module-level oracle import found in runner"


def test_poisoned_answers_do_not_change_prediction():
    """Tampering with recorded answers must not alter what the product predicts."""
    safety_cases = Simulator.generate_safety_corpus()

    for case in safety_cases:
        poisoned = case.model_copy(
            update={
                "gold_outcome": PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
                "expected_reasons": ["REQUIRED_EVIDENCE_SATISFIED", "EXACT_INTENT_FROZEN"],
            }
        )
        baseline = execute_runtime_case(case.to_runtime_input())
        poisoned_run = execute_runtime_case(poisoned.to_runtime_input())
        assert poisoned_run.predicted_outcome == baseline.predicted_outcome, (
            f"poisoned answers changed prediction for {case.case_id}"
        )
        assert poisoned_run.predicted_reasons == baseline.predicted_reasons


def test_poisoned_category_and_description_do_not_change_prediction():
    safety_cases = Simulator.generate_safety_corpus()
    for case in safety_cases:
        poisoned = case.model_copy(
            update={
                "category": "CAT2_UNAPPROVED_DESTINATION",
                "scenario_description": "totally benign routine payout",
                "suite": "DEV",
            }
        )
        baseline = execute_runtime_case(case.to_runtime_input())
        poisoned_run = execute_runtime_case(poisoned.to_runtime_input())
        assert poisoned_run.predicted_outcome == baseline.predicted_outcome
        assert poisoned_run.predicted_reasons == baseline.predicted_reasons


def test_execute_case_under_test_uses_oracle_for_gold_not_case_label():
    """Compatibility orchestration takes gold from the oracle, not the recorded label."""
    safety_cases = Simulator.generate_safety_corpus()
    cat6 = next(c for c in safety_cases if c.category == "CAT6_EXTRACTION_SCHEMA_FAIL")

    # The recorded label agrees with scenario truth for the real corpus, so use
    # a poisoned variant to prove the score path reads the oracle.
    poisoned = cat6.model_copy(update={"gold_outcome": PolicyOutcome.ELIGIBLE_FOR_HANDOFF})
    result = execute_case_under_test(poisoned)
    assert result.gold_outcome == PolicyOutcome.HOLD
    assert result.predicted_outcome == PolicyOutcome.HOLD
    assert result.is_exact_match is True
    assert result.is_unsafe_handoff is False


# ---------------------------------------------------------------------------
# CAT1: material intent error
# ---------------------------------------------------------------------------


def test_cat1_variants_hold_via_material_intent_changed():
    safety_cases = Simulator.generate_safety_corpus()
    cat1_cases = [c for c in safety_cases if c.category == "CAT1_MATERIAL_INTENT_ERROR"]
    assert len(cat1_cases) == 3

    from payoutproof.core.crypto import compute_intent_hash

    for case in cat1_cases:
        assert case.gold_outcome == PolicyOutcome.HOLD
        assert case.has_material_intent_error is True
        assert case.is_unusable_audio is False
        assert case.is_schema_failure is False

        diagnostics = execute_runtime_case(case.to_runtime_input())
        assert diagnostics.predicted_outcome == PolicyOutcome.HOLD, (
            f"CAT1 case {case.case_id} did not HOLD"
        )
        assert "MATERIAL_INTENT_CHANGED" in diagnostics.predicted_reasons
        assert diagnostics.model_status == "SUCCEEDED"

        # A material intent error means the binding is broken, in every
        # representation of that error: field equality alone must not report a
        # correct binding.
        assert diagnostics.is_intent_binding_correct is False, (
            f"CAT1 case {case.case_id} reported a correct intent binding "
            "despite its material intent error"
        )

        # The HOLD must be derived from a real case-state inconsistency,
        # never assigned directly.
        state = diagnostics.state
        if case.intent_error_mode == "HASH_MISMATCH":
            # Recomputing the hash over the stored intent cannot reproduce it.
            assert state.intent.status == IntentStatus.CONFIRMED
            assert compute_intent_hash(state.intent) != state.intent.intent_hash
        else:
            assert state.intent.status == IntentStatus.INVALIDATED


def test_cat1_hash_mismatch_variant_exists():
    safety_cases = Simulator.generate_safety_corpus()
    modes = {
        c.case_id: c.intent_error_mode
        for c in safety_cases
        if c.category == "CAT1_MATERIAL_INTENT_ERROR"
    }
    assert "HASH_MISMATCH" in modes.values()
    assert "INVALIDATED" in modes.values()


def test_cat1_hash_mismatch_with_amount_one_still_mismatches():
    """Regression: the mutated amount must never collide with the real amount.

    The HASH_MISMATCH construction previously mutated the amount to a
    hardcoded "1"; when the runtime amount was itself "1" the recomputed hash
    equalled the frozen hash and the material mutation silently vanished.
    """
    case = next(
        c for c in Simulator.generate_safety_corpus()
        if c.category == "CAT1_MATERIAL_INTENT_ERROR"
    ).model_copy(update={"amount": "1", "intent_error_mode": "HASH_MISMATCH"})

    diagnostics = execute_runtime_case(case.to_runtime_input())
    assert diagnostics.state.intent.status == IntentStatus.CONFIRMED
    assert compute_intent_hash(diagnostics.state.intent) != diagnostics.state.intent.intent_hash, (
        "HASH_MISMATCH construction reproduced the real hash for amount == '1'"
    )
    assert diagnostics.predicted_outcome == PolicyOutcome.HOLD
    assert "MATERIAL_INTENT_CHANGED" in diagnostics.predicted_reasons


# ---------------------------------------------------------------------------
# CAT6: extraction schema failure
# ---------------------------------------------------------------------------


def test_cat6_variants_are_schema_failure_not_audio():
    safety_cases = Simulator.generate_safety_corpus()
    cat6_cases = [c for c in safety_cases if c.category == "CAT6_EXTRACTION_SCHEMA_FAIL"]
    assert len(cat6_cases) == 3

    for case in cat6_cases:
        assert case.is_schema_failure is True
        assert case.is_unusable_audio is False

        diagnostics = execute_runtime_case(case.to_runtime_input())
        assert diagnostics.predicted_outcome == PolicyOutcome.HOLD
        assert diagnostics.model_status == "FAILED_SCHEMA_ERROR"
        assert diagnostics.model_status != "FAILED_UNUSABLE_AUDIO"

        state = diagnostics.state
        assert state.investigation.model_status == "FAILED_SCHEMA_ERROR"
        assert state.investigation.model_status != "FAILED_UNUSABLE_AUDIO"

        # Schema failure holds without claiming a model decode failure.
        assert "REQUIRED_SIGNAL_UNAVAILABLE" in diagnostics.predicted_reasons
        assert "MODEL_FAILURE" not in diagnostics.predicted_reasons


def test_cat4_audio_still_reports_model_failure():
    safety_cases = Simulator.generate_safety_corpus()
    cat4 = next(c for c in safety_cases if c.category == "CAT4_UNUSABLE_AUDIO_FAILURE")

    diagnostics = execute_runtime_case(cat4.to_runtime_input())
    assert diagnostics.predicted_outcome == PolicyOutcome.HOLD
    assert diagnostics.model_status == "FAILED_UNUSABLE_AUDIO"
    assert "REQUIRED_SIGNAL_UNAVAILABLE" in diagnostics.predicted_reasons
    assert "MODEL_FAILURE" in diagnostics.predicted_reasons


# ---------------------------------------------------------------------------
# All safety categories: 27 frozen cases match gold and oracle
# ---------------------------------------------------------------------------


def test_all_safety_cases_match_frozen_gold_and_oracle():
    """Every one of the 27 critical safety cases matches both its frozen gold outcome and oracle truth."""
    safety_cases = Simulator.generate_safety_corpus()
    assert len(safety_cases) == 27

    for case in safety_cases:
        diagnostics = execute_runtime_case(case.to_runtime_input())
        oracle_gold, _ = PolicyOracle.evaluate_expected(case)

        # Checked against both frozen gold_outcome and evaluator oracle result
        assert case.gold_outcome == oracle_gold, (
            f"{case.case_id} ({case.category}): frozen gold {case.gold_outcome} != oracle {oracle_gold}"
        )
        assert diagnostics.predicted_outcome == case.gold_outcome, (
            f"{case.case_id} ({case.category}): predicted {diagnostics.predicted_outcome} != gold {case.gold_outcome}"
        )
        assert diagnostics.predicted_outcome == oracle_gold, (
            f"{case.case_id} ({case.category}): predicted {diagnostics.predicted_outcome} != oracle {oracle_gold}"
        )
        # Never an unsafe handoff
        assert diagnostics.predicted_outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF


def test_non_step_up_safety_categories_hold_or_block():
    """HOLD and BLOCKED categories are named truthfully: STEP_UP_REQUIRED categories are excluded."""
    safety_cases = Simulator.generate_safety_corpus()
    hold_or_block_categories = {
        "CAT1_MATERIAL_INTENT_ERROR",
        "CAT3_CONTRADICTORY_EVIDENCE",
        "CAT4_UNUSABLE_AUDIO_FAILURE",
        "CAT6_EXTRACTION_SCHEMA_FAIL",
        "CAT7_MATERIAL_MUTATION",
        "CAT8_DUPLICATE_REPLAY",
        "CAT9_TAMPERED_SNAPSHOT",
    }

    checked = 0
    for case in safety_cases:
        if case.category in hold_or_block_categories:
            diagnostics = execute_runtime_case(case.to_runtime_input())
            assert diagnostics.predicted_outcome in (PolicyOutcome.HOLD, PolicyOutcome.BLOCKED), (
                f"{case.case_id} ({case.category}) predicted "
                f"{diagnostics.predicted_outcome}, expected HOLD or BLOCKED"
            )
            checked += 1
    assert checked == len(hold_or_block_categories) * 3


# ---------------------------------------------------------------------------
# Dedicated CAT7: real post-evaluation material mutation
# ---------------------------------------------------------------------------


def test_cat7_variants_post_evaluation_material_mutation_invalidates_and_refuses_handoff():
    """Dedicated CAT7 test: proves real transition invalidation and refusal/no handoff for all 3 variants."""
    safety_cases = Simulator.generate_safety_corpus()
    cat7_cases = [c for c in safety_cases if c.category == "CAT7_MATERIAL_MUTATION"]
    assert len(cat7_cases) == 3

    for case in cat7_cases:
        assert case.gold_outcome == PolicyOutcome.HOLD
        assert case.mutate_amount_after_grant is True
        assert case.replay_grant_after_storage_restart is False
        assert case.has_callback is True
        assert case.has_destination_approval is True
        assert case.destination_status == DestinationStatus.APPROVED_FOR_COUNTERPARTY

        # 1. Product execution boundary assertion
        diagnostics = execute_runtime_case(case.to_runtime_input())
        assert diagnostics.predicted_outcome == PolicyOutcome.HOLD
        assert "PREVIOUS_EVALUATION_INVALIDATED" in diagnostics.predicted_reasons
        assert "MATERIAL_INTENT_CHANGED" in diagnostics.predicted_reasons
        assert diagnostics.is_intent_binding_correct is False
        assert diagnostics.state.intent.status == IntentStatus.INVALIDATED
        assert diagnostics.state.grant is not None
        assert diagnostics.state.grant.status == GrantStatus.INVALIDATED
        assert diagnostics.state.handoff.status == HandoffStatus.NOT_STARTED
        assert diagnostics.state.handoff.attempts == 0
        assert diagnostics.state.policy.outcome == PolicyOutcome.HOLD

        # 2. Real domain sequence verification directly on state transitions
        initial_state = runner_module._build_runtime_state(
            case.to_runtime_input(), runner_module.FIXED_EVALUATION_TIME
        )
        init_eval = PolicyGate.evaluate(initial_state, evaluation_time=runner_module.FIXED_EVALUATION_TIME)
        assert init_eval.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF

        ready_state = initial_state.model_copy(update={
            "policy": init_eval,
            "phase": CasePhase.READY_FOR_HUMAN_HANDOFF,
        })
        granted_state = StateMachine.reduce(
            ready_state,
            {"type": "ISSUE_GRANT", "payload": {}},
            grant_secret=runner_module._EVALUATOR_GRANT_SECRET,
            clock=runner_module.FixedClock(runner_module.FIXED_EVALUATION_TIME),
        )
        assert granted_state.grant is not None
        assert granted_state.grant.status == GrantStatus.ACTIVE
        assert granted_state.grant.used is False

        # Real EDIT_AMOUNT with guaranteed-different amount
        current_amount = granted_state.intent.amount or "500000"
        mutated_amount = "600000" if current_amount != "600000" else "700000"
        mutated_state = StateMachine.reduce(
            granted_state,
            {"type": "EDIT_AMOUNT", "payload": {"amount": mutated_amount}},
            clock=runner_module.FixedClock(runner_module.FIXED_EVALUATION_TIME),
        )
        assert mutated_state.intent.status == IntentStatus.INVALIDATED
        assert mutated_state.grant.status == GrantStatus.INVALIDATED
        assert mutated_state.policy.outcome == PolicyOutcome.HOLD
        assert ReasonCode.PREVIOUS_EVALUATION_INVALIDATED in mutated_state.policy.reasons
        assert ReasonCode.MATERIAL_INTENT_CHANGED in mutated_state.policy.reasons

        # Handoff refusal on mutated state: no handoff initiated
        refused_state = StateMachine.reduce(
            mutated_state,
            {"type": "INITIATE_HANDOFF", "payload": {}},
            grant_secret=runner_module._EVALUATOR_GRANT_SECRET,
        )
        assert "Refused" in refused_state.last_change
        assert refused_state.handoff.status == HandoffStatus.NOT_STARTED


# ---------------------------------------------------------------------------
# Dedicated CAT8: real durable duplicate-grant replay
# ---------------------------------------------------------------------------


def test_cat8_variants_durable_duplicate_grant_replay_rejected_with_hold():
    """Dedicated CAT8 test: proves first success, DB close/reopen, second replay rejection,
    exactly one durable pending item, consumed grant, final HOLD/reason for all 3 variants.
    """
    safety_cases = Simulator.generate_safety_corpus()
    cat8_cases = [c for c in safety_cases if c.category == "CAT8_DUPLICATE_REPLAY"]
    assert len(cat8_cases) == 3

    for case in cat8_cases:
        assert case.gold_outcome == PolicyOutcome.HOLD
        assert case.replay_grant_after_storage_restart is True
        assert case.mutate_amount_after_grant is False
        assert case.has_callback is True
        assert case.has_destination_approval is True
        assert case.destination_status == DestinationStatus.APPROVED_FOR_COUNTERPARTY

        # 1. Product execution boundary assertion
        diagnostics = execute_runtime_case(case.to_runtime_input())
        assert diagnostics.predicted_outcome == PolicyOutcome.HOLD
        assert "REQUIRED_SIGNAL_UNAVAILABLE" in diagnostics.predicted_reasons
        assert diagnostics.state.grant is not None
        assert diagnostics.state.grant.status == GrantStatus.CONSUMED
        assert diagnostics.state.grant.used is True
        assert diagnostics.state.handoff.last_adapter_decision == AdapterDecision.REPLAY_REJECTED

        # 2. Step-by-step durable domain lifecycle with temporary directory
        open_conns = []
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / f"cat8_test_{case.case_id}.db"
            db1 = Database(db_path=db_path, audit_checkpoint_secret=runner_module._EVALUATOR_AUDIT_SECRET)

            orig_conn1 = db1.get_connection
            def _track1(*args, **kwargs):
                conn = orig_conn1(*args, **kwargs)
                open_conns.append(conn)
                return conn
            db1.get_connection = _track1

            try:
                # Eligible initial state
                initial_state = runner_module._build_runtime_state(
                    case.to_runtime_input(), runner_module.FIXED_EVALUATION_TIME
                )
                init_eval = PolicyGate.evaluate(initial_state, evaluation_time=runner_module.FIXED_EVALUATION_TIME)
                assert init_eval.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF

                ready_state = initial_state.model_copy(update={
                    "policy": init_eval,
                    "phase": CasePhase.READY_FOR_HUMAN_HANDOFF,
                })
                # Real StateMachine ISSUE_GRANT
                granted_state = StateMachine.reduce(
                    ready_state,
                    {"type": "ISSUE_GRANT", "payload": {}},
                    grant_secret=runner_module._EVALUATOR_GRANT_SECRET,
                    clock=None,
                )
                assert granted_state.grant.status == GrantStatus.ACTIVE
                assert granted_state.grant.used is False

                # Persist authoritative case & grant
                db1.save_case(granted_state)

                # First real fake-rail handoff
                adapter1 = FakeApprovalRailAdapter(
                    db=db1,
                    grant_secret=runner_module._EVALUATOR_GRANT_SECRET,
                    audit_checkpoint_secret=runner_module._EVALUATOR_AUDIT_SECRET,
                )
                decision1, item1, err1 = adapter1.submit_handoff(
                    grant=granted_state.grant,
                    intent=granted_state.intent,
                )
                assert decision1 == AdapterDecision.PENDING_ITEM_CREATED
                assert item1 is not None
                assert err1 is None

                # Must create exactly one pending item and consume grant
                pending_items_1 = db1.get_all_pending_items()
                assert len(pending_items_1) == 1
                assert granted_state.grant.grant_id in db1.get_consumed_grant_ids()

                # Close/reopen Database and recreate adapter/service state on same DB file
                db2 = Database(db_path=db_path, audit_checkpoint_secret=runner_module._EVALUATOR_AUDIT_SECRET)
                orig_conn2 = db2.get_connection
                def _track2(*args, **kwargs):
                    conn = orig_conn2(*args, **kwargs)
                    open_conns.append(conn)
                    return conn
                db2.get_connection = _track2

                adapter2 = FakeApprovalRailAdapter(
                    db=db2,
                    grant_secret=runner_module._EVALUATOR_GRANT_SECRET,
                    audit_checkpoint_secret=runner_module._EVALUATOR_AUDIT_SECRET,
                )

                # Replay the same grant through the real persistence/adapter transaction
                decision2, item2, err2 = adapter2.submit_handoff(
                    grant=granted_state.grant,
                    intent=granted_state.intent,
                )
                assert decision2 == AdapterDecision.REPLAY_REJECTED
                assert item2 is None
                assert "already been consumed" in (err2 or "").lower()

                # Must create no second item, leave exactly one pending item, and retain consumed/used grant state
                pending_items_2 = db2.get_all_pending_items()
                assert len(pending_items_2) == 1
                assert granted_state.grant.grant_id in db2.get_consumed_grant_ids()

                # Feed real replay decision/state through StateMachine/PolicyGate boundaries
                persisted_case = db2.load_case(granted_state.case_id)
                replayed_state = StateMachine.apply_adapter_decision(
                    state=persisted_case,
                    decision=decision2,
                    error_message=err2,
                )
                assert replayed_state.handoff.last_adapter_decision == AdapterDecision.REPLAY_REJECTED

                eval_res = PolicyGate.evaluate(replayed_state, evaluation_time=runner_module.FIXED_EVALUATION_TIME)
                assert eval_res.outcome == PolicyOutcome.HOLD
                assert ReasonCode.REQUIRED_SIGNAL_UNAVAILABLE in eval_res.reasons

                # Verify no second handoff can be initiated
                second_init = StateMachine.reduce(
                    replayed_state,
                    {"type": "INITIATE_HANDOFF", "payload": {}},
                    grant_secret=runner_module._EVALUATOR_GRANT_SECRET,
                )
                assert "Refused" in second_init.last_change
                assert second_init.handoff.status == HandoffStatus.PENDING_IN_APPROVAL_RAIL

            finally:
                for conn in open_conns:
                    try:
                        conn.close()
                    except Exception:
                        pass


def test_evaluated_at_is_deterministic():
    dev_cases = Simulator.generate_dev_corpus()
    a = execute_runtime_case(dev_cases[0].to_runtime_input())
    b = execute_runtime_case(dev_cases[0].to_runtime_input())
    assert a.predicted_outcome == b.predicted_outcome
    assert a.predicted_reasons == b.predicted_reasons
    assert a.model_status == b.model_status
    assert a.intent_status == b.intent_status

    # Policy-relevant state content is byte-identical across runs: the
    # confirmed intent hash, findings, and investigation inputs.
    assert a.state.intent.intent_hash == b.state.intent.intent_hash
    assert a.state.findings == b.state.findings
    assert a.state.investigation == b.state.investigation

    # The evaluation clock is injected, not wall-clock dependent: an explicit
    # fixed time yields the same policy result as the default.
    injected = execute_runtime_case(
        dev_cases[0].to_runtime_input(),
        evaluation_time=runner_module.FIXED_EVALUATION_TIME,
    )
    assert injected.predicted_outcome == a.predicted_outcome
    assert injected.predicted_reasons == a.predicted_reasons
    assert injected.state.intent.intent_hash == a.state.intent.intent_hash


def test_identical_eligible_executions_are_fully_deterministic():
    """Determinism goes beyond identical HOLD output: the entire case content is identical.

    Evidence `admitted_at` is injected from the resolved evaluation time in
    every evidence construction path, so two executions of the same eligible
    stimulus produce identical evidence and — because the snapshot hash covers
    that evidence — an identical evaluated snapshot hash.
    """
    eligible = next(
        c for c in Simulator.generate_dev_corpus()
        if c.gold_outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
    )

    first = execute_runtime_case(eligible.to_runtime_input())
    second = execute_runtime_case(eligible.to_runtime_input())

    assert first.predicted_outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
    assert first.predicted_outcome == second.predicted_outcome
    assert first.predicted_reasons == second.predicted_reasons

    # Identical evidence, not merely identical policy conclusions.
    assert first.state.evidence == second.state.evidence, (
        "two identical eligible executions produced different evidence — "
        "admitted_at must be injected from the resolved evaluation time"
    )
    for ev in first.state.evidence:
        assert ev.admitted_at == runner_module.FIXED_EVALUATION_TIME.isoformat(), (
            f"evidence admitted_at is not the injected evaluation time: {ev.admitted_at}"
        )

    # The eligible evaluation itself carries the snapshot hash, and it is
    # identical across runs.
    first_eval = PolicyGate.evaluate(
        first.state, evaluation_time=runner_module.FIXED_EVALUATION_TIME
    )
    second_eval = PolicyGate.evaluate(
        second.state, evaluation_time=runner_module.FIXED_EVALUATION_TIME
    )
    assert first_eval.evaluated_snapshot_hash is not None
    assert first_eval.evaluated_snapshot_hash == second_eval.evaluated_snapshot_hash


# ---------------------------------------------------------------------------
# Admission Rejection (P0-4A1)
# ---------------------------------------------------------------------------


def test_admission_rejection_has_no_policy_outcome():
    """An unauthorized case is rejected at admission and never gets a Policy Outcome.

    Per CONTEXT.md, Admission Rejection happens before policy evaluation, so
    the product must report None — never a false mapping to BLOCKED, and never
    a Pydantic ValidationError from a non-optional field.
    """
    base = Simulator.generate_dev_corpus()[0]
    rejected = base.model_copy(update={"is_unauthorized": True})

    diagnostics = execute_runtime_case(rejected.to_runtime_input())
    assert isinstance(diagnostics, RuntimeCaseDiagnostics)
    assert diagnostics.predicted_outcome is None, (
        "Admission Rejection must not produce a Policy Outcome"
    )
    assert diagnostics.predicted_reasons == ["ADMISSION_AUTHORITY_INCOMPLETE"]
    assert diagnostics.state.phase == CasePhase.ADMISSION_REJECTED
    assert diagnostics.state.processing_authority.value == "REJECTED"

    # The oracle agrees: an admission-rejected case has no expected policy
    # outcome either, rather than a fabricated BLOCKED.
    oracle_gold, oracle_reasons = PolicyOracle.evaluate_expected(rejected)
    assert oracle_gold is None
    assert oracle_reasons == ["ADMISSION_AUTHORITY_INCOMPLETE"]


def test_scoring_an_admission_rejected_fixture_fails_with_domain_error(monkeypatch):
    """The scoring wrapper must refuse admission-rejected fixtures, not product execution.

    Product execution succeeds (predicted_outcome=None); only the attempt to
    score that result against the benchmark's EvaluationResult — which cannot
    represent None — raises the explicit domain error. The oracle is
    monkeypatched to raise so this test proves the domain error fires before
    any oracle call, i.e. the failure belongs to the scoring boundary alone.
    """
    base = Simulator.generate_dev_corpus()[0]
    rejected = base.model_copy(update={"is_unauthorized": True})

    def _boom(case):
        raise AssertionError("oracle must not be consulted for an admission-rejected fixture")

    monkeypatch.setattr(PolicyOracle, "evaluate_expected", _boom)

    diagnostics = execute_runtime_case(rejected.to_runtime_input())
    with pytest.raises(runner_module.AdmissionRejectedScoringError) as excinfo:
        execute_case_under_test(rejected)
    assert "no Policy Outcome" in str(excinfo.value)
    assert "cannot represent None" in str(excinfo.value)


def test_runtime_case_diagnostics_is_frozen():
    """RuntimeCaseDiagnostics is an immutable execution record."""
    diagnostics = execute_runtime_case(
        Simulator.generate_dev_corpus()[0].to_runtime_input()
    )
    with pytest.raises(pydantic.ValidationError):
        diagnostics.model_status = "TAMPERED"


# ---------------------------------------------------------------------------
# Dynamic isolation of the product execution boundary (P0-4A1)
# ---------------------------------------------------------------------------


def test_product_execution_survives_oracle_failure(monkeypatch):
    """Runtime isolation is behavioral, not merely textual: if PolicyOracle breaks,
    execute_runtime_case still succeeds.

    The source-inspection test above (no oracle import at module level) is
    kept as documentation, but a monkeypatched oracle raising on every call
    is the dynamic proof that product execution never depends on the oracle.
    """
    def _boom(case):
        raise RuntimeError("oracle is broken")

    monkeypatch.setattr(PolicyOracle, "evaluate_expected", _boom)

    eligible = next(
        c for c in Simulator.generate_dev_corpus()
        if c.gold_outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
    )
    diagnostics = execute_runtime_case(eligible.to_runtime_input())
    assert diagnostics.predicted_outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF

    # And the broader corpus still executes end to end without touching it.
    for case in Simulator.generate_safety_corpus():
        executed = execute_runtime_case(case.to_runtime_input())
        assert executed.predicted_outcome is not None or case.is_unauthorized


def test_intent_binding_true_requires_confirmed_status_and_recomputed_hash():
    """A correct binding requires CONFIRMED status and a reproducible hash, not field equality alone."""
    safety_cases = Simulator.generate_safety_corpus()

    # CAT1: every material-intent-error representation is a broken binding.
    for case in [c for c in safety_cases if c.category == "CAT1_MATERIAL_INTENT_ERROR"]:
        diagnostics = execute_runtime_case(case.to_runtime_input())
        assert diagnostics.is_intent_binding_correct is False

    # Failed extractions never have a confirmed, reproducible intent either.
    for case in [
        c for c in safety_cases
        if c.category in ("CAT4_UNUSABLE_AUDIO_FAILURE", "CAT6_EXTRACTION_SCHEMA_FAIL")
    ]:
        diagnostics = execute_runtime_case(case.to_runtime_input())
        assert diagnostics.is_intent_binding_correct is False

    # Eligible cases: confirmed status, hash reproduces, and the binding is true.
    eligible = next(
        c for c in Simulator.generate_dev_corpus()
        if c.gold_outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
    )
    diagnostics = execute_runtime_case(eligible.to_runtime_input())
    assert diagnostics.state.intent.status == IntentStatus.CONFIRMED
    assert compute_intent_hash(diagnostics.state.intent) == diagnostics.state.intent.intent_hash
    assert diagnostics.is_intent_binding_correct is True


# ---------------------------------------------------------------------------
# P0-4B: Centralized EvaluationExecutionService & anti-shortcut spy tests
# ---------------------------------------------------------------------------


def test_safety_suite_anti_shortcut_spy_and_audit(monkeypatch):
    """Monkeypatch service-bound boundary and prove safety executes exactly 81 real calls."""
    import payoutproof.scorer.service as service_mod

    intercepted_stimuli: List[RuntimeCaseInput] = []
    real_boundary = runner_module.execute_runtime_case

    def spy_execute(stimulus: RuntimeCaseInput, evaluation_time=None):
        intercepted_stimuli.append(stimulus)
        return real_boundary(stimulus, evaluation_time=evaluation_time)

    # Monkeypatch the exact service-bound boundary symbol
    monkeypatch.setattr(service_mod, "execute_runtime_case", spy_execute)

    report = EvaluationExecutionService.run_suite("safety")

    # 1. Exactly 81 real calls to execute_runtime_case
    assert len(intercepted_stimuli) == 81

    # 2. Inspect every intercepted argument: RuntimeCaseInput only, no evaluator metadata
    forbidden_evaluator_fields = [
        "category",
        "gold_outcome",
        "expected_reasons",
        "suite",
        "scenario_description",
        "speaker_profile",
        "oracle",
        "simulated_no_tool_interactions",
        "simulated_tool_interactions",
    ]
    seen_case_ids = set()
    for stim in intercepted_stimuli:
        assert isinstance(stim, RuntimeCaseInput), "Intercepted stimulus is not RuntimeCaseInput"
        dumped = stim.model_dump()
        for field_name in forbidden_evaluator_fields:
            assert field_name not in dumped, f"Intercepted stimulus leaked evaluator field: {field_name}"
        assert stim.case_id, "Intercepted stimulus has empty case_id"
        assert stim.case_id not in seen_case_ids, f"Duplicate execution case_id: {stim.case_id}"
        seen_case_ids.add(stim.case_id)

    # 3. 81 safety case_ids are deterministic, unique, and follow collision-safe format
    assert len(seen_case_ids) == 81
    assert all(cid.endswith(("-R1", "-R2", "-R3")) for cid in seen_case_ids)

    # 4. Assert 9 categories × 9 executions
    assert len(report.category_counts) == 9
    for cat_name, count in report.category_counts.items():
        assert count == 9, f"Category {cat_name} had {count} executions, expected 9"

    # 5. Assert 27 base cases × 3 executions
    assert len(report.base_case_counts) == 27
    for bc_id, count in report.base_case_counts.items():
        assert count == 3, f"Base case {bc_id} had {count} executions, expected 3"

    # 6. Three repetition records each containing all 27 ordered base IDs
    assert len(report.repetition_records) == 3
    expected_base_ids = [c.case_id for c in Simulator.generate_safety_corpus()]
    assert len(expected_base_ids) == 27

    for idx, rep_rec in enumerate(report.repetition_records):
        assert rep_rec.repetition_index == idx
        assert rep_rec.repetition_number == idx + 1
        assert rep_rec.case_count == 27
        assert rep_rec.base_case_ids == tuple(expected_base_ids)
        assert len(rep_rec.execution_ids) == 27
        expected_exec_ids = [f"{cid}-R{idx + 1}" for cid in expected_base_ids]
        assert rep_rec.execution_ids == tuple(expected_exec_ids)

    # 7. Ordered execution IDs and counts
    assert len(report.execution_ids) == 81
    assert len(set(report.execution_ids)) == 81
    assert report.total_executions == 81
    assert report.product_boundary_call_count == 81
    assert report.exact_mismatches_count == 0
    assert report.mismatched_execution_ids == ()
    assert report.unsafe_handoffs_count == 0
    assert report.passed_safety_gate is True
    assert report.scope_declaration == SYNTHETIC_SCOPE_DECLARATION

    # 8. Per-execution audit records
    assert len(report.execution_records) == 81
    for rec in report.execution_records:
        assert isinstance(rec, ExecutionAuditRecord)
        assert rec.is_exact_match is True
        assert rec.is_unsafe_handoff is False
        assert rec.predicted_outcome is not None
        assert rec.predicted_outcome == rec.gold_outcome
        assert rec.predicted_outcome == rec.oracle_outcome
        assert rec.base_case in expected_base_ids
        assert rec.repetition in (1, 2, 3)


def test_dev_and_sealed_anti_shortcut_spies(monkeypatch):
    """Prove dev makes 45 actual execute_runtime_case calls and sealed makes 90."""
    import payoutproof.scorer.service as service_mod

    intercepted_dev: List[RuntimeCaseInput] = []
    real_boundary = runner_module.execute_runtime_case

    def spy_dev(stimulus: RuntimeCaseInput, evaluation_time=None):
        intercepted_dev.append(stimulus)
        return real_boundary(stimulus, evaluation_time=evaluation_time)

    monkeypatch.setattr(service_mod, "execute_runtime_case", spy_dev)

    dev_report = EvaluationExecutionService.run_suite("dev")
    assert len(intercepted_dev) == 45
    assert dev_report.total_executions == 45
    assert dev_report.product_boundary_call_count == 45
    assert dev_report.repetition_count == 1
    assert dev_report.base_case_count == 45
    assert len(dev_report.repetition_records) == 1
    assert dev_report.repetition_records[0].case_count == 45
    assert dev_report.exact_mismatches_count == 0
    assert dev_report.unsafe_handoffs_count == 0

    intercepted_sealed: List[RuntimeCaseInput] = []

    def spy_sealed(stimulus: RuntimeCaseInput, evaluation_time=None):
        intercepted_sealed.append(stimulus)
        return real_boundary(stimulus, evaluation_time=evaluation_time)

    monkeypatch.setattr(service_mod, "execute_runtime_case", spy_sealed)

    sealed_report = EvaluationExecutionService.run_suite("sealed")
    assert len(intercepted_sealed) == 90
    assert sealed_report.total_executions == 90
    assert sealed_report.product_boundary_call_count == 90
    assert sealed_report.repetition_count == 1
    assert sealed_report.base_case_count == 90
    assert len(sealed_report.repetition_records) == 1
    assert sealed_report.repetition_records[0].case_count == 90
    assert sealed_report.exact_mismatches_count == 0
    assert sealed_report.unsafe_handoffs_count == 0


def test_unknown_service_suite_raises_value_error():
    """Service rejects invalid suite names with ValueError."""
    with pytest.raises(ValueError) as excinfo:
        EvaluationExecutionService.run_suite("unknown_suite")
    assert "Unknown evaluation suite" in str(excinfo.value)
    assert "unknown_suite" in str(excinfo.value)

    with pytest.raises(ValueError):
        EvaluationExecutionService.run_suite("")

    with pytest.raises(ValueError):
        EvaluationExecutionService.run_suite(None)  # type: ignore


def test_api_evaluation_endpoint_counts_and_structured_audit(tmp_path):
    """API endpoint delegates to service, returns structured report, and maps unknown suite to HTTP 400."""
    from starlette.testclient import TestClient
    from payoutproof.api.app import create_app
    from payoutproof.core.config import AppConfig

    config = AppConfig.for_tests(
        grant_secret="at-least-32-characters-grant-secret-ok",
        audit_checkpoint_secret="at-least-32-characters-checkpoint-ok",
        db_path=str(tmp_path / "api_eval_test.db"),
    )
    client = TestClient(create_app(config=config))

    # 1. Safety suite: 81 executions, 27 base cases, 3 repetitions
    resp_safety = client.post("/api/evaluate/run?suite=safety")
    assert resp_safety.status_code == 200
    data_safety = resp_safety.json()

    assert data_safety["total_cases"] == 81
    assert data_safety["total_executions"] == 81
    assert data_safety["repetition_count"] == 3
    assert data_safety["base_case_count"] == 27
    assert data_safety["product_boundary_call_count"] == 81
    assert data_safety["exact_mismatches_count"] == 0
    assert data_safety["mismatched_execution_ids"] == []
    assert data_safety["unsafe_handoffs_count"] == 0
    assert data_safety["passed_safety_gate"] is True
    assert data_safety["scope_declaration"] == "SYNTHETIC_INVARIANT_HARNESS_ONLY_NOT_HELD_OUT"
    assert len(data_safety["repetition_records"]) == 3
    assert len(data_safety["execution_records"]) == 81
    assert len(data_safety["execution_ids"]) == 81
    assert len(data_safety["category_counts"]) == 9
    for cat_name, cnt in data_safety["category_counts"].items():
        assert cnt == 9
    assert len(data_safety["base_case_counts"]) == 27
    for bc_id, cnt in data_safety["base_case_counts"].items():
        assert cnt == 3

    # Inspect first execution record
    first_rec = data_safety["execution_records"][0]
    assert "execution_id" in first_rec
    assert "base_case_id" in first_rec
    assert "repetition_number" in first_rec
    assert "category" in first_rec
    assert "predicted_outcome" in first_rec
    assert "gold_outcome" in first_rec
    assert "oracle_outcome" in first_rec
    assert first_rec["is_exact_match"] is True
    assert first_rec["is_unsafe_handoff"] is False

    # 2. Dev suite: 45 executions, 1 repetition
    resp_dev = client.post("/api/evaluate/run?suite=dev")
    assert resp_dev.status_code == 200
    data_dev = resp_dev.json()
    assert data_dev["total_cases"] == 45
    assert data_dev["total_executions"] == 45
    assert data_dev["repetition_count"] == 1
    assert data_dev["base_case_count"] == 45
    assert data_dev["product_boundary_call_count"] == 45
    assert data_dev["exact_mismatches_count"] == 0
    assert data_dev["unsafe_handoffs_count"] == 0

    # 3. Sealed suite: 90 executions, 1 repetition
    resp_sealed = client.post("/api/evaluate/run?suite=sealed")
    assert resp_sealed.status_code == 200
    data_sealed = resp_sealed.json()
    assert data_sealed["total_cases"] == 90
    assert data_sealed["total_executions"] == 90
    assert data_sealed["repetition_count"] == 1
    assert data_sealed["base_case_count"] == 90
    assert data_sealed["product_boundary_call_count"] == 90
    assert data_sealed["exact_mismatches_count"] == 0
    assert data_sealed["unsafe_handoffs_count"] == 0

    # 4. Unknown suite returns HTTP 400
    resp_invalid = client.post("/api/evaluate/run?suite=nonexistent_suite")
    assert resp_invalid.status_code == 400
    assert "Unknown evaluation suite" in resp_invalid.json()["detail"]


def test_cli_safety_output_truthful_and_visible(monkeypatch):
    """CLI eval output for safety visibly and truthfully reports 81 synthetic executions, 27x3, zero unsafe/mismatches."""
    import sys
    from rich.console import Console
    import payoutproof.cli.main

    cli_mod = sys.modules["payoutproof.cli.main"]
    record_console = Console(record=True, width=140)
    monkeypatch.setattr(cli_mod, "console", record_console)

    cli_mod.run_benchmark("safety")

    output = record_console.export_text()
    assert "81 synthetic executions" in output
    assert "27×3" in output
    assert "zero unsafe" in output
    assert "zero exact mismatches" in output
    assert "NOT held-out" in output
    assert "product proof" in output


def test_service_run_suite_admission_rejected_before_oracle(monkeypatch):
    """Corpus producing predicted_outcome=None raises AdmissionRejectedScoringError before oracle is consulted."""
    base = Simulator.generate_dev_corpus()[0]
    unauthorized_case = base.model_copy(update={"is_unauthorized": True})

    monkeypatch.setitem(
        EvaluationExecutionService.SUITE_CONFIGS,
        "unauthorized_suite",
        {
            "generator": lambda: [unauthorized_case],
            "repetitions": 1,
            "expected_base_count": 1,
        },
    )

    def _boom(case):
        raise AssertionError("PolicyOracle.evaluate_expected must not be called when admission is rejected")

    monkeypatch.setattr(PolicyOracle, "evaluate_expected", _boom)

    with pytest.raises(runner_module.AdmissionRejectedScoringError) as excinfo:
        EvaluationExecutionService.run_suite("unauthorized_suite")

    err_msg = str(excinfo.value)
    assert f"cannot score admission-rejected case {unauthorized_case.case_id}" in err_msg
    assert "no Policy Outcome" in err_msg
    assert "cannot represent None" in err_msg


def test_service_run_suite_base_count_drift_fails_closed_without_boundary_calls(monkeypatch):
    """Enforce expected_base_count invariant after corpus generation: dev 45, sealed 90, safety 27.

    Proves zero boundary calls occur when count drift is detected.
    """
    import payoutproof.scorer.service as service_mod

    boundary_calls = []

    def spy_boundary(stimulus: RuntimeCaseInput, evaluation_time=None):
        boundary_calls.append(stimulus)
        return runner_module.execute_runtime_case(stimulus, evaluation_time=evaluation_time)

    monkeypatch.setattr(service_mod, "execute_runtime_case", spy_boundary)

    # 1. Dev suite drift: 44 instead of 45
    dev_cases = Simulator.generate_dev_corpus()[:44]
    monkeypatch.setitem(
        EvaluationExecutionService.SUITE_CONFIGS["dev"],
        "generator",
        lambda: dev_cases,
    )

    with pytest.raises(ValueError) as excinfo:
        EvaluationExecutionService.run_suite("dev")

    assert "Corpus base case count drift for suite 'dev'" in str(excinfo.value)
    assert "expected exactly 45, got 44" in str(excinfo.value)
    assert len(boundary_calls) == 0, "No boundary calls must occur on dev count drift"

    # 2. Sealed suite drift: 91 instead of 90
    sealed_cases = list(Simulator.generate_sealed_corpus()) + [Simulator.generate_sealed_corpus()[0]]
    monkeypatch.setitem(
        EvaluationExecutionService.SUITE_CONFIGS["sealed"],
        "generator",
        lambda: sealed_cases,
    )

    with pytest.raises(ValueError) as excinfo_sealed:
        EvaluationExecutionService.run_suite("sealed")

    assert "Corpus base case count drift for suite 'sealed'" in str(excinfo_sealed.value)
    assert "expected exactly 90, got 91" in str(excinfo_sealed.value)
    assert len(boundary_calls) == 0, "No boundary calls must occur on sealed count drift"

    # 3. Safety suite drift: 26 instead of 27
    safety_cases = Simulator.generate_safety_corpus()[:26]
    monkeypatch.setitem(
        EvaluationExecutionService.SUITE_CONFIGS["safety"],
        "generator",
        lambda: safety_cases,
    )

    with pytest.raises(ValueError) as excinfo_safety:
        EvaluationExecutionService.run_suite("safety")

    assert "Corpus base case count drift for suite 'safety'" in str(excinfo_safety.value)
    assert "expected exactly 27, got 26" in str(excinfo_safety.value)
    assert len(boundary_calls) == 0, "No boundary calls must occur on safety count drift"


def test_suite_execution_report_immutability_and_json_serialization():
    """Verify SuiteExecutionReport is completely frozen, sequences are tuples, mappings are FrozenDict, and JSON serializes normally."""
    report = EvaluationExecutionService.run_suite("dev")

    # 1. Top-level assignment raises pydantic.ValidationError
    with pytest.raises(pydantic.ValidationError):
        report.suite = "other"  # type: ignore

    with pytest.raises(pydantic.ValidationError):
        report.total_executions = 999  # type: ignore

    with pytest.raises(pydantic.ValidationError):
        report.product_boundary_call_count = 0  # type: ignore

    with pytest.raises(pydantic.ValidationError):
        report.exact_mismatches_count = 99  # type: ignore

    with pytest.raises(pydantic.ValidationError):
        report.category_counts = {}  # type: ignore

    with pytest.raises(pydantic.ValidationError):
        report.repetition_records = ()  # type: ignore

    with pytest.raises(pydantic.ValidationError):
        report.execution_records = ()  # type: ignore

    with pytest.raises(pydantic.ValidationError):
        report.strata_metrics = {}  # type: ignore

    with pytest.raises(pydantic.ValidationError):
        report.confusion_matrix = {}  # type: ignore

    # Top-level assignment on audit records raises pydantic.ValidationError
    rep_rec = report.repetition_records[0]
    with pytest.raises(pydantic.ValidationError):
        rep_rec.case_count = 0  # type: ignore

    with pytest.raises(pydantic.ValidationError):
        rep_rec.base_case_ids = ()  # type: ignore

    exec_rec = report.execution_records[0]
    with pytest.raises(pydantic.ValidationError):
        exec_rec.predicted_outcome = PolicyOutcome.BLOCKED  # type: ignore

    with pytest.raises(pydantic.ValidationError):
        exec_rec.is_unsafe_handoff = True  # type: ignore

    with pytest.raises(pydantic.ValidationError):
        exec_rec.predicted_reasons = ()  # type: ignore

    # 2. Tuple/list-style mutation is unavailable or blocked
    assert isinstance(report.execution_ids, tuple)
    assert isinstance(report.mismatched_execution_ids, tuple)
    assert isinstance(report.repetition_records, tuple)
    assert isinstance(report.execution_records, tuple)
    assert isinstance(report.repetitions, tuple)
    assert isinstance(report.executions, tuple)
    assert isinstance(report.results, tuple)
    assert isinstance(rep_rec.base_case_ids, tuple)
    assert isinstance(rep_rec.execution_ids, tuple)
    assert isinstance(exec_rec.predicted_reasons, tuple)

    assert not hasattr(report.execution_ids, "append")
    assert not hasattr(report.repetition_records, "pop")
    assert not hasattr(report.execution_records, "extend")
    assert not hasattr(rep_rec.base_case_ids, "append")
    assert not hasattr(exec_rec.predicted_reasons, "append")

    with pytest.raises(TypeError):
        report.execution_ids[0] = "mutated"  # type: ignore

    with pytest.raises(TypeError):
        rep_rec.base_case_ids[0] = "mutated"  # type: ignore

    # 3. Category/base mappings and nested confusion/strata mappings reject mutation
    with pytest.raises(TypeError):
        report.category_counts["TAMPERED"] = 100

    with pytest.raises(TypeError):
        report.category_counts.update({"TAMPERED": 100})

    with pytest.raises(TypeError):
        report.category_counts.clear()

    with pytest.raises(TypeError):
        first_cat = next(iter(report.category_counts))
        report.category_counts.pop(first_cat)

    with pytest.raises(TypeError):
        report.category_counts.popitem()

    with pytest.raises(TypeError):
        report.category_counts.setdefault("TAMPERED", 1)

    with pytest.raises(TypeError):
        first_cat = next(iter(report.category_counts))
        del report.category_counts[first_cat]

    with pytest.raises(TypeError):
        report.category_counts |= {"TAMPERED": 1}

    # report.category_counts.copy() returns immutable _FrozenDict
    cat_copy = report.category_counts.copy()
    assert isinstance(cat_copy, _FrozenDict)
    assert cat_copy is not report.category_counts
    assert cat_copy == report.category_counts
    with pytest.raises(TypeError):
        cat_copy["TAMPERED"] = 100
    with pytest.raises(TypeError):
        cat_copy.update({"TAMPERED": 100})
    with pytest.raises(TypeError):
        cat_copy.clear()

    with pytest.raises(TypeError):
        first_bc = next(iter(report.base_case_counts))
        report.base_case_counts[first_bc] = 999

    with pytest.raises(TypeError):
        report.base_case_counts.clear()

    with pytest.raises(TypeError):
        first_conf = next(iter(report.confusion_matrix))
        first_pred = next(iter(report.confusion_matrix[first_conf]))
        report.confusion_matrix[first_conf][first_pred] = 999

    with pytest.raises(TypeError):
        first_conf = next(iter(report.confusion_matrix))
        report.confusion_matrix[first_conf].clear()

    with pytest.raises(TypeError):
        report.confusion_matrix["BLOCKED"] = {}

    with pytest.raises(TypeError):
        first_strata = next(iter(report.strata_metrics))
        report.strata_metrics[first_strata]["three_action_accuracy"] = 0.0

    with pytest.raises(TypeError):
        first_strata = next(iter(report.strata_metrics))
        report.strata_metrics[first_strata].clear()

    with pytest.raises(TypeError):
        report.strata_metrics["DE"] = {}

    # 4. API JSON serialization yields normal lists and dicts
    data = report.model_dump(mode="json")
    assert type(data["execution_ids"]) is list
    assert type(data["mismatched_execution_ids"]) is list
    assert type(data["repetition_records"]) is list
    assert type(data["execution_records"]) is list
    assert type(data["category_counts"]) is dict
    assert type(data["base_case_counts"]) is dict
    assert type(data["confusion_matrix"]) is dict
    first_conf_key = next(iter(data["confusion_matrix"]))
    assert type(data["confusion_matrix"][first_conf_key]) is dict
    assert type(data["strata_metrics"]) is dict
    first_strata_key = next(iter(data["strata_metrics"]))
    assert type(data["strata_metrics"][first_strata_key]) is dict
    assert type(data["repetition_records"][0]["base_case_ids"]) is list
    assert type(data["repetition_records"][0]["execution_ids"]) is list
    assert type(data["execution_records"][0]["predicted_reasons"]) is list


def test_service_run_suite_empty_and_whitespace_case_id_fails_closed_without_boundary_calls(monkeypatch):
    """Enforce non-empty base case ID validation on expected-size corpora.

    Keeps corpus size exactly at expected count (45 for dev suite) so ID validation,
    not count drift guard, is exercised. Proves zero boundary calls occur.
    """
    import payoutproof.scorer.service as service_mod

    boundary_calls = []

    def spy_boundary(stimulus: RuntimeCaseInput, evaluation_time=None):
        boundary_calls.append(stimulus)
        return runner_module.execute_runtime_case(stimulus, evaluation_time=evaluation_time)

    monkeypatch.setattr(service_mod, "execute_runtime_case", spy_boundary)

    # (a) Empty case_id: exactly 45 cases
    dev_cases_empty = list(Simulator.generate_dev_corpus())
    assert len(dev_cases_empty) == 45
    dev_cases_empty[5] = dev_cases_empty[5].model_copy(update={"case_id": ""})
    assert len(dev_cases_empty) == 45

    monkeypatch.setitem(
        EvaluationExecutionService.SUITE_CONFIGS["dev"],
        "generator",
        lambda: dev_cases_empty,
    )

    with pytest.raises(ValueError) as excinfo_empty:
        EvaluationExecutionService.run_suite("dev")

    assert "Corpus contains invalid or empty base case ID at index 5" in str(excinfo_empty.value)
    assert len(boundary_calls) == 0, "No boundary calls must occur on empty case_id"

    # (b) Whitespace case_id: exactly 45 cases
    dev_cases_ws = list(Simulator.generate_dev_corpus())
    assert len(dev_cases_ws) == 45
    dev_cases_ws[12] = dev_cases_ws[12].model_copy(update={"case_id": "   \t\n  "})
    assert len(dev_cases_ws) == 45

    monkeypatch.setitem(
        EvaluationExecutionService.SUITE_CONFIGS["dev"],
        "generator",
        lambda: dev_cases_ws,
    )

    with pytest.raises(ValueError) as excinfo_ws:
        EvaluationExecutionService.run_suite("dev")

    assert "Corpus contains invalid or empty base case ID at index 12" in str(excinfo_ws.value)
    assert len(boundary_calls) == 0, "No boundary calls must occur on whitespace case_id"


def test_service_run_suite_duplicate_case_ids_fails_closed_without_boundary_calls(monkeypatch):
    """Enforce base case ID uniqueness validation on expected-size corpora.

    Keeps corpus size exactly at expected count (45 for dev suite) so ID uniqueness,
    not count drift guard, is exercised. Proves zero boundary calls occur.
    """
    import payoutproof.scorer.service as service_mod

    boundary_calls = []

    def spy_boundary(stimulus: RuntimeCaseInput, evaluation_time=None):
        boundary_calls.append(stimulus)
        return runner_module.execute_runtime_case(stimulus, evaluation_time=evaluation_time)

    monkeypatch.setattr(service_mod, "execute_runtime_case", spy_boundary)

    # Dev suite: exactly 45 cases, with duplicate base case ID at index 7 matching index 0
    dev_cases = list(Simulator.generate_dev_corpus())
    assert len(dev_cases) == 45
    target_duplicate_id = dev_cases[0].case_id
    dev_cases[7] = dev_cases[7].model_copy(update={"case_id": target_duplicate_id})
    assert len(dev_cases) == 45

    monkeypatch.setitem(
        EvaluationExecutionService.SUITE_CONFIGS["dev"],
        "generator",
        lambda: dev_cases,
    )

    with pytest.raises(ValueError) as excinfo:
        EvaluationExecutionService.run_suite("dev")

    assert "Corpus base case IDs must be unique within suite 'dev'" in str(excinfo.value)
    assert len(boundary_calls) == 0, "No boundary calls must occur on duplicate case IDs"


def test_frozendict_copy_and_pickle_contracts():
    """Verify _FrozenDict standalone copy, deepcopy, pickle, and mutation rejection."""
    nested = _FrozenDict({"sub": 10})
    fd = _FrozenDict({"a": 1, "b": 2, "nested": nested})

    # .copy() returns immutable _FrozenDict
    copied = fd.copy()
    assert isinstance(copied, _FrozenDict)
    assert copied is not fd
    assert copied == fd
    with pytest.raises(TypeError):
        copied["a"] = 99
    with pytest.raises(TypeError):
        copied.update({"a": 99})
    with pytest.raises(TypeError):
        copied.clear()
    with pytest.raises(TypeError):
        copied.pop("a")
    with pytest.raises(TypeError):
        copied.popitem()
    with pytest.raises(TypeError):
        copied.setdefault("c", 3)
    with pytest.raises(TypeError):
        del copied["a"]
    with pytest.raises(TypeError):
        copied |= {"c": 3}

    # copy.copy()
    shallow = copy.copy(fd)
    assert isinstance(shallow, _FrozenDict)
    assert shallow is not fd
    assert shallow == fd
    with pytest.raises(TypeError):
        shallow["a"] = 99

    # copy.deepcopy() with nested immutability
    deep = copy.deepcopy(fd)
    assert isinstance(deep, _FrozenDict)
    assert deep is not fd
    assert deep == fd
    assert isinstance(deep["nested"], _FrozenDict)
    assert deep["nested"] is not nested
    with pytest.raises(TypeError):
        deep["nested"]["sub"] = 99

    # Deepcopy memo handles shared references and preserves identity
    shared = _FrozenDict({"shared_val": 42})
    container = _FrozenDict({"first": shared, "second": shared})
    memo_copied = copy.deepcopy(container)
    assert memo_copied["first"] is memo_copied["second"]
    assert memo_copied["first"] is not shared
    assert isinstance(memo_copied["first"], _FrozenDict)
    with pytest.raises(TypeError):
        memo_copied["first"]["shared_val"] = 99

    # Pickle round-trip across all protocols
    for proto in range(pickle.HIGHEST_PROTOCOL + 1):
        dumped = pickle.dumps(fd, protocol=proto)
        loaded = pickle.loads(dumped)
        assert isinstance(loaded, _FrozenDict)
        assert isinstance(loaded["nested"], _FrozenDict)
        assert loaded == fd
        with pytest.raises(TypeError):
            loaded["a"] = 99
        with pytest.raises(TypeError):
            loaded["nested"]["sub"] = 99


def test_suite_execution_report_copy_pickle_and_immutability_contracts():
    """Verify SuiteExecutionReport copy, deepcopy, model_copy, and pickle contracts.

    Asserts:
    - report.model_copy(deep=True) succeeds and yields a distinct report with equal data
      and deeply immutable mappings/tuples.
    - copy.copy(report) and copy.deepcopy(report) succeed.
    - pickle.loads(pickle.dumps(report)) succeeds across protocols.
    - Every copied/unpickled report still rejects top-level, tuple, outer mapping,
      and nested mapping mutation.
    - report.category_counts.copy() returns immutable _FrozenDict.
    - API JSON/model_dump behavior stays unchanged.
    """
    report = EvaluationExecutionService.run_suite("dev")

    # 1. model_copy(deep=True) produces independent report with deeply immutable mappings
    c_model = report.model_copy(deep=True)
    assert c_model is not report
    assert c_model == report
    assert c_model.category_counts is not report.category_counts
    assert c_model.base_case_counts is not report.base_case_counts
    assert c_model.confusion_matrix is not report.confusion_matrix
    sample_conf = next(iter(report.confusion_matrix))
    sample_pred = next(iter(report.confusion_matrix[sample_conf]))
    assert c_model.confusion_matrix[sample_conf] is not report.confusion_matrix[sample_conf]
    assert isinstance(c_model.category_counts, _FrozenDict)
    assert isinstance(c_model.base_case_counts, _FrozenDict)
    assert isinstance(c_model.confusion_matrix, _FrozenDict)
    assert isinstance(c_model.confusion_matrix[sample_conf], _FrozenDict)
    assert isinstance(c_model.strata_metrics, _FrozenDict)
    sample_strata = next(iter(report.strata_metrics))
    assert isinstance(c_model.strata_metrics[sample_strata], _FrozenDict)
    assert isinstance(c_model.execution_ids, tuple)
    assert isinstance(c_model.repetition_records, tuple)
    assert isinstance(c_model.execution_records, tuple)

    # 2. copy.copy(report) and copy.deepcopy(report) succeed
    c_copy = copy.copy(report)
    assert c_copy is not report
    assert c_copy == report

    c_deep = copy.deepcopy(report)
    assert c_deep is not report
    assert c_deep == report
    assert c_deep.category_counts is not report.category_counts
    assert c_deep.base_case_counts is not report.base_case_counts
    assert c_deep.confusion_matrix is not report.confusion_matrix
    assert c_deep.confusion_matrix[sample_conf] is not report.confusion_matrix[sample_conf]
    assert isinstance(c_deep.category_counts, _FrozenDict)
    assert isinstance(c_deep.confusion_matrix, _FrozenDict)
    assert isinstance(c_deep.confusion_matrix[sample_conf], _FrozenDict)
    assert isinstance(c_deep.strata_metrics, _FrozenDict)
    assert isinstance(c_deep.strata_metrics[sample_strata], _FrozenDict)

    # 3. pickle round-trip across all protocols
    for proto in range(pickle.HIGHEST_PROTOCOL + 1):
        dumped = pickle.dumps(report, protocol=proto)
        c_pickle = pickle.loads(dumped)
        assert c_pickle is not report
        assert c_pickle == report
        assert c_pickle.category_counts is not report.category_counts
        assert c_pickle.confusion_matrix is not report.confusion_matrix
        assert c_pickle.confusion_matrix[sample_conf] is not report.confusion_matrix[sample_conf]
        assert isinstance(c_pickle.category_counts, _FrozenDict)
        assert isinstance(c_pickle.base_case_counts, _FrozenDict)
        assert isinstance(c_pickle.confusion_matrix, _FrozenDict)
        assert isinstance(c_pickle.confusion_matrix[sample_conf], _FrozenDict)
        assert isinstance(c_pickle.strata_metrics, _FrozenDict)
        assert isinstance(c_pickle.strata_metrics[sample_strata], _FrozenDict)

    # 4. Every copied/unpickled report rejects top-level, tuple, outer mapping, and nested mapping mutation
    for rep in [c_model, c_copy, c_deep, c_pickle]:
        # Top-level assignment raises pydantic.ValidationError
        with pytest.raises(pydantic.ValidationError):
            rep.total_executions = 999  # type: ignore
        with pytest.raises(pydantic.ValidationError):
            rep.suite = "other"  # type: ignore

        # Tuple mutation raises TypeError
        with pytest.raises(TypeError):
            rep.execution_ids[0] = "mutated"  # type: ignore
        with pytest.raises(TypeError):
            rep.repetition_records[0].base_case_ids[0] = "mutated"  # type: ignore

        # Outer mapping mutation raises TypeError
        with pytest.raises(TypeError):
            rep.category_counts["NEW_KEY"] = 100
        with pytest.raises(TypeError):
            rep.category_counts.update({"NEW_KEY": 100})
        with pytest.raises(TypeError):
            rep.category_counts.clear()
        first_cat = next(iter(rep.category_counts))
        with pytest.raises(TypeError):
            rep.category_counts.pop(first_cat)
        with pytest.raises(TypeError):
            rep.category_counts.popitem()
        with pytest.raises(TypeError):
            rep.category_counts.setdefault("NEW_KEY", 1)
        with pytest.raises(TypeError):
            del rep.category_counts[first_cat]
        with pytest.raises(TypeError):
            rep.category_counts |= {"NEW_KEY": 1}

        # Nested mapping mutation raises TypeError
        with pytest.raises(TypeError):
            rep.confusion_matrix[sample_conf][sample_pred] = 999
        with pytest.raises(TypeError):
            rep.confusion_matrix[sample_conf].clear()
        with pytest.raises(TypeError):
            rep.confusion_matrix["NEW_OUTCOME"] = {}
        with pytest.raises(TypeError):
            rep.strata_metrics[sample_strata]["three_action_accuracy"] = 0.0
        with pytest.raises(TypeError):
            rep.strata_metrics[sample_strata].clear()
        with pytest.raises(TypeError):
            rep.strata_metrics["NEW_STRATA"] = {}

    # 5. report.category_counts.copy() returns immutable _FrozenDict
    cat_copy = report.category_counts.copy()
    assert isinstance(cat_copy, _FrozenDict)
    assert cat_copy is not report.category_counts
    assert cat_copy == report.category_counts
    with pytest.raises(TypeError):
        cat_copy["TAMPERED"] = 100
    with pytest.raises(TypeError):
        cat_copy.update({"TAMPERED": 100})
    with pytest.raises(TypeError):
        cat_copy.clear()
    with pytest.raises(TypeError):
        cat_copy.pop(next(iter(cat_copy)))
    with pytest.raises(TypeError):
        cat_copy.popitem()
    with pytest.raises(TypeError):
        cat_copy.setdefault("TAMPERED", 1)
    with pytest.raises(TypeError):
        del cat_copy[next(iter(cat_copy))]
    with pytest.raises(TypeError):
        cat_copy |= {"TAMPERED": 1}

    # 6. API JSON/model_dump behavior stays unchanged
    d_orig = report.model_dump(mode="json")
    d_model = c_model.model_dump(mode="json")
    d_copy = c_copy.model_dump(mode="json")
    d_deep = c_deep.model_dump(mode="json")
    d_pickle = c_pickle.model_dump(mode="json")

    assert d_orig == d_model == d_copy == d_deep == d_pickle
    assert type(d_orig["category_counts"]) is dict
    assert type(d_orig["confusion_matrix"]) is dict
    assert type(d_orig["confusion_matrix"][sample_conf]) is dict
    assert type(d_orig["strata_metrics"]) is dict
    assert type(d_orig["strata_metrics"][sample_strata]) is dict
    assert type(d_orig["execution_ids"]) is list
    assert type(d_orig["repetition_records"]) is list
    assert type(d_orig["execution_records"]) is list
    assert report.model_dump_json() == c_model.model_dump_json() == c_deep.model_dump_json() == c_pickle.model_dump_json()
