"""Execution runner for evaluation cases.

The product execution boundary lives in `execute_runtime_case`: it accepts only
`RuntimeCaseInput` (runtime-observable stimulus, no evaluator metadata or answer
labels) and returns product-observed diagnostics. Oracle comparison is a separate
step (`_score_case_against_oracle`) that imports the oracle locally and runs only
after the product execution has returned, so product execution can never depend
on evaluator truth.
"""

from datetime import datetime, timezone
from pathlib import Path
import tempfile
from typing import List, Optional

from pydantic import BaseModel, ConfigDict

from payoutproof.core.models import (
    RiskCaseState,
    PaymentIntent,
    Finding,
    CaseInvestigation,
    ProcessingAuthorityRecord,
    EvidenceItem,
)
from payoutproof.core.enums import (
    PolicyOutcome,
    TruthState,
    IntentStatus,
    DestinationStatus,
    FindingName,
    CasePhase,
    ProcessingAuthorityStatus,
    GrantStatus,
    AdapterDecision,
    ReasonCode,
)
from payoutproof.simulator.generator import EvaluationCase, RuntimeCaseInput
from payoutproof.scorer.scorer import EvaluationResult
from payoutproof.policy.evaluator import PolicyGate
from payoutproof.intent.extractor import confirm_intent, extract_intent_from_structured_data
from payoutproof.core.crypto import compute_intent_hash
from payoutproof.core.providers import FixedClock
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.storage.db import Database
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter

# Deterministic default evaluation instant, so repeated benchmark runs are
# reproducible; callers may inject a different time where a test needs to
# exercise time-dependent policy behavior.
FIXED_EVALUATION_TIME = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

# Evaluator-only deterministic signing and audit secrets for isolated benchmark execution
_EVALUATOR_GRANT_SECRET = "evaluator-deterministic-grant-secret-32-chars-long"
_EVALUATOR_AUDIT_SECRET = "evaluator-deterministic-audit-secret-32-chars-long"


class RuntimeCaseDiagnostics(BaseModel):
    """Product-observed execution result for one runtime case.

    Carries only what the product itself observed: the executed case state and
    the Policy Gate evaluation of that state. It never contains evaluator truth
    or answer labels. `predicted_outcome` is None when the case was rejected at
    admission: per CONTEXT.md, Admission Rejection never reaches policy
    evaluation, so there is no Policy Outcome to report — and none may be
    invented by, for example, mapping it to BLOCKED.
    """
    model_config = ConfigDict(frozen=True)

    state: RiskCaseState
    predicted_outcome: Optional[PolicyOutcome]
    predicted_reasons: List[str]
    is_intent_binding_correct: bool
    observed_intent_binding: Optional[bool] = None
    model_status: str
    intent_status: str


def _build_authority_record() -> ProcessingAuthorityRecord:
    """Valid synthetic processing authority for benchmark execution."""
    return ProcessingAuthorityRecord(
        data_class="SYNTHETIC_VOICE_AND_TEXT",
        source="BENCHMARK_SIMULATOR",
        subject_category="VENDOR",
        submitter="Benchmark Runner",
        purpose="Evaluation benchmark execution",
        asserted_authority_ref="AUTH-BENCHMARK-2026",
        permitted_uses=["INTENT_EXTRACTION", "POLICY_EVALUATION"],
        processing_route="LOCAL_ONLY",
        redaction_declaration="SYNTHETIC_NO_PII",
        retention_days=7,
        legal_hold=False,
        restrictions=[],
        is_valid=True,
    )


def _build_runtime_state(runtime_case: RuntimeCaseInput, evaluation_time: datetime) -> RiskCaseState:
    """Assemble the RiskCaseState the product observes for this stimulus.

    `evaluation_time` is the same instant `execute_runtime_case` resolved and
    passed to the Policy Gate, so every evidence item is admitted at exactly
    that injected/fixed time. Two identical executions therefore produce
    identical evidence — and identical evaluated snapshot hashes — instead of
    inheriting the wall clock.
    """
    # 1. Check admission / tamper
    if runtime_case.is_tampered:
        req_status = "TAMPERED"
        pa_status = ProcessingAuthorityStatus.VALID
        auth_record = _build_authority_record()
        evidence = [EvidenceItem(
            id=f"EV-{runtime_case.case_id}-01",
            item_type="VOICE_AND_TEXT_BUNDLE",
            title=f"Evaluation evidence for {runtime_case.case_id}",
            content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            admitted_at=evaluation_time.isoformat(),
            finding="admitted",
            truth_state=TruthState.SUPPORTED,
        )]
        phase = CasePhase.INVESTIGATION
    elif runtime_case.is_unauthorized:
        req_status = "REJECTED"
        pa_status = ProcessingAuthorityStatus.REJECTED
        auth_record = None
        evidence = []
        phase = CasePhase.ADMISSION_REJECTED
    else:
        req_status = "ADMITTED"
        pa_status = ProcessingAuthorityStatus.VALID
        auth_record = _build_authority_record()
        evidence = [EvidenceItem(
            id=f"EV-{runtime_case.case_id}-01",
            item_type="VOICE_AND_TEXT_BUNDLE",
            title=f"Evaluation evidence for {runtime_case.case_id}",
            content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            admitted_at=evaluation_time.isoformat(),
            finding="admitted",
            truth_state=TruthState.SUPPORTED,
        )]
        phase = CasePhase.INVESTIGATION

    # 2. Build extracted intent using canonical extractor & confirm if the
    # model run produced a usable structured signal.
    raw_intent = extract_intent_from_structured_data({
        "counterparty": runtime_case.counterparty,
        "destination": runtime_case.destination,
        "destination_status": runtime_case.destination_status,
        "amount": runtime_case.amount,
        "currency": runtime_case.currency,
        "purpose": runtime_case.purpose,
        "instruction_reference": runtime_case.instruction_ref,
    })
    raw_intent = raw_intent.model_copy(update={"destination_status": runtime_case.destination_status})

    model_status = "SUCCEEDED"
    if runtime_case.is_unusable_audio:
        # Unusable media: no structured signal, no confirmable intent.
        intent = raw_intent
        model_status = "FAILED_UNUSABLE_AUDIO"
    elif runtime_case.is_schema_failure:
        # Model output violated the strict extraction schema, which is a
        # distinct failure mode from unusable audio: no confirmed intent exists.
        intent = raw_intent
        model_status = "FAILED_SCHEMA_ERROR"
    else:
        intent = confirm_intent(raw_intent)
        if runtime_case.has_material_intent_error:
            # Represent the detected material intent inconsistency in the case
            # state itself and let the Policy Gate derive the outcome.
            if runtime_case.intent_error_mode == "HASH_MISMATCH":
                # The frozen intent hash was recorded over different material
                # content; recomputing over the confirmed intent cannot
                # reproduce it, so the binding is inconsistent. The mutated
                # amount must always differ from the runtime amount — a
                # hardcoded "1" would silently reproduce the real hash when
                # the runtime amount is itself "1" and the mismatch would
                # disappear.
                mutated_amount = "1" if runtime_case.amount != "1" else "2"
                variant = intent.model_copy(update={"amount": mutated_amount})
                intent = intent.model_copy(update={"intent_hash": compute_intent_hash(variant)})
            else:
                # The previously confirmed intent was invalidated.
                intent = intent.model_copy(update={"status": IntentStatus.INVALIDATED})

    # 3. Build findings
    findings = []
    if runtime_case.has_contradiction:
        findings.append(Finding(name=FindingName.DESTINATION_CONSISTENCY.value, truth_state=TruthState.CONTRADICTED, detail="Invoice mismatch"))
    if runtime_case.has_callback:
        findings.append(Finding(name=FindingName.INDEPENDENT_CALLBACK.value, truth_state=TruthState.SUPPORTED, detail="Callback confirmed"))
    org_id = getattr(runtime_case, "organization_id", None) or "org_evaluation_synthetic"
    if runtime_case.has_destination_approval or runtime_case.destination_status == DestinationStatus.APPROVED_FOR_COUNTERPARTY:
        findings.append(Finding(name=FindingName.DESTINATION_APPROVAL.value, truth_state=TruthState.SUPPORTED, detail="Approved", organization_id=org_id))

    state = RiskCaseState(
        case_id=runtime_case.case_id,
        organization_id=org_id,
        case_version=1 if req_status == "ADMITTED" else 0,
        phase=phase,
        processing_authority=pa_status,
        authority_record=auth_record,
        request_bundle_status=req_status,
        evidence=evidence,
        intent=intent,
        findings=findings,
        investigation=CaseInvestigation(model_status=model_status),
    )
    return state


def _execute_mutation_after_grant(
    runtime_case: RuntimeCaseInput,
    eval_dt: datetime,
) -> RuntimeCaseDiagnostics:
    fixed_clock = FixedClock(eval_dt)
    initial_state = _build_runtime_state(runtime_case, eval_dt)

    # 1. Initial PolicyGate evaluation
    init_eval = PolicyGate.evaluate(initial_state, evaluation_time=eval_dt)
    ready_state = initial_state.model_copy(update={
        "policy": init_eval,
        "phase": (
            CasePhase.READY_FOR_HUMAN_HANDOFF
            if init_eval.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
            else CasePhase.OPERATOR_INTERVENTION
        ),
    })

    # 2. Real StateMachine ISSUE_GRANT
    granted_state = StateMachine.reduce(
        ready_state,
        {"type": "ISSUE_GRANT", "payload": {}},
        grant_secret=_EVALUATOR_GRANT_SECRET,
        clock=fixed_clock,
    )

    # 3. Real StateMachine EDIT_AMOUNT with a guaranteed-different amount
    current_amt = granted_state.intent.amount or "500000"
    mutated_amt = "600000" if current_amt != "600000" else "700000"
    mutated_state = StateMachine.reduce(
        granted_state,
        {"type": "EDIT_AMOUNT", "payload": {"amount": mutated_amt}},
        clock=fixed_clock,
    )

    eval_res = mutated_state.policy
    predicted_reasons = [r.value if hasattr(r, "value") else str(r) for r in eval_res.reasons]
    is_ib_correct = (
        mutated_state.intent.status == IntentStatus.CONFIRMED
        and compute_intent_hash(mutated_state.intent) == mutated_state.intent.intent_hash
        and mutated_state.intent.counterparty == runtime_case.counterparty
        and mutated_state.intent.amount == runtime_case.amount
        and mutated_state.intent.destination == runtime_case.destination
    )
    intent_status = (
        mutated_state.intent.status.value
        if hasattr(mutated_state.intent.status, "value")
        else str(mutated_state.intent.status)
    )

    return RuntimeCaseDiagnostics(
        state=mutated_state,
        predicted_outcome=eval_res.outcome,
        predicted_reasons=predicted_reasons,
        is_intent_binding_correct=is_ib_correct,
        model_status=mutated_state.investigation.model_status,
        intent_status=intent_status,
    )


def _execute_replay_after_storage_restart(
    runtime_case: RuntimeCaseInput,
    eval_dt: datetime,
) -> RuntimeCaseDiagnostics:
    fixed_clock = FixedClock(eval_dt)
    open_conns = []
    first_db_conns = []

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "cat8_replay.db"
        db = Database(db_path=db_path, audit_checkpoint_secret=_EVALUATOR_AUDIT_SECRET)

        orig_conn = db.get_connection
        def _get_conn(*args, **kwargs):
            c = orig_conn(*args, **kwargs)
            first_db_conns.append(c)
            open_conns.append(c)
            return c
        db.get_connection = _get_conn

        try:
            initial_state = _build_runtime_state(runtime_case, eval_dt)

            init_eval = PolicyGate.evaluate(initial_state, evaluation_time=eval_dt)
            ready_state = initial_state.model_copy(update={
                "policy": init_eval,
                "phase": (
                    CasePhase.READY_FOR_HUMAN_HANDOFF
                    if init_eval.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
                    else CasePhase.OPERATOR_INTERVENTION
                ),
            })

            granted_state = StateMachine.reduce(
                ready_state,
                {"type": "ISSUE_GRANT", "payload": {}},
                grant_secret=_EVALUATOR_GRANT_SECRET,
                clock=None,
            )

            db.save_case(granted_state)

            adapter = FakeApprovalRailAdapter(
                db=db,
                grant_secret=_EVALUATOR_GRANT_SECRET,
                audit_checkpoint_secret=_EVALUATOR_AUDIT_SECRET,
            )
            decision1, item1, err1 = adapter.submit_handoff(
                grant=granted_state.grant,
                intent=granted_state.intent,
            )
            if decision1 != AdapterDecision.PENDING_ITEM_CREATED or item1 is None:
                raise RuntimeError(f"First handoff failed unexpectedly: {decision1} ({err1})")

            pending_items_1 = db.get_all_pending_items()
            if len(pending_items_1) != 1 or granted_state.grant.grant_id not in db.get_consumed_grant_ids():
                raise RuntimeError("First handoff did not create exactly one pending item or consume grant")

            # Explicitly close every first-Database connection before constructing second Database/adapter
            for conn in first_db_conns:
                try:
                    conn.close()
                except Exception:
                    pass

            def _closed_get_conn(*args, **kwargs):
                raise RuntimeError("First Database closed; connections cannot be reused across storage restart")
            db.get_connection = _closed_get_conn
            db = None
            adapter = None

            db2 = Database(db_path=db_path, audit_checkpoint_secret=_EVALUATOR_AUDIT_SECRET)
            orig_conn2 = db2.get_connection
            def _get_conn2(*args, **kwargs):
                c = orig_conn2(*args, **kwargs)
                open_conns.append(c)
                return c
            db2.get_connection = _get_conn2

            adapter2 = FakeApprovalRailAdapter(
                db=db2,
                grant_secret=_EVALUATOR_GRANT_SECRET,
                audit_checkpoint_secret=_EVALUATOR_AUDIT_SECRET,
            )

            decision2, item2, err2 = adapter2.submit_handoff(
                grant=granted_state.grant,
                intent=granted_state.intent,
            )
            if decision2 != AdapterDecision.REPLAY_REJECTED or item2 is not None:
                raise RuntimeError(f"Replay was not rejected: {decision2}")

            pending_items_2 = db2.get_all_pending_items()
            if len(pending_items_2) != 1 or granted_state.grant.grant_id not in db2.get_consumed_grant_ids():
                raise RuntimeError("Replay altered pending items or consumed grant state")

            persisted_case = db2.load_case(granted_state.case_id)
            replayed_state = StateMachine.apply_adapter_decision(
                state=persisted_case,
                decision=decision2,
                error_message=err2,
                clock=fixed_clock,
            )
            eval_res = PolicyGate.evaluate(replayed_state, evaluation_time=eval_dt)
            final_state = replayed_state.model_copy(update={"policy": eval_res})
            db2.save_case(final_state)

        finally:
            for conn in open_conns:
                try:
                    conn.close()
                except Exception:
                    pass

    predicted_reasons = [r.value if hasattr(r, "value") else str(r) for r in eval_res.reasons]
    is_ib_correct = (
        final_state.intent.status == IntentStatus.CONFIRMED
        and compute_intent_hash(final_state.intent) == final_state.intent.intent_hash
        and final_state.intent.counterparty == runtime_case.counterparty
        and final_state.intent.amount == runtime_case.amount
        and final_state.intent.destination == runtime_case.destination
    )
    intent_status = (
        final_state.intent.status.value
        if hasattr(final_state.intent.status, "value")
        else str(final_state.intent.status)
    )

    return RuntimeCaseDiagnostics(
        state=final_state,
        predicted_outcome=eval_res.outcome,
        predicted_reasons=predicted_reasons,
        is_intent_binding_correct=is_ib_correct,
        model_status=final_state.investigation.model_status,
        intent_status=intent_status,
    )


def execute_runtime_case(
    runtime_case: RuntimeCaseInput,
    evaluation_time: Optional[datetime] = None,
) -> RuntimeCaseDiagnostics:
    """Execute one runtime case through the PayoutProof product boundary.

    Accepts only `RuntimeCaseInput`; anything carrying evaluator metadata or
    answer labels is rejected. Returns product-observed state and the Policy
    Gate evaluation of that state.
    """
    if not isinstance(runtime_case, RuntimeCaseInput):
        raise TypeError(
            "execute_runtime_case accepts only RuntimeCaseInput; sanitize the "
            "case stimulus with to_runtime_input() before execution"
        )

    eval_dt = evaluation_time if evaluation_time is not None else FIXED_EVALUATION_TIME
    if runtime_case.mutate_amount_after_grant:
        return _execute_mutation_after_grant(runtime_case, eval_dt)
    if runtime_case.replay_grant_after_storage_restart:
        return _execute_replay_after_storage_restart(runtime_case, eval_dt)

    state = _build_runtime_state(runtime_case, eval_dt)
    eval_res = PolicyGate.evaluate(state, evaluation_time=eval_dt)

    predicted_reasons = [r.value if hasattr(r, "value") else str(r) for r in eval_res.reasons]
    # Intent binding is correct only when the intent is confirmed, the
    # recomputed hash reproduces the frozen hash, and every material field
    # still matches the runtime stimulus. Matching fields alone must never
    # report a correct binding for material-intent-error stimuli (invalidated
    # or hash-mismatched) or for failed extractions.
    is_ib_correct = (
        state.intent.status == IntentStatus.CONFIRMED
        and compute_intent_hash(state.intent) == state.intent.intent_hash
        and state.intent.counterparty == runtime_case.counterparty
        and state.intent.amount == runtime_case.amount
        and state.intent.destination == runtime_case.destination
    )
    intent_status = state.intent.status.value if hasattr(state.intent.status, "value") else str(state.intent.status)

    return RuntimeCaseDiagnostics(
        state=state,
        predicted_outcome=eval_res.outcome,
        predicted_reasons=predicted_reasons,
        is_intent_binding_correct=is_ib_correct,
        model_status=state.investigation.model_status,
        intent_status=intent_status,
    )


class AdmissionRejectedScoringError(ValueError):
    """Raised when the scoring wrapper is handed an admission-rejected case.

    Admission Rejection produces no Policy Outcome (`predicted_outcome=None`),
    which the benchmark `EvaluationResult` cannot represent. This is an
    explicit scoring-boundary limitation: it must surface only here, when
    someone attempts to score an admission-rejected fixture — never during
    product execution, which succeeds and reports the rejection as None.
    """


def _score_case_against_oracle(case: EvaluationCase, diagnostics: RuntimeCaseDiagnostics) -> EvaluationResult:
    """Compare product-observed diagnostics against independent oracle truth.

    Runs only after `execute_runtime_case` has returned. The oracle import is
    local to this function so the execution boundary above can never depend on
    it, and the oracle computes expected outcomes from scenario truth rather
    than from the case's recorded answer labels.
    """
    if diagnostics.predicted_outcome is None:
        raise AdmissionRejectedScoringError(
            f"cannot score admission-rejected case {case.case_id}: it produced "
            "no Policy Outcome, and EvaluationResult cannot represent None"
        )

    from payoutproof.oracle.oracle import PolicyOracle

    gold_out, _ = PolicyOracle.evaluate_expected(case)
    predicted = diagnostics.predicted_outcome

    is_unsafe = (predicted == PolicyOutcome.ELIGIBLE_FOR_HANDOFF and gold_out != PolicyOutcome.ELIGIBLE_FOR_HANDOFF)
    is_exact = (predicted == gold_out)
    is_abstain_correct = (predicted in (PolicyOutcome.HOLD, PolicyOutcome.STEP_UP_REQUIRED, PolicyOutcome.BLOCKED)) if gold_out != PolicyOutcome.ELIGIBLE_FOR_HANDOFF else True

    expected_ib = PolicyOracle.expected_intent_binding(case)
    is_ib_correct = (diagnostics.is_intent_binding_correct == expected_ib)

    return EvaluationResult(
        case_id=case.case_id,
        suite=case.suite,
        language=case.language,
        gold_outcome=gold_out,
        predicted_outcome=predicted,
        is_unsafe_handoff=is_unsafe,
        is_exact_match=is_exact,
        is_intent_binding_correct=is_ib_correct,
        observed_intent_binding=diagnostics.is_intent_binding_correct,
        expected_intent_binding=expected_ib,
        is_correct_abstention=is_abstain_correct,
        simulated_no_tool_interactions=case.simulated_no_tool_interactions,
        simulated_tool_interactions=case.simulated_tool_interactions,
    )


def execute_case_under_test(case: EvaluationCase, evaluation_time: Optional[datetime] = None) -> EvaluationResult:
    """Compatibility orchestration: sanitize, execute the product, then score independently."""
    diagnostics = execute_runtime_case(case.to_runtime_input(), evaluation_time=evaluation_time)
    return _score_case_against_oracle(case, diagnostics)
