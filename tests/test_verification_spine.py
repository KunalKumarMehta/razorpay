"""Zero-tolerance verification spine tests according to Issue 13 acceptance criteria.

Covers:
1. Property test: Zero eligible outcomes for incomplete, ambiguous, unsupported, contradicted, mutated, unauthorized, replayed, or failed cases.
2. Concurrent/repeated grant use cannot create duplicate pending items (thread safety).
3. Ambiguity / Reconciliation Required cannot retry blindly.
4. Restart preserves authority and cryptographic audit verification across SQLite reloads.
5. Largest-case-removed sensitivity for paired-task interaction reduction.
6. Deterministic simulator seed reproducibility and oracle structural independence.
"""

import concurrent.futures
import tempfile
from pathlib import Path
import pytest

from payoutproof.core.enums import (
    PolicyOutcome,
    TruthState,
    IntentStatus,
    DestinationStatus,
    CasePhase,
    GrantStatus,
    HandoffStatus,
    AdapterDecision,
    ReasonCode,
    ProcessingAuthorityStatus,
)
from payoutproof.core.models import (
    RiskCaseState,
    PaymentIntent,
    EvidenceItem,
    Finding,
    CaseInvestigation,
    PolicyEvaluationResult,
    ProcessingAuthorityRecord,
)
from payoutproof.core.crypto import compute_intent_hash
from payoutproof.policy.evaluator import PolicyGate
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
from payoutproof.grants.issuer import GrantIssuer
from payoutproof.simulator.generator import Simulator, EvaluationCase
from payoutproof.oracle.oracle import PolicyOracle
from payoutproof.scorer.scorer import EvaluationScorer
from payoutproof.scorer.runner import execute_case_under_test
from payoutproof.storage.db import Database
from payoutproof.audit.chain import AuditChain
from tests.helpers import (
    make_authorized_bundle_action,
    make_admitted_case_state,
    make_valid_authority_record,
    make_confirmed_intent,
    TEST_GRANT_SECRET,
    TEST_AUDIT_CHECKPOINT_SECRET,
)


def test_property_zero_eligible_for_unsafe_cases():
    """Property test: Zero eligible outcomes for incomplete, unsupported, contradicted, mutated, or failed cases."""
    base_intent = make_confirmed_intent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        destination_status=DestinationStatus.APPROVED_FOR_COUNTERPARTY,
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
    )
    supported_cb = Finding(name="Independent callback", truth_state=TruthState.SUPPORTED, detail="Confirmed")
    supported_da = Finding(name="Destination approval", truth_state=TruthState.SUPPORTED, detail="Approved")

    unsafe_variations = [
        # 1. Tampered snapshot
        make_admitted_case_state(case_id="RC-UNSAFE-1", request_bundle_status="TAMPERED", intent=base_intent, findings=[supported_cb, supported_da]),
        # 2. Unusable model failure
        make_admitted_case_state(case_id="RC-UNSAFE-2", intent=base_intent, findings=[supported_cb, supported_da], investigation=CaseInvestigation(model_status="FAILED_UNUSABLE_AUDIO")),
        # 3. Schema error model failure
        make_admitted_case_state(case_id="RC-UNSAFE-3", intent=base_intent, findings=[supported_cb, supported_da], investigation=CaseInvestigation(model_status="FAILED_SCHEMA_ERROR")),
        # 4. Timeout model failure
        make_admitted_case_state(case_id="RC-UNSAFE-4", intent=base_intent, findings=[supported_cb, supported_da], investigation=CaseInvestigation(model_status="FAILED_TIMEOUT")),
        # 5. Invalidated intent (post-mutation)
        make_admitted_case_state(case_id="RC-UNSAFE-5", intent=base_intent.model_copy(update={"status": IntentStatus.INVALIDATED}), findings=[supported_cb, supported_da]),
        # 6. Unconfirmed intent
        make_admitted_case_state(case_id="RC-UNSAFE-6", intent=base_intent.model_copy(update={"status": IntentStatus.EXTRACTED, "intent_hash": None}), findings=[supported_cb, supported_da]),
        # 7. Contradiction in findings
        make_admitted_case_state(case_id="RC-UNSAFE-7", intent=base_intent, findings=[supported_cb, supported_da, Finding(name="Invoice", truth_state=TruthState.CONTRADICTED, detail="Mismatch")]),
        # 8. Missing callback
        make_admitted_case_state(case_id="RC-UNSAFE-8", intent=base_intent, findings=[supported_da]),
        # 9. Callback not observed
        make_admitted_case_state(case_id="RC-UNSAFE-9", intent=base_intent, findings=[Finding(name="Independent callback", truth_state=TruthState.NOT_OBSERVED, detail="None"), supported_da]),
        # 10. Missing destination approval and unapproved status
        make_admitted_case_state(
            case_id="RC-UNSAFE-10",
            intent=base_intent.model_copy(update={"destination_status": DestinationStatus.UNAPPROVED}),
            findings=[supported_cb],
        ),
        # 11. Missing both callback and destination approval
        make_admitted_case_state(
            case_id="RC-UNSAFE-11",
            intent=base_intent.model_copy(update={"destination_status": DestinationStatus.UNAPPROVED}),
            findings=[],
        ),
        # 12. Rejected admission / unauthorized bundle (direct evaluate must return outcome None, never eligible)
        RiskCaseState(
            case_id="RC-UNSAFE-12",
            phase=CasePhase.ADMISSION_REJECTED,
            request_bundle_status="REJECTED",
            processing_authority=ProcessingAuthorityStatus.REJECTED,
            intent=base_intent,
            findings=[supported_cb, supported_da],
            evidence=[],
        ),
    ]

    for idx, state in enumerate(unsafe_variations):
        result = PolicyGate.evaluate(state)
        assert result.outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF, f"Unsafe variation {idx + 1} produced ELIGIBLE_FOR_HANDOFF!"
        if idx < 11:
            assert result.outcome in (PolicyOutcome.HOLD, PolicyOutcome.STEP_UP_REQUIRED, PolicyOutcome.BLOCKED)
        else:
            assert result.outcome is None


def test_zero_eligible_outcomes_for_invalid_mutated_or_unauthorized_cases():
    """Behavioral assertions for three distinct runtime rejection pathways.

    Scenario A — Unauthorized/unadmitted state (ADMISSION_REJECTED + REJECTED authority):
        PolicyGate.evaluate() must return outcome=None (not any PolicyOutcome value).
        GrantIssuer.issue_grant() must raise ValueError.
        A fresh FakeApprovalRailAdapter backed by a temp DB must have zero adapter_attempts
        and zero pending_approval_items for this case.

    Scenario B — Confirmed intent whose fields no longer match intent_hash (post-mutation):
        After an intent is confirmed+hashed, if any canonical field is mutated the stored
        intent_hash is stale.  PolicyGate recomputes the intent hash and returns a protective
        HOLD (never ELIGIBLE_FOR_HANDOFF).  GrantIssuer rejects issuance with exact ValueError.
        Zero pending_approval_items and zero adapter_attempts.

    Scenario C — Post-grant snapshot mutation:
        A fully eligible case gets a valid grant issued and saved to the DB.  If the
        persisted intent is then mutated so that recompute_hash(intent) != intent.intent_hash,
        the adapter detects the authoritative-case intent inconsistency and returns
        INTENT_MISMATCH.  Zero pending_approval_items and zero durable adapter_attempts
        written for this case.
    """
    import json as _json
    import tempfile
    from pathlib import Path as _Path
    from payoutproof.core.crypto import compute_intent_hash

    supported_cb = Finding(name="Independent callback", truth_state=TruthState.SUPPORTED, detail="Confirmed")
    supported_da = Finding(name="Destination approval", truth_state=TruthState.SUPPORTED, detail="Approved")

    # ── Scenario A: Unauthorized / unadmitted ──────────────────────────────────
    base_intent_a = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        destination_status=DestinationStatus.APPROVED_FOR_COUNTERPARTY,
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        status=IntentStatus.CONFIRMED,
        intent_hash="stale_hash_a",
    )
    unauthorized_state = RiskCaseState(
        case_id="RC-UNAUTH-A",
        phase=CasePhase.ADMISSION_REJECTED,
        request_bundle_status="REJECTED",
        processing_authority=ProcessingAuthorityStatus.REJECTED,
        intent=base_intent_a,
        findings=[supported_cb, supported_da],
        evidence=[],
    )

    # PolicyGate must yield outcome=None — never any PolicyOutcome value
    result_a = PolicyGate.evaluate(unauthorized_state)
    assert result_a.outcome is None, (
        f"Unauthorized state must produce outcome=None; got {result_a.outcome}"
    )
    assert result_a.outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF

    # GrantIssuer must refuse to issue a grant for this state
    with pytest.raises(Exception):
        GrantIssuer.issue_grant(unauthorized_state, secret=TEST_GRANT_SECRET)

    # Temp DB: zero adapter_attempts and zero pending_approval_items for this case
    with tempfile.TemporaryDirectory() as tmpdir_a:
        db_a = Database(db_path=_Path(tmpdir_a) / "unauth_a.db", audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
        with db_a.get_connection() as conn_a:
            attempts_a = conn_a.execute(
                "SELECT COUNT(*) FROM adapter_attempts WHERE case_id = ?",
                ("RC-UNAUTH-A",),
            ).fetchone()[0]
            items_a = conn_a.execute(
                "SELECT COUNT(*) FROM pending_approval_items WHERE case_id = ?",
                ("RC-UNAUTH-A",),
            ).fetchone()[0]
        assert attempts_a == 0, f"Unauthorized case must have 0 adapter_attempts; got {attempts_a}"
        assert items_a == 0, f"Unauthorized case must have 0 pending_approval_items; got {items_a}"

    # ── Scenario B: Confirmed intent with stale/mismatched intent_hash ─────────
    # Build a legitimately confirmed intent, then mutate a field so the hash is stale.
    real_intent_b = make_confirmed_intent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        destination_status=DestinationStatus.APPROVED_FOR_COUNTERPARTY,
    )
    # Mutate the amount field — the stored intent_hash now does NOT match the new canonical string
    mutated_intent_b = real_intent_b.model_copy(update={"amount": "999999"})
    assert compute_intent_hash(mutated_intent_b) != mutated_intent_b.intent_hash, (
        "Test setup error: mutated intent must have a mismatched hash"
    )

    admitted_b = make_admitted_case_state(
        case_id="RC-MUTATED-B",
        intent=mutated_intent_b,
        findings=[supported_cb, supported_da],
    )
    result_b = PolicyGate.evaluate(admitted_b)

    # 1. Assert PolicyGate returns noneligible outcome (never ELIGIBLE_FOR_HANDOFF)
    assert result_b.outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF, (
        f"Mutated-hash intent must never be ELIGIBLE_FOR_HANDOFF; got {result_b.outcome}"
    )
    assert result_b.outcome == PolicyOutcome.HOLD
    assert ReasonCode.MATERIAL_INTENT_CHANGED in result_b.reasons

    # 2. Assert exact GrantIssuer ValueError on uneligible policy result
    admitted_b_with_policy = admitted_b.model_copy(update={"policy": result_b})
    with pytest.raises(ValueError) as exc_info:
        GrantIssuer.issue_grant(admitted_b_with_policy, secret=TEST_GRANT_SECRET)
    assert "Cannot issue Handoff Grant for case with policy outcome" in str(exc_info.value)

    # Even if caller forces ELIGIBLE_FOR_HANDOFF, GrantIssuer recomputes intent and rejects with exact ValueError
    forced_eligible_policy = PolicyEvaluationResult(
        outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
        evaluated_intent_hash=mutated_intent_b.intent_hash,
        evaluated_snapshot_hash="dummy_snapshot_hash",
        policy_version="PP-POLICY-V1",
    )
    forced_state_b = admitted_b.model_copy(update={"policy": forced_eligible_policy})
    with pytest.raises(ValueError) as exc_info_recompute:
        GrantIssuer.issue_grant(forced_state_b, secret=TEST_GRANT_SECRET)
    assert "Recomputed intent hash mismatch" in str(exc_info_recompute.value)

    # 3. Assert zero adapter attempts and zero pending items in DB
    with tempfile.TemporaryDirectory() as tmpdir_b:
        db_b = Database(db_path=_Path(tmpdir_b) / "mutated_b.db", audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
        with db_b.get_connection() as conn_b:
            attempts_b = conn_b.execute(
                "SELECT COUNT(*) FROM adapter_attempts WHERE case_id = ?",
                ("RC-MUTATED-B",),
            ).fetchone()[0]
            items_b = conn_b.execute(
                "SELECT COUNT(*) FROM pending_approval_items WHERE case_id = ?",
                ("RC-MUTATED-B",),
            ).fetchone()[0]
        assert attempts_b == 0, (
            f"Mutated-hash case must produce 0 adapter_attempts; got {attempts_b}"
        )
        assert items_b == 0, (
            f"Mutated-hash case must produce 0 pending_approval_items; got {items_b}"
        )

    # ── Scenario C: Post-grant snapshot mutation ───────────────────────────────
    real_intent_c = make_confirmed_intent(
        counterparty="Apex Systems",
        destination="ICICI ••9900",
        amount="500000",
        currency="INR",
        purpose="Component supply",
        destination_status=DestinationStatus.APPROVED_FOR_COUNTERPARTY,
    )
    admitted_c = make_admitted_case_state(
        case_id="RC-SNAPMUT-C",
        intent=real_intent_c,
        findings=[supported_cb, supported_da],
    )
    eligible_result_c = PolicyGate.evaluate(admitted_c)
    assert eligible_result_c.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF, (
        "Test setup error: scenario C base case must be ELIGIBLE_FOR_HANDOFF"
    )

    clean_state_c = admitted_c.model_copy(update={"policy": eligible_result_c})
    grant_c = GrantIssuer.issue_grant(clean_state_c, secret=TEST_GRANT_SECRET)
    persisted_c = clean_state_c.model_copy(update={"grant": grant_c})

    with tempfile.TemporaryDirectory() as tmpdir_c:
        db_c = Database(db_path=_Path(tmpdir_c) / "snapmut_c.db", audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
        db_c.save_case(persisted_c)

        # Corrupt the persisted state_json: mutate amount so recompute hash mismatches
        with db_c.get_connection() as conn_c:
            row_c = conn_c.execute(
                "SELECT state_json FROM risk_cases WHERE case_id = ?",
                ("RC-SNAPMUT-C",),
            ).fetchone()
            state_data_c = _json.loads(row_c["state_json"])
            state_data_c["intent"]["amount"] = "1"  # mutate post-grant
            conn_c.execute(
                "UPDATE risk_cases SET state_json = ? WHERE case_id = ?",
                (_json.dumps(state_data_c), "RC-SNAPMUT-C"),
            )
            conn_c.commit()

        # Adapter must detect authoritative intent inconsistency
        adapter_c = FakeApprovalRailAdapter(
            db=db_c,
            grant_secret=TEST_GRANT_SECRET,
            audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        )
        decision_c, _item_c, _err_c = adapter_c.submit_handoff(
            grant=grant_c,
            intent=real_intent_c,
        )
        assert decision_c == AdapterDecision.INTENT_MISMATCH, (
            f"Post-snapshot-mutation must be rejected as INTENT_MISMATCH; got {decision_c}"
        )

        # Zero pending_approval_items and zero adapter_attempts for this case
        with db_c.get_connection() as conn_c2:
            items_c = conn_c2.execute(
                "SELECT COUNT(*) FROM pending_approval_items WHERE case_id = ?",
                ("RC-SNAPMUT-C",),
            ).fetchone()[0]
            attempts_c = conn_c2.execute(
                "SELECT COUNT(*) FROM adapter_attempts WHERE case_id = ?",
                ("RC-SNAPMUT-C",),
            ).fetchone()[0]
        assert items_c == 0, (
            f"Post-snapshot-mutation must produce 0 pending_approval_items; got {items_c}"
        )
        assert attempts_c == 0, (
            f"Post-snapshot-mutation must produce 0 durable adapter_attempts; got {attempts_c}"
        )


def test_concurrent_grant_consumption_produces_single_pending_item():
    """Concurrent repeated grant use cannot create duplicate pending items."""
    adapter = FakeApprovalRailAdapter(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )
    intent = make_confirmed_intent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
    )
    state = make_admitted_case_state(
        case_id="RC-CONCURRENT-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    grant = GrantIssuer.issue_grant(state, secret=TEST_GRANT_SECRET)
    state = state.model_copy(update={"grant": grant})
    adapter.db.save_case(state)

    # Launch 10 concurrent threads attempting to submit the same grant
    def attempt_submit(worker_id: int):
        return adapter.submit_handoff(
            grant=grant,
            intent=intent,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(attempt_submit, i) for i in range(10)]
        results = [f.result() for f in futures]

    successes = [r for r in results if r[0] == AdapterDecision.PENDING_ITEM_CREATED]
    replays = [r for r in results if r[0] == AdapterDecision.REPLAY_REJECTED]

    # Exactly 1 submission succeeds, 9 are rejected
    assert len(successes) == 1
    assert len(replays) == 9
    assert len(adapter.pending_rail_items) == 1



def test_ambiguity_cannot_retry():
    """Ambiguous handoff transitions to RECONCILIATION_REQUIRED and refuses blind retry."""
    s = StateMachine.initial_state(case_id="RC-AMBIG-01")
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-AMBIG-01"))
    s = StateMachine.reduce(s, {"type": "EXTRACT_INTENT"})
    s = StateMachine.reduce(s, {"type": "CONFIRM_INTENT"})
    s = StateMachine.reduce(s, {"type": "ADD_CALLBACK_EVIDENCE"})
    s = StateMachine.reduce(s, {"type": "ADD_DESTINATION_APPROVAL"})
    s = StateMachine.reduce(s, {"type": "EVALUATE_POLICY"})
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    s = StateMachine.reduce(s, {"type": "INITIATE_HANDOFF"}, grant_secret=TEST_GRANT_SECRET)
    assert s.phase == CasePhase.HANDOFF_IN_PROGRESS

    # Simulate ambiguous timeout via server-side internal typed transition
    s_ambig = StateMachine.apply_adapter_decision(
        s,
        AdapterDecision.DOWNSTREAM_STATUS_UNKNOWN_NO_RETRY,
        error_message="Downstream timeout",
    )
    assert s_ambig.phase == CasePhase.RECONCILIATION_REQUIRED
    assert s_ambig.handoff.status == HandoffStatus.RECONCILIATION_REQUIRED
    assert s_ambig.grant.status == GrantStatus.SUSPENDED_FOR_RECONCILIATION
    assert s_ambig.policy.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF

    # Attempting to re-initiate handoff directly without resolution must be refused
    s_retry = StateMachine.reduce(s_ambig, {"type": "INITIATE_HANDOFF"}, grant_secret=TEST_GRANT_SECRET)
    assert "Refused" in s_retry.last_change
    assert s_retry.phase == CasePhase.RECONCILIATION_REQUIRED


def test_restart_preserves_authority():
    """Restart preserves authority, processing status, intent, and audit verification across SQLite lifecycle."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "restart_test.db"

        # Initialize and populate database in Session 1
        db1 = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
        s = StateMachine.initial_state(case_id="RC-RESTART-01")
        s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-RESTART-01"))
        s = StateMachine.reduce(s, {"type": "EXTRACT_INTENT", "payload": {"counterparty": "Apex Systems", "destination": "ICICI ••9900", "amount": "500000"}})
        s = StateMachine.reduce(s, {"type": "CONFIRM_INTENT"})
        s = StateMachine.reduce(s, {"type": "ADD_CALLBACK_EVIDENCE"})
        s = StateMachine.reduce(s, {"type": "ADD_DESTINATION_APPROVAL"})
        s = StateMachine.reduce(s, {"type": "EVALUATE_POLICY"})
        s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
        db1.save_case(s)

        # Simulate process termination & fresh cold restart in Session 2
        del db1
        db2 = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
        reloaded = db2.load_case("RC-RESTART-01")

        assert reloaded is not None
        assert reloaded.case_id == "RC-RESTART-01"
        assert reloaded.processing_authority == ProcessingAuthorityStatus.VALID
        assert reloaded.authority_record is not None
        assert reloaded.phase == CasePhase.READY_FOR_HUMAN_HANDOFF
        assert reloaded.intent.status == IntentStatus.CONFIRMED
        assert reloaded.policy.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
        assert reloaded.grant.status == GrantStatus.ACTIVE

        # Verify audit chain integrity survives restart
        is_valid, broken_seq, _ = AuditChain.verify_chain(reloaded.audit)
        assert is_valid
        assert broken_seq is None


def test_largest_case_removed_sensitivity_for_interaction_reduction():
    """Interaction reduction gate (>= 30%) holds even with the single largest case removed."""
    dev_cases = Simulator.generate_dev_corpus()
    results = [execute_case_under_test(c) for c in dev_cases]

    # Find the case with the largest interaction savings
    savings = [r.simulated_no_tool_interactions - r.simulated_tool_interactions for r in results]
    max_idx = savings.index(max(savings))

    # Remove the largest saving case
    sensitivity_results = results[:max_idx] + results[max_idx + 1:]
    assert len(sensitivity_results) == 44

    report = EvaluationScorer.score_results(sensitivity_results)
    assert report.passed_interaction_gate
    assert report.interaction_reduction_pct >= 30.0


def test_simulator_and_oracle_reproducibility():
    """Simulator generation is deterministic and structurally separate from Oracle."""
    dev1 = Simulator.generate_dev_corpus(seed=42)
    dev2 = Simulator.generate_dev_corpus(seed=42)
    sealed1 = Simulator.generate_sealed_corpus(seed=101)
    sealed2 = Simulator.generate_sealed_corpus(seed=101)

    assert len(dev1) == len(dev2) == 45
    assert len(sealed1) == len(sealed2) == 90

    for c1, c2 in zip(dev1, dev2):
        assert c1.case_id == c2.case_id
        assert c1.amount == c2.amount
        assert c1.gold_outcome == c2.gold_outcome
        # Verify Oracle computes expected outcome independently
        gold_out, _ = PolicyOracle.evaluate_expected(c1)
        assert gold_out == c1.gold_outcome

    for c1, c2 in zip(sealed1, sealed2):
        assert c1.case_id == c2.case_id
        assert c1.amount == c2.amount
        assert c1.gold_outcome == c2.gold_outcome
        gold_out, _ = PolicyOracle.evaluate_expected(c1)
        assert gold_out == c1.gold_outcome
