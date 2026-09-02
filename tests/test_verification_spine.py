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
from payoutproof.grants.issuer import GrantIssuer, DEFAULT_GRANT_SECRET
from payoutproof.simulator.generator import Simulator, EvaluationCase
from payoutproof.oracle.oracle import PolicyOracle
from payoutproof.scorer.scorer import EvaluationScorer
from payoutproof.scorer.runner import execute_case_under_test
from payoutproof.storage.db import Database
from payoutproof.audit.chain import AuditChain


def test_property_zero_eligible_for_unsafe_cases():
    """Property test: Zero eligible outcomes for incomplete, unsupported, contradicted, mutated, or failed cases."""
    base_intent = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        destination_status=DestinationStatus.APPROVED_FOR_COUNTERPARTY,
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        status=IntentStatus.CONFIRMED,
        intent_hash="valid_hash_12345",
    )
    supported_cb = Finding(name="Independent callback", truth_state=TruthState.SUPPORTED, detail="Confirmed")
    supported_da = Finding(name="Destination approval", truth_state=TruthState.SUPPORTED, detail="Approved")

    unsafe_variations = [
        # 1. Tampered snapshot
        RiskCaseState(case_id="RC-UNSAFE-1", request_bundle_status="TAMPERED", intent=base_intent, findings=[supported_cb, supported_da]),
        # 2. Unusable model failure
        RiskCaseState(case_id="RC-UNSAFE-2", intent=base_intent, findings=[supported_cb, supported_da], investigation=CaseInvestigation(model_status="FAILED_UNUSABLE_AUDIO")),
        # 3. Schema error model failure
        RiskCaseState(case_id="RC-UNSAFE-3", intent=base_intent, findings=[supported_cb, supported_da], investigation=CaseInvestigation(model_status="FAILED_SCHEMA_ERROR")),
        # 4. Timeout model failure
        RiskCaseState(case_id="RC-UNSAFE-4", intent=base_intent, findings=[supported_cb, supported_da], investigation=CaseInvestigation(model_status="FAILED_TIMEOUT")),
        # 5. Invalidated intent (post-mutation)
        RiskCaseState(case_id="RC-UNSAFE-5", intent=base_intent.model_copy(update={"status": IntentStatus.INVALIDATED}), findings=[supported_cb, supported_da]),
        # 6. Unconfirmed intent
        RiskCaseState(case_id="RC-UNSAFE-6", intent=base_intent.model_copy(update={"status": IntentStatus.EXTRACTED, "intent_hash": None}), findings=[supported_cb, supported_da]),
        # 7. Contradiction in findings
        RiskCaseState(case_id="RC-UNSAFE-7", intent=base_intent, findings=[supported_cb, supported_da, Finding(name="Invoice", truth_state=TruthState.CONTRADICTED, detail="Mismatch")]),
        # 8. Missing callback
        RiskCaseState(case_id="RC-UNSAFE-8", intent=base_intent, findings=[supported_da]),
        # 9. Callback not observed
        RiskCaseState(case_id="RC-UNSAFE-9", intent=base_intent, findings=[Finding(name="Independent callback", truth_state=TruthState.NOT_OBSERVED, detail="None"), supported_da]),
        # 10. Missing destination approval and unapproved status
        RiskCaseState(
            case_id="RC-UNSAFE-10",
            intent=base_intent.model_copy(update={"destination_status": DestinationStatus.UNAPPROVED}),
            findings=[supported_cb],
        ),
        # 11. Missing both callback and destination approval
        RiskCaseState(
            case_id="RC-UNSAFE-11",
            intent=base_intent.model_copy(update={"destination_status": DestinationStatus.UNAPPROVED}),
            findings=[],
        ),
    ]

    for idx, state in enumerate(unsafe_variations):
        result = PolicyGate.evaluate(state)
        assert result.outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF, f"Unsafe variation {idx + 1} produced ELIGIBLE_FOR_HANDOFF!"
        assert result.outcome in (PolicyOutcome.HOLD, PolicyOutcome.STEP_UP_REQUIRED, PolicyOutcome.BLOCKED)


def test_concurrent_grant_consumption_produces_single_pending_item():
    """Concurrent repeated grant use cannot create duplicate pending items."""
    adapter = FakeApprovalRailAdapter()
    intent = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        status=IntentStatus.CONFIRMED,
        intent_hash="sample_hash_concurrent",
    )
    state = RiskCaseState(
        case_id="RC-CONCURRENT-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    grant = GrantIssuer.issue_grant(state, secret=DEFAULT_GRANT_SECRET)

    # Launch 10 concurrent threads attempting to submit the same grant
    def attempt_submit(worker_id: int):
        return adapter.submit_handoff(
            grant=grant,
            intent=intent,
            idempotency_key=f"IDEM-CONCURRENT-{worker_id}",
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
    s = StateMachine.reduce(s, {"type": "ADMIT_AUTHORIZED_BUNDLE"})
    s = StateMachine.reduce(s, {"type": "EXTRACT_INTENT"})
    s = StateMachine.reduce(s, {"type": "CONFIRM_INTENT"})
    s = StateMachine.reduce(s, {"type": "ADD_CALLBACK_EVIDENCE"})
    s = StateMachine.reduce(s, {"type": "ADD_DESTINATION_APPROVAL"})
    s = StateMachine.reduce(s, {"type": "EVALUATE_POLICY"})
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"})
    s = StateMachine.reduce(s, {"type": "INITIATE_HANDOFF"})

    # Simulate ambiguous timeout
    s_ambig = StateMachine.reduce(s, {"type": "HANDOFF_AMBIGUOUS"})
    assert s_ambig.phase == CasePhase.RECONCILIATION_REQUIRED
    assert s_ambig.handoff.status == HandoffStatus.RECONCILIATION_REQUIRED
    assert s_ambig.grant.status == GrantStatus.SUSPENDED_FOR_RECONCILIATION

    # Attempting to re-initiate handoff directly without resolution must be refused
    s_retry = StateMachine.reduce(s_ambig, {"type": "INITIATE_HANDOFF"})
    assert "Refused" in s_retry.last_change
    assert s_retry.phase == CasePhase.RECONCILIATION_REQUIRED


def test_restart_preserves_authority():
    """Restart preserves authority, processing status, intent, and audit verification across SQLite lifecycle."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "restart_test.db"

        # Initialize and populate database in Session 1
        db1 = Database(db_path=db_file)
        s = StateMachine.initial_state(case_id="RC-RESTART-01")
        s = StateMachine.reduce(s, {"type": "ADMIT_AUTHORIZED_BUNDLE", "payload": {"case_id": "RC-RESTART-01"}})
        s = StateMachine.reduce(s, {"type": "EXTRACT_INTENT", "payload": {"counterparty": "Apex Systems", "destination": "ICICI ••9900", "amount": "500000"}})
        s = StateMachine.reduce(s, {"type": "CONFIRM_INTENT"})
        s = StateMachine.reduce(s, {"type": "ADD_CALLBACK_EVIDENCE"})
        s = StateMachine.reduce(s, {"type": "ADD_DESTINATION_APPROVAL"})
        s = StateMachine.reduce(s, {"type": "EVALUATE_POLICY"})
        s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"})
        db1.save_case(s)

        # Simulate process termination & fresh cold restart in Session 2
        del db1
        db2 = Database(db_path=db_file)
        reloaded = db2.load_case("RC-RESTART-01")

        assert reloaded is not None
        assert reloaded.case_id == "RC-RESTART-01"
        assert reloaded.processing_authority == ProcessingAuthorityStatus.VALID
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
