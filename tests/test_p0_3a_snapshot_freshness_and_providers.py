"""Tests for P0-3A: Policy evaluation snapshot freshness and deterministic providers.

Covers:
1. ClockProvider and NonceProvider protocol and implementation correctness:
   - SystemClock & SystemNonce (secure system implementations)
   - FixedClock & SequentialNonce (deterministic test implementations)
2. Deterministic lifecycle reproducibility:
   - Two identical lifecycle runs with FixedClock and SequentialNonce produce byte-equal model_dump().
   - Audit timestamps, hashes, grant ID, nonce, issued_at, expires_at, signature, idempotency key match.
   - Different clock/nonce changes expected fields.
3. Parameterized tests mutating every snapshot-relevant input class after eligible evaluation before issuance;
   all reject with stable ValueError.
"""

from datetime import datetime, timezone, timedelta
from typing import Callable
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
    FindingName,
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
from payoutproof.core.crypto import (
    compute_intent_hash,
    compute_snapshot_hash,
    derive_idempotency_key,
)
from payoutproof.core.providers import (
    ClockProvider,
    NonceProvider,
    SystemClock,
    SystemNonce,
    FixedClock,
    SequentialNonce,
)
from payoutproof.policy.evaluator import PolicyGate
from payoutproof.grants.issuer import GrantIssuer, GrantVerifier
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.audit.chain import AuditChain
from tests.helpers import (
    make_confirmed_intent,
    make_valid_authority_record,
    make_authorized_bundle_action,
    make_admitted_case_state,
    TEST_GRANT_SECRET,
)


# ==============================================================================
# SECTION 1: Clock & Nonce Provider Correctness
# ==============================================================================

def test_system_clock_and_nonce():
    """SystemClock produces valid UTC datetimes; SystemNonce produces secure hex nonces."""
    clock = SystemClock()
    assert isinstance(clock, ClockProvider)
    now_dt = clock.now()
    assert now_dt.tzinfo is not None
    assert abs((datetime.now(timezone.utc) - now_dt).total_seconds()) < 2.0

    iso_str = clock.now_iso()
    parsed = datetime.fromisoformat(iso_str)
    assert parsed.tzinfo is not None

    nonce_prov = SystemNonce()
    assert isinstance(nonce_prov, NonceProvider)
    n1 = nonce_prov.generate_nonce(16)
    n2 = nonce_prov.generate_nonce(16)
    assert len(n1) == 32
    assert len(n2) == 32
    assert n1 != n2


def test_fixed_clock_and_sequential_nonce():
    """FixedClock is deterministic and advanceable; SequentialNonce produces sequential hex nonces."""
    t0 = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)
    clock = FixedClock(t0)
    assert isinstance(clock, ClockProvider)
    assert clock.now() == t0
    assert clock.now_iso() == t0.isoformat()

    clock.advance(60.0)
    t1 = t0 + timedelta(seconds=60)
    assert clock.now() == t1

    clock.set_time("2026-10-01T00:00:00+00:00")
    assert clock.now() == datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)

    seq_nonce = SequentialNonce(start=1, prefix="")
    assert isinstance(seq_nonce, NonceProvider)
    n1 = seq_nonce.generate_nonce(16)
    n2 = seq_nonce.generate_nonce(16)
    n3 = seq_nonce.generate_nonce(16)
    assert len(n1) == 32
    assert n1[:8] == "00000001"
    assert n2[:8] == "00000002"
    assert n3[:8] == "00000003"


# ==============================================================================
# SECTION 2: Deterministic Lifecycle Reproducibility (Requirement 7)
# ==============================================================================

def _run_full_lifecycle(clock: ClockProvider, nonce_provider: NonceProvider, case_id: str = "RC-LIFECYCLE-01") -> tuple[RiskCaseState, RiskCaseState]:
    """Execute a complete authoritative RiskCase lifecycle using provided clock and nonce provider.

    Returns (active_granted_state, complete_state).
    """
    s = StateMachine.initial_state(case_id=case_id, tenant_id="tenant_acme", clock=clock)
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id=case_id), clock=clock, nonce_provider=nonce_provider)
    s = StateMachine.reduce(s, {"type": "EXTRACT_INTENT"}, clock=clock, nonce_provider=nonce_provider)
    s = StateMachine.reduce(s, {"type": "CONFIRM_INTENT"}, clock=clock, nonce_provider=nonce_provider)
    s = StateMachine.reduce(s, {"type": "ADD_CALLBACK_EVIDENCE"}, clock=clock, nonce_provider=nonce_provider)
    s = StateMachine.reduce(s, {"type": "ADD_DESTINATION_APPROVAL"}, clock=clock, nonce_provider=nonce_provider)
    s = StateMachine.reduce(s, {"type": "EVALUATE_POLICY"}, clock=clock, nonce_provider=nonce_provider)
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET, clock=clock, nonce_provider=nonce_provider)
    granted_s = s
    s = StateMachine.reduce(s, {"type": "INITIATE_HANDOFF"}, grant_secret=TEST_GRANT_SECRET, clock=clock, nonce_provider=nonce_provider)
    s = StateMachine.apply_adapter_decision(
        s,
        AdapterDecision.PENDING_ITEM_CREATED,
        pending_item_id=f"ITEM-{case_id}-99",
        clock=clock,
    )
    return granted_s, s


def test_two_identical_runs_produce_byte_equal_model_dump():
    """Requirement 7: With fixed clock+sequential nonce, two identical lifecycle runs must produce byte-equal model_dump."""
    fixed_time = datetime(2026, 9, 2, 15, 30, 0, tzinfo=timezone.utc)

    # Run 1
    clock1 = FixedClock(fixed_time)
    nonce1 = SequentialNonce(start=42)
    granted1, state1 = _run_full_lifecycle(clock=clock1, nonce_provider=nonce1, case_id="RC-DET-RUN")

    # Run 2
    clock2 = FixedClock(fixed_time)
    nonce2 = SequentialNonce(start=42)
    granted2, state2 = _run_full_lifecycle(clock=clock2, nonce_provider=nonce2, case_id="RC-DET-RUN")

    # Exact byte equality of dumps for both active-granted and completed states
    assert granted1.model_dump() == granted2.model_dump()
    assert state1.model_dump() == state2.model_dump()

    # Verify specific cryptographic and temporal fields match
    assert state1.grant is not None and state2.grant is not None
    assert state1.grant.grant_id == state2.grant.grant_id
    assert state1.grant.nonce == state2.grant.nonce
    assert state1.grant.issued_at == state2.grant.issued_at
    assert state1.grant.expires_at == state2.grant.expires_at
    assert state1.grant.signature == state2.grant.signature
    assert state1.grant.bound_intent_hash == state2.grant.bound_intent_hash
    assert state1.grant.bound_snapshot_hash == state2.grant.bound_snapshot_hash

    assert state1.policy.evaluated_intent_hash == state2.policy.evaluated_intent_hash
    assert state1.policy.evaluated_snapshot_hash == state2.policy.evaluated_snapshot_hash
    assert state1.policy.evaluated_at == state2.policy.evaluated_at
    assert state1.policy.expires_at == state2.policy.expires_at

    assert len(state1.audit) == len(state2.audit)
    for ev1, ev2 in zip(state1.audit, state2.audit):
        assert ev1.seq == ev2.seq
        assert ev1.event_type == ev2.event_type
        assert ev1.prev_hash == ev2.prev_hash
        assert ev1.current_hash == ev2.current_hash
        assert ev1.timestamp == ev2.timestamp

    # Cryptographic verification of audit chain holds
    valid1, broken1, _ = AuditChain.verify_chain(state1.audit)
    valid2, broken2, _ = AuditChain.verify_chain(state2.audit)
    assert valid1 and broken1 is None
    assert valid2 and broken2 is None

    # Cryptographic verification of active grant holds
    valid_g1, err_g1 = GrantVerifier.verify(granted1.grant, granted1.intent.intent_hash, secret=TEST_GRANT_SECRET, clock=clock1)
    valid_g2, err_g2 = GrantVerifier.verify(granted2.grant, granted2.intent.intent_hash, secret=TEST_GRANT_SECRET, clock=clock2)
    assert valid_g1 and err_g1 is None
    assert valid_g2 and err_g2 is None

    # After adapter submission, grant is consumed single-use
    assert state1.grant.status == GrantStatus.CONSUMED
    assert state1.grant.used is True


def test_different_clock_or_nonce_changes_expected_fields():
    """Requirement 7: Different clock/nonce changes expected fields."""
    fixed_time_a = datetime(2026, 9, 2, 10, 0, 0, tzinfo=timezone.utc)
    fixed_time_b = datetime(2026, 9, 2, 18, 0, 0, tzinfo=timezone.utc)

    # Run A
    clock_a = FixedClock(fixed_time_a)
    nonce_a = SequentialNonce(start=1)
    _, state_a = _run_full_lifecycle(clock=clock_a, nonce_provider=nonce_a, case_id="RC-DIFF")

    # Run B (different clock, same nonce)
    clock_b = FixedClock(fixed_time_b)
    nonce_b = SequentialNonce(start=1)
    _, state_b = _run_full_lifecycle(clock=clock_b, nonce_provider=nonce_b, case_id="RC-DIFF")

    # Run C (same clock as A, different nonce)
    clock_c = FixedClock(fixed_time_a)
    nonce_c = SequentialNonce(start=999)
    _, state_c = _run_full_lifecycle(clock=clock_c, nonce_provider=nonce_c, case_id="RC-DIFF")

    # Clock change changes timestamps, hashes, signatures
    assert state_a.grant.issued_at != state_b.grant.issued_at
    assert state_a.grant.expires_at != state_b.grant.expires_at
    assert state_a.grant.signature != state_b.grant.signature
    assert state_a.policy.evaluated_at != state_b.policy.evaluated_at
    assert state_a.policy.expires_at != state_b.policy.expires_at
    assert [e.timestamp for e in state_a.audit] != [e.timestamp for e in state_b.audit]
    assert [e.current_hash for e in state_a.audit] != [e.current_hash for e in state_b.audit]

    # Nonce change changes grant ID, nonce, signature, idempotency key
    assert state_a.grant.grant_id != state_c.grant.grant_id
    assert state_a.grant.nonce != state_c.grant.nonce
    assert state_a.grant.signature != state_c.grant.signature
    assert state_a.handoff.idempotency_key != state_c.handoff.idempotency_key
    # But clock-derived timestamps remain identical between A and C
    assert state_a.grant.issued_at == state_c.grant.issued_at
    assert state_a.policy.evaluated_at == state_c.policy.evaluated_at


# ==============================================================================
# SECTION 3: Parameterized Post-Evaluation Snapshot Mutation Rejection (Requirement 9)
# ==============================================================================

def _make_base_eligible_state() -> RiskCaseState:
    """Construct a fully admitted, confirmed, and eligible RiskCaseState."""
    intent = make_confirmed_intent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        destination_status=DestinationStatus.APPROVED_FOR_COUNTERPARTY,
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
    )
    supported_cb = Finding(name="Independent callback", truth_state=TruthState.SUPPORTED, detail="Confirmed")
    supported_da = Finding(name="Destination approval", truth_state=TruthState.SUPPORTED, detail="Approved")
    state = make_admitted_case_state(
        case_id="RC-MUT-TEST-01",
        tenant_id="tenant_01",
        intent=intent,
        findings=[supported_cb, supported_da],
    )
    eval_result = PolicyGate.evaluate(state)
    assert eval_result.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
    assert eval_result.evaluated_snapshot_hash is not None
    return state.model_copy(update={"policy": eval_result})


MUTATION_CASES = [
    # ── 1. Authority mutations ──
    ("authority_purpose", lambda s: s.model_copy(update={"authority_record": s.authority_record.model_copy(update={"purpose": "mutated purpose"})})),
    ("authority_retention_days", lambda s: s.model_copy(update={"authority_record": s.authority_record.model_copy(update={"retention_days": 30})})),
    ("authority_is_valid_false", lambda s: s.model_copy(update={"authority_record": s.authority_record.model_copy(update={"is_valid": False})})),
    ("authority_record_none", lambda s: s.model_copy(update={"authority_record": None})),
    ("processing_authority_rejected", lambda s: s.model_copy(update={"processing_authority": ProcessingAuthorityStatus.REJECTED})),
    ("processing_authority_incomplete", lambda s: s.model_copy(update={"processing_authority": ProcessingAuthorityStatus.INCOMPLETE})),

    # ── 2. Evidence mutations ──
    ("evidence_add_item", lambda s: s.model_copy(update={"evidence": list(s.evidence) + [
        EvidenceItem(id="EV-MUT-EXTRA", item_type="EXTRA", title="Extra", content_hash="extra_hash", finding="extra", truth_state=TruthState.SUPPORTED)
    ]})),
    ("evidence_remove_item", lambda s: s.model_copy(update={"evidence": []})),
    ("evidence_modify_content_hash", lambda s: s.model_copy(update={"evidence": [
        s.evidence[0].model_copy(update={"content_hash": "mutated_content_hash_1234"})
    ]})),
    ("evidence_modify_truth_state", lambda s: s.model_copy(update={"evidence": [
        s.evidence[0].model_copy(update={"truth_state": TruthState.CONTRADICTED})
    ]})),

    # ── 3. Findings mutations ──
    ("finding_add", lambda s: s.model_copy(update={"findings": list(s.findings) + [
        Finding(name="Extra finding", truth_state=TruthState.SUPPORTED, detail="Extra")
    ]})),
    ("finding_remove", lambda s: s.model_copy(update={"findings": s.findings[:1]})),
    ("finding_modify_truth_state", lambda s: s.model_copy(update={"findings": [
        s.findings[0].model_copy(update={"truth_state": TruthState.CONTRADICTED}), s.findings[1]
    ]})),
    ("finding_modify_detail", lambda s: s.model_copy(update={"findings": [
        s.findings[0].model_copy(update={"detail": "Mutated detail string"}), s.findings[1]
    ]})),

    # ── 4. Intent mutations ──
    ("intent_amount", lambda s: s.model_copy(update={"intent": s.intent.model_copy(update={"amount": "999999"})})),
    ("intent_destination", lambda s: s.model_copy(update={"intent": s.intent.model_copy(update={"destination": "HDFC ••0000"})})),
    ("intent_counterparty", lambda s: s.model_copy(update={"intent": s.intent.model_copy(update={"counterparty": "Malicious Corp"})})),
    ("intent_currency", lambda s: s.model_copy(update={"intent": s.intent.model_copy(update={"currency": "USD"})})),
    ("intent_purpose", lambda s: s.model_copy(update={"intent": s.intent.model_copy(update={"purpose": "Extortion payout"})})),
    ("intent_destination_status", lambda s: s.model_copy(update={"intent": s.intent.model_copy(update={"destination_status": DestinationStatus.UNAPPROVED})})),
    ("intent_instruction_reference", lambda s: s.model_copy(update={"intent": s.intent.model_copy(update={"instruction_reference": "FORGED-REF"})})),
    ("intent_provenance", lambda s: s.model_copy(update={"intent": s.intent.model_copy(update={"provenance": ["FORGED: 00:01"]})})),
    ("intent_status_invalidated", lambda s: s.model_copy(update={"intent": s.intent.model_copy(update={"status": IntentStatus.INVALIDATED})})),
    ("intent_hash_tampered", lambda s: s.model_copy(update={"intent": s.intent.model_copy(update={"intent_hash": "forged_intent_hash_value"})})),

    # ── 5. Case metadata / version mutations ──
    ("case_id_mutated", lambda s: s.model_copy(update={"case_id": "RC-FORGED-CASE-ID"})),
    ("tenant_id_mutated", lambda s: s.model_copy(update={"tenant_id": "tenant_rogue"})),
    ("case_version_mutated", lambda s: s.model_copy(update={"case_version": s.case_version + 1})),
    ("request_bundle_status_tampered", lambda s: s.model_copy(update={"request_bundle_status": "TAMPERED"})),
    ("request_bundle_status_rejected", lambda s: s.model_copy(update={"request_bundle_status": "REJECTED"})),

    # ── 6. Investigation mutations ──
    ("investigation_model_status", lambda s: s.model_copy(update={"investigation": s.investigation.model_copy(update={"model_status": "FAILED_TIMEOUT"})})),
    ("investigation_attempt", lambda s: s.model_copy(update={"investigation": s.investigation.model_copy(update={"attempt": 5})})),
    ("investigation_asr_confidence", lambda s: s.model_copy(update={"investigation": s.investigation.model_copy(update={"asr_confidence": 0.1})})),

    # ── 7. Policy result mutations ──
    ("policy_missing_snapshot_hash", lambda s: s.model_copy(update={"policy": s.policy.model_copy(update={"evaluated_snapshot_hash": None})})),
    ("policy_mismatched_snapshot_hash", lambda s: s.model_copy(update={"policy": s.policy.model_copy(update={"evaluated_snapshot_hash": "tampered_snapshot_hash_value"})})),
    ("policy_mismatched_intent_hash", lambda s: s.model_copy(update={"policy": s.policy.model_copy(update={"evaluated_intent_hash": "tampered_intent_hash_value"})})),
    ("policy_outcome_hold", lambda s: s.model_copy(update={"policy": s.policy.model_copy(update={"outcome": PolicyOutcome.HOLD})})),
    ("policy_outcome_blocked", lambda s: s.model_copy(update={"policy": s.policy.model_copy(update={"outcome": PolicyOutcome.BLOCKED})})),
    ("policy_outcome_step_up", lambda s: s.model_copy(update={"policy": s.policy.model_copy(update={"outcome": PolicyOutcome.STEP_UP_REQUIRED})})),
    ("policy_empty_version", lambda s: s.model_copy(update={"policy": s.policy.model_copy(update={"policy_version": ""})})),
]


@pytest.mark.parametrize("name,mutator", MUTATION_CASES)
def test_post_evaluation_snapshot_mutation_rejects_grant_issuance(name: str, mutator: Callable[[RiskCaseState], RiskCaseState]):
    """Requirement 9: Mutating every snapshot-relevant input class after eligible evaluation before issuance rejects with stable ValueError."""
    base_state = _make_base_eligible_state()

    # Pre-condition: base state must be issuable
    clean_grant = GrantIssuer.issue_grant(base_state, secret=TEST_GRANT_SECRET)
    assert clean_grant.status == GrantStatus.ACTIVE

    # Apply mutation
    mutated_state = mutator(base_state)

    # Post-condition: GrantIssuer must reject with ValueError
    with pytest.raises(ValueError) as exc_info:
        GrantIssuer.issue_grant(mutated_state, secret=TEST_GRANT_SECRET)

    # Assert stable ValueError
    err_msg = str(exc_info.value)
    assert len(err_msg) > 0
    assert any(expected in err_msg for expected in [
        "Cannot issue Handoff Grant",
        "Evaluated snapshot hash mismatch",
        "Evaluated intent hash mismatch",
        "Recomputed intent hash mismatch",
        "Policy evaluation result is missing evaluated_snapshot_hash",
        "Policy evaluation version is required",
        "Case ID is required",
        "Payment Intent must be confirmed",
    ]), f"Unexpected error message for mutation '{name}': {err_msg}"
