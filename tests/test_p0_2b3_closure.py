"""Comprehensive test suite for P0-2B.3 closure ticket requirements (A through F)."""

import pytest
import sqlite3
import json
import sys
import payoutproof.api
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient

api_app = sys.modules["payoutproof.api.app"]
from payoutproof.core.models import (
    RiskCaseState,
    PaymentIntent,
    PolicyEvaluationResult,
    HandoffGrant,
    PendingApprovalItem,
    EvidenceItem,
    Finding,
)
from payoutproof.core.enums import (
    CasePhase,
    GrantStatus,
    HandoffStatus,
    PolicyOutcome,
    IntentStatus,
    AdapterDecision,
    ProcessingAuthorityStatus,
    TruthState,
)
from payoutproof.core.crypto import (
    compute_intent_hash,
    compute_snapshot_hash,
    derive_idempotency_key,
    create_grant_signature,
)
from payoutproof.grants.issuer import GrantIssuer
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.case_workflow.handoff_service import HandoffService
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
from payoutproof.storage.db import (
    Database,
    StaleCaseStateError,
    GrantTransitionError,
    validate_grant_transition,
    TERMINAL_GRANT_STATUSES,
)
from tests.helpers import make_admitted_case_state, make_confirmed_intent, TEST_GRANT_SECRET, TEST_AUDIT_CHECKPOINT_SECRET


# ==============================================================================
# SECTION A: Persisted Authority Only
# ==============================================================================

def test_handoff_with_unpersisted_caller_state_creates_zero_db_rows(tmp_path):
    """Section A Requirement: HandoffService.execute_handoff with unpersisted caller state
    (even with a cryptographically valid signed grant) must safely refuse and create ZERO rows
    in risk_cases, handoff_grants, adapter_attempts, and pending_approval_items.
    """
    db_path = tmp_path / "unpersisted_authority.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
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
    unpersisted_state = make_admitted_case_state(
        case_id="RC-UNPERSISTED-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    grant = GrantIssuer.issue_grant(unpersisted_state, secret=TEST_GRANT_SECRET)
    unpersisted_state = unpersisted_state.model_copy(update={"grant": grant})

    # Execute handoff directly with unpersisted state
    result = HandoffService.execute_handoff(state=unpersisted_state, adapter=adapter, grant_secret=TEST_GRANT_SECRET)

    # Must refuse safely
    assert result.phase != CasePhase.COMPLETE
    assert result.phase != CasePhase.HANDOFF_IN_PROGRESS
    assert result.handoff.status == HandoffStatus.FAILED
    assert "not found in persistence" in result.last_change

    # Verify ZERO database rows were inserted across all tables
    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM risk_cases").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM handoff_grants").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM adapter_attempts").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM pending_approval_items").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0


def test_handoff_with_unpersisted_grant_on_persisted_case_creates_zero_attempts(tmp_path):
    """Section A Requirement: Persisted case without a persisted matching handoff_grants row
    cannot execute handoff and creates zero attempts or items.
    """
    db_path = tmp_path / "unpersisted_grant.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        case_id="RC-NO-GRANT-ROW",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    db.save_case(state)

    # Caller crafts and attaches a valid signed grant without persisting it to DB
    grant = GrantIssuer.issue_grant(state, secret=TEST_GRANT_SECRET)
    caller_state = state.model_copy(update={"grant": grant})

    result = HandoffService.execute_handoff(state=caller_state, adapter=adapter, grant_secret=TEST_GRANT_SECRET)
    assert result.phase != CasePhase.COMPLETE
    assert "no grant found on authoritative case" in result.last_change

    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM handoff_grants").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM adapter_attempts").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM pending_approval_items").fetchone()[0] == 0


# ==============================================================================
# SECTION B: Serialize Every API Case Mutation
# ==============================================================================

def test_concurrent_api_case_creation_prevents_duplicate_and_returns_409(tmp_path, monkeypatch):
    """Section B Requirement: Concurrent POST /api/cases for the same case_id
    serializes: exactly one succeeds with 200, concurrent attempts return 409 Conflict.
    """
    db_file = tmp_path / "api_create_concurrent.db"
    test_db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    test_adapter = FakeApprovalRailAdapter(
        db=test_db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )
    from payoutproof.api.app import create_app
    from payoutproof.core.config import AppConfig
    cfg = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(db_file),
    )
    test_app = create_app(config=cfg, db=test_db)
    test_app.state.adapter = test_adapter
    client = TestClient(test_app, headers={"X-Organization-Id": "org_default"})

    case_id = "RC-CONCURRENT-CREATE"
    results = []

    def try_create():
        return client.post("/api/cases", json={"case_id": case_id, "tenant_id": "tenant_01"})

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(try_create) for _ in range(10)]
        for f in futures:
            results.append(f.result())

    status_codes = [r.status_code for r in results]
    assert status_codes.count(200) == 1
    assert status_codes.count(409) == 9

    # Exactly 1 row in database
    with test_db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM risk_cases WHERE case_id = ?", (case_id,)).fetchone()[0] == 1


def test_concurrent_api_mutations_serialize_without_lost_updates(tmp_path, monkeypatch):
    """Section B Requirement: Concurrent mutating actions via API dispatch serialize safely."""
    from tests.helpers import make_authorized_bundle_action, make_valid_authority_record
    db_file = tmp_path / "api_mutation_concurrent.db"
    test_db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    test_adapter = FakeApprovalRailAdapter(
        db=test_db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )
    from payoutproof.api.app import create_app
    from payoutproof.core.config import AppConfig
    cfg = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(db_file),
    )
    test_app = create_app(config=cfg, db=test_db)
    test_app.state.adapter = test_adapter
    client = TestClient(test_app, headers={"X-Organization-Id": "org_default"})

    case_id = "RC-MUT-SERIALIZE"
    client.post("/api/cases", json={"case_id": case_id, "tenant_id": "tenant_01"})
    admit_act = make_authorized_bundle_action(
        case_id=case_id,
        authority=make_valid_authority_record().model_dump(),
    )
    r_admit = client.post(f"/api/cases/{case_id}/dispatch", json=admit_act)
    assert r_admit.status_code == 200

    def send_action(action_type, payload=None):
        return client.post(f"/api/cases/{case_id}/dispatch", json={"type": action_type, "payload": payload or {}})

    with ThreadPoolExecutor(max_workers=4) as executor:
        f1 = executor.submit(send_action, "EXTRACT_INTENT", {"counterparty": "Kaveri Components", "destination": "HDFC ••4821", "amount": "425000"})
        f2 = executor.submit(send_action, "ADD_CALLBACK_EVIDENCE")
        r1 = f1.result()
        r2 = f2.result()

    assert r1.status_code == 200
    assert r2.status_code == 200

    # Ensure final DB state reflects serialized execution
    final_case = test_db.load_case(case_id)
    assert final_case is not None
    assert len(final_case.audit) >= 3


# ==============================================================================
# SECTION C: Reject Stale / Incoherent Direct Saves
# ==============================================================================

def test_stale_active_direct_save_rejected_against_all_terminal_statuses(tmp_path):
    """Section C Requirement: Directly saving candidate state with status ACTIVE
    when durable row is in any terminal status (CONSUMED, SUSPENDED_FOR_RECONCILIATION,
    INVALIDATED, EXPIRED) raises StaleCaseStateError and leaves DB row untouched.
    """
    for idx, (term_status, term_used) in enumerate([
        (GrantStatus.CONSUMED, True),
        (GrantStatus.SUSPENDED_FOR_RECONCILIATION, True),
        (GrantStatus.INVALIDATED, False),
        (GrantStatus.EXPIRED, False),
    ]):
        db_path = tmp_path / f"stale_saves_{idx}.db"
        db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

        intent = make_confirmed_intent()
        case_id = f"RC-STALE-{idx}"
        state = make_admitted_case_state(
            case_id=case_id,
            tenant_id="tenant_01",
            intent=intent,
            policy=PolicyEvaluationResult(
                outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
                evaluated_intent_hash=intent.intent_hash,
                policy_version="PP-POLICY-V1",
            ),
        )
        grant = GrantIssuer.issue_grant(state, secret=TEST_GRANT_SECRET)
        active_state = state.model_copy(update={"grant": grant})
        db.save_case(active_state)

        # Transition grant to terminal status
        term_grant = grant.model_copy(update={"status": term_status, "used": term_used})
        term_state = state.model_copy(update={"grant": term_grant})
        db.save_case(term_state)

        # Confirm durable DB has terminal status
        with db.get_connection() as conn:
            row = conn.execute("SELECT status, used FROM handoff_grants WHERE grant_id = ?", (grant.grant_id,)).fetchone()
            assert row["status"] == term_status.value
            assert row["used"] == (1 if term_used else 0)

        # Attempt to save stale active_state
        with pytest.raises(StaleCaseStateError):
            db.save_case(active_state)

        # Verify durable DB was NOT modified
        with db.get_connection() as conn:
            row = conn.execute("SELECT status, used FROM handoff_grants WHERE grant_id = ?", (grant.grant_id,)).fetchone()
            assert row["status"] == term_status.value
            assert row["used"] == (1 if term_used else 0)


def test_active_grant_with_used_true_invariant_violation(tmp_path):
    """Section C & D Requirement: An ACTIVE grant with used=True is an invariant violation."""
    db_path = tmp_path / "invariant_used.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        case_id="RC-INV-USED",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    grant = GrantIssuer.issue_grant(state, secret=TEST_GRANT_SECRET)

    # Invariant violation: ACTIVE + used=True
    bad_grant = grant.model_copy(update={"status": GrantStatus.ACTIVE, "used": True})
    bad_state = state.model_copy(update={"grant": bad_grant})

    with pytest.raises(ValueError, match="Invariant violation"):
        db.save_case(bad_state)


# ==============================================================================
# SECTION D: Explicit Irreversible GrantStatus Lattice
# ==============================================================================

def test_validate_grant_transition_all_pairwise_statuses():
    """Section D Requirement: Exhaustive pairwise validation of the GrantStatus lattice."""
    all_statuses = [
        GrantStatus.NOT_ISSUED,
        GrantStatus.ACTIVE,
        GrantStatus.CONSUMED,
        GrantStatus.SUSPENDED_FOR_RECONCILIATION,
        GrantStatus.INVALIDATED,
        GrantStatus.EXPIRED,
    ]

    coherent_used = {
        GrantStatus.NOT_ISSUED: False,
        GrantStatus.ACTIVE: False,
        GrantStatus.CONSUMED: True,
        GrantStatus.SUSPENDED_FOR_RECONCILIATION: True,
        GrantStatus.INVALIDATED: False,
        GrantStatus.EXPIRED: False,
    }

    for curr in all_statuses:
        for target in all_statuses:
            # 1. Same-state transition (idempotent only with coherent used flag)
            if curr == target:
                u = coherent_used[curr]
                validate_grant_transition(curr, u, target, u)
                incoherent_u = not u
                if curr == GrantStatus.ACTIVE:
                    with pytest.raises(ValueError):
                        validate_grant_transition(curr, incoherent_u, target, incoherent_u)
                elif curr in (GrantStatus.CONSUMED, GrantStatus.SUSPENDED_FOR_RECONCILIATION):
                    with pytest.raises(GrantTransitionError):
                        validate_grant_transition(curr, incoherent_u, target, incoherent_u)
                continue

            # 2. From NOT_ISSUED / None: can only become ACTIVE unused
            if curr == GrantStatus.NOT_ISSUED:
                if target == GrantStatus.ACTIVE:
                    validate_grant_transition(curr, False, target, False)
                else:
                    with pytest.raises(GrantTransitionError):
                        target_u = coherent_used[target]
                        validate_grant_transition(curr, False, target, target_u)
                continue

            # 3. From ACTIVE: can transition to any terminal status
            if curr == GrantStatus.ACTIVE:
                if target in TERMINAL_GRANT_STATUSES:
                    used = target in (GrantStatus.CONSUMED, GrantStatus.SUSPENDED_FOR_RECONCILIATION)
                    validate_grant_transition(curr, False, target, used)
                elif target == GrantStatus.NOT_ISSUED:
                    with pytest.raises(GrantTransitionError):
                        validate_grant_transition(curr, False, target, False)
                continue

            # 4. From any TERMINAL status: CANNOT transition to ACTIVE or any other terminal status
            if curr in TERMINAL_GRANT_STATUSES:
                target_u = coherent_used[target]
                if target == GrantStatus.ACTIVE:
                    with pytest.raises((StaleCaseStateError, ValueError)):
                        validate_grant_transition(curr, coherent_used[curr], target, False)
                else:
                    with pytest.raises(StaleCaseStateError):
                        validate_grant_transition(curr, coherent_used[curr], target, target_u)


def test_used_flag_cannot_revert_from_true_to_false():
    """Section D Requirement: used flag can only go False -> True, never True -> False."""
    with pytest.raises(StaleCaseStateError, match="Cannot revert used grant"):
        validate_grant_transition(
            current_status=GrantStatus.CONSUMED,
            current_used=True,
            new_status=GrantStatus.CONSUMED,
            new_used=False,
        )


# ==============================================================================
# SECTION E: Authoritative Snapshot Bound at Claim
# ==============================================================================

@pytest.mark.parametrize("mutation_field,mutation_val", [
    ("evidence", [EvidenceItem(id="EV-TAMPER", item_type="manual", title="Tampered", content_hash="hash999", finding="none", truth_state=TruthState.SUPPORTED)]),
    ("findings", [Finding(name="DESTINATION_UNCONFIRMED", truth_state=TruthState.CONTRADICTED, detail="Tampered finding")]),
    ("processing_authority", ProcessingAuthorityStatus.REJECTED),
    ("tenant_id", "tenant_compromised"),
    ("case_version", 99),
])
def test_post_grant_case_mutation_blocks_claim_and_leaves_zero_attempts(tmp_path, mutation_field, mutation_val):
    """Section E Requirement: Any post-grant change to authoritative case fields
    (evidence, findings, processing authority, tenant, case_version) before handoff claim
    causes bound snapshot mismatch, blocking claim and creating 0 attempts / items.
    """
    db_path = tmp_path / f"snap_tamper_{mutation_field}.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        case_id="RC-SNAP-TAMPER",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    state = state.model_copy(update={"phase": CasePhase.READY_FOR_HUMAN_HANDOFF})
    db.save_case(state)

    state = StateMachine.reduce(state, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    db.save_case(state)
    assert state.grant is not None

    # Tamper with the persisted case in DB
    tampered_state = state.model_copy(update={mutation_field: mutation_val})
    with db.get_connection() as conn:
        if mutation_field == "tenant_id":
            conn.execute(
                "UPDATE risk_cases SET tenant_id = ?, state_json = ? WHERE case_id = 'RC-SNAP-TAMPER'",
                (mutation_val, json.dumps(tampered_state.model_dump())),
            )
        else:
            conn.execute(
                "UPDATE risk_cases SET state_json = ? WHERE case_id = 'RC-SNAP-TAMPER'",
                (json.dumps(tampered_state.model_dump()),),
            )

    # Attempt handoff
    result = HandoffService.execute_handoff(state=state, adapter=adapter, grant_secret=TEST_GRANT_SECRET)

    # Must refuse claim
    assert result.phase != CasePhase.COMPLETE
    assert "snapshot does not match bound grant snapshot hash" in result.last_change

    # Verify zero adapter attempts and zero pending items created
    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM adapter_attempts").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM pending_approval_items").fetchone()[0] == 0


# ==============================================================================
# SECTION F: Recovery Integrity Failure is Typed and No-Retry
# ==============================================================================

@pytest.mark.parametrize("corrupt_field,corrupt_val", [
    ("status", "FAILED"),
    ("ambiguity_state", "SOME_AMBIGUITY"),
    ("pending_item_id", None),
    ("error_code", "SOME_ERROR_CODE"),
    ("error_message", "Unexpected error message"),
    ("case_id", "RC-WRONG-CASE"),
    ("grant_id", "GRANT-WRONG-GRANT"),
    ("idempotency_key", "IDEM-WRONG-KEY"),
])
def test_recovery_tuple_field_corruption_triggers_recovery_integrity_failure(tmp_path, corrupt_field, corrupt_val):
    """Section F Requirement: Corrupting any field in the attempt recovery tuple
    causes RECOVERY_INTEGRITY_FAILURE_NO_RETRY, enters OPERATOR_INTERVENTION,
    and durable grant remains terminal no-retry.
    """
    db_path = tmp_path / f"rec_tuple_corrupt_{corrupt_field}.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        case_id="RC-CORRUPT-TUPLE",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    state = state.model_copy(update={"phase": CasePhase.READY_FOR_HUMAN_HANDOFF})
    db.save_case(state)
    state = StateMachine.reduce(state, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    db.save_case(state)
    grant = state.grant
    assert grant is not None

    # Step 1: Submit valid handoff to populate durable attempt, item, and consumed grant
    dec, item, err = adapter.submit_handoff(grant=grant, intent=intent)
    assert dec == AdapterDecision.PENDING_ITEM_CREATED
    assert item is not None

    # Step 2: Corrupt the specific field in adapter_attempts
    with db.get_connection() as conn:
        conn.execute(
            f"UPDATE adapter_attempts SET {corrupt_field} = ? WHERE grant_id = ?",
            (corrupt_val, grant.grant_id),
        )

    # Step 3: Run recovery via HandoffService
    persisted_case = db.load_case("RC-CORRUPT-TUPLE")
    assert persisted_case is not None
    rec_result = HandoffService.execute_handoff(state=persisted_case, adapter=adapter, grant_secret=TEST_GRANT_SECRET)

    # Must fail recovery integrity
    assert rec_result.phase == CasePhase.OPERATOR_INTERVENTION
    assert rec_result.handoff.last_adapter_decision == AdapterDecision.RECOVERY_INTEGRITY_FAILURE_NO_RETRY
    assert rec_result.grant is not None
    assert rec_result.grant.status == GrantStatus.CONSUMED  # Preserves consumed terminal status
    assert rec_result.grant.used is True

    # Durable grant remains terminal
    with db.get_connection() as conn:
        grow = conn.execute("SELECT status, used FROM handoff_grants WHERE grant_id = ?", (grant.grant_id,)).fetchone()
        assert grow["status"] == "CONSUMED"
        assert grow["used"] == 1

    # Audit event recorded
    audit_events = [ev for ev in rec_result.audit if ev.event_type == "RECOVERY_INTEGRITY_FAILURE"]
    assert len(audit_events) == 1
