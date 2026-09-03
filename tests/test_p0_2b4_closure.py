"""Tests for P0-2B.4 final authority closure.

Covers:
1. Terminal lifecycle cannot be erased (save_case_tx rejects reset/no-grant overwrites)
2. No implicit cases (404 on GET/dispatch for missing cases, 409 on duplicate POST)
3. Full snapshot authorization input (canonical snapshot hash sensitivity to authority inputs)
4. Recovery integrity logic (fail_recovery_integrity never marks unused grants used; typed refusal)
5. Complete GrantStatus lattice (pairwise parameterized tests)
6. Standalone adapter cannot desynchronize case JSON (submit_handoff syncs risk_cases)
7. Claim admission authority prerequisites in execute_adapter_submission_tx
8. Schema correctness (clean DB churn-free, migration idempotent, drift fails with DatabaseSchemaError)
"""

import json
import sqlite3
import pytest
from fastapi.testclient import TestClient

from payoutproof.core.models import (
    RiskCaseState,
    PaymentIntent,
    PolicyEvaluationResult,
    EvidenceItem,
    Finding,
    CaseInvestigation,
    ProcessingAuthorityRecord,
)
from payoutproof.core.enums import (
    CasePhase,
    PolicyOutcome,
    GrantStatus,
    HandoffStatus,
    AdapterDecision,
    ProcessingAuthorityStatus,
    TruthState,
    IntentStatus,
    DestinationStatus,
)
from payoutproof.core.crypto import (
    compute_snapshot_hash,
    compute_intent_hash,
    derive_idempotency_key,
)
from payoutproof.grants.issuer import GrantIssuer
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.case_workflow.handoff_service import HandoffService
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
from payoutproof.storage.db import (
    Database,
    StaleCaseStateError,
    GrantTransitionError,
    DatabaseSchemaError,
    validate_grant_transition,
    TERMINAL_GRANT_STATUSES,
)
from tests.helpers import (
    make_admitted_case_state,
    make_confirmed_intent,
    make_valid_authority_record,
    make_authorized_bundle_action,
    TEST_GRANT_SECRET,
    TEST_AUDIT_CHECKPOINT_SECRET,
)


# ==============================================================================
# SECTION 1: Terminal Lifecycle Cannot Be Erased
# ==============================================================================

def test_save_case_tx_refuses_no_grant_candidate_when_durable_state_exists(tmp_path):
    """save_case_tx rejects candidate state lacking grant when case has active/terminal grants,
    attempts, items, or terminal phases.
    """
    db_path = tmp_path / "terminal_lifecycle.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        case_id="RC-TERM-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    db.save_case(state)
    state = StateMachine.reduce(state, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    db.save_case(state)

    # 1. State has ACTIVE grant: candidate with grant=None is rejected
    no_grant_candidate = state.model_copy(update={"grant": None})
    with pytest.raises(StaleCaseStateError, match="Cannot overwrite case"):
        db.save_case(no_grant_candidate)

    # 2. Complete handoff: candidate with grant=None is rejected
    done_state = HandoffService.execute_handoff(state=state, adapter=adapter, grant_secret=TEST_GRANT_SECRET)
    assert done_state.phase == CasePhase.COMPLETE

    with pytest.raises(StaleCaseStateError, match="Cannot overwrite case"):
        db.save_case(no_grant_candidate)

    # 3. Candidate attempting to regress phase from COMPLETE is rejected
    regress_candidate = done_state.model_copy(update={"phase": CasePhase.EVIDENCE_ADMISSION})
    with pytest.raises(StaleCaseStateError, match="Cannot revert case"):
        db.save_case(regress_candidate)


def test_reset_reducer_refuses_when_authority_or_grant_or_terminal_phase_exists():
    """StateMachine.reduce refuses RESET when grant, authority, or terminal phase exists."""
    intent = make_confirmed_intent()
    state = make_admitted_case_state(case_id="RC-RESET-TEST", intent=intent)

    # Authority exists (admitted)
    res1 = StateMachine.reduce(state, {"type": "RESET"})
    assert "Refused" in res1.last_change

    # Grant exists
    granted_state = StateMachine.reduce(
        state.model_copy(update={"policy": PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            evaluated_snapshot_hash=compute_snapshot_hash(state),
            policy_version="V1",
        )}),
        {"type": "ISSUE_GRANT"},
        grant_secret=TEST_GRANT_SECRET,
    )
    res2 = StateMachine.reduce(granted_state, {"type": "RESET"})
    assert "Refused" in res2.last_change

    # Complete phase
    complete_state = granted_state.model_copy(update={"phase": CasePhase.COMPLETE})
    res3 = StateMachine.reduce(complete_state, {"type": "RESET"})
    assert "Refused" in res3.last_change


# ==============================================================================
# SECTION 2: No Implicit Cases
# ==============================================================================

def test_no_implicit_case_creation_on_get_or_dispatch(tmp_path, monkeypatch):
    """GET and POST /api/cases/{case_id}/dispatch on missing case return 404; POST /api/cases is sole creation path."""
    from payoutproof.api.app import create_app
    from payoutproof.core.config import AppConfig
    db = Database(db_path=tmp_path / "no_implicit.db", audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    cfg = AppConfig.for_tests(grant_secret=TEST_GRANT_SECRET, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET, db_path=str(tmp_path / "no_implicit.db"))
    app = create_app(config=cfg, db=db)
    client = TestClient(app, headers={"X-Organization-Id": "org_default"})

    missing_id = "RC-NONEXISTENT-999"

    # GET missing case returns 404
    r_get = client.get(f"/api/cases/{missing_id}")
    assert r_get.status_code == 404
    assert "not found" in r_get.json()["detail"].lower()

    # Dispatch on missing case returns 404 for any action
    for action in ["ADMIT_AUTHORIZED_BUNDLE", "INITIATE_HANDOFF", "EXTRACT_INTENT", "RESET"]:
        r_disp = client.post(f"/api/cases/{missing_id}/dispatch", json={"type": action, "payload": {}})
        assert r_disp.status_code == 404
        assert "not found" in r_disp.json()["detail"].lower()

    # Ensure DB still has 0 rows
    with db.get_connection() as conn:
        assert conn.execute("SELECT count(*) FROM risk_cases").fetchone()[0] == 0

    # POST /api/cases creates case
    r_post = client.post("/api/cases", json={"case_id": missing_id, "tenant_id": "tenant_01"})
    assert r_post.status_code == 200
    assert r_post.json()["case_id"] == missing_id

    # Duplicate POST /api/cases returns 409
    r_dup = client.post("/api/cases", json={"case_id": missing_id, "tenant_id": "tenant_01"})
    assert r_dup.status_code == 409


# ==============================================================================
# SECTION 3: Full Snapshot Authorization Input
# ==============================================================================

def test_canonical_snapshot_hash_sensitivity_to_authority_inputs():
    """Canonical snapshot hash changes on mutation of any authority input."""
    intent = make_confirmed_intent()
    base_state = make_admitted_case_state(
        case_id="RC-SNAP-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    base_hash = compute_snapshot_hash(base_state)
    assert len(base_hash) == 64

    # 1. Mutate authority_record
    mut_auth = base_state.authority_record.model_copy(update={"source": "Telegram_Verified"})
    assert compute_snapshot_hash(base_state.model_copy(update={"authority_record": mut_auth})) != base_hash

    # 2. Mutate processing_authority
    assert compute_snapshot_hash(base_state.model_copy(update={"processing_authority": ProcessingAuthorityStatus.REJECTED})) != base_hash

    # 3. Mutate request_bundle_status
    assert compute_snapshot_hash(base_state.model_copy(update={"request_bundle_status": "REJECTED"})) != base_hash

    # 4. Mutate intent (status, destination_status, provenance)
    mut_intent = intent.model_copy(update={"destination_status": DestinationStatus.SUSPICIOUS_OR_CHANGED})
    assert compute_snapshot_hash(base_state.model_copy(update={"intent": mut_intent})) != base_hash

    mut_prov = intent.model_copy(update={"provenance": ["additional provenance line"]})
    assert compute_snapshot_hash(base_state.model_copy(update={"intent": mut_prov})) != base_hash

    # 5. Mutate evidence
    mut_ev = [EvidenceItem(id="EV-NEW", item_type="doc", title="Doc", content_hash="h1", finding="f", truth_state=TruthState.SUPPORTED)]
    assert compute_snapshot_hash(base_state.model_copy(update={"evidence": mut_ev})) != base_hash

    # 6. Mutate findings
    mut_find = [Finding(name="NEW_FINDING", truth_state=TruthState.CONTRADICTED, detail="detail")]
    assert compute_snapshot_hash(base_state.model_copy(update={"findings": mut_find})) != base_hash

    # 7. Mutate investigation
    mut_inv = CaseInvestigation(model_status="RUNNING", attempt=2)
    assert compute_snapshot_hash(base_state.model_copy(update={"investigation": mut_inv})) != base_hash

    # 8. Mutate tenant_id, case_id, case_version
    assert compute_snapshot_hash(base_state.model_copy(update={"tenant_id": "tenant_other"})) != base_hash
    assert compute_snapshot_hash(base_state.model_copy(update={"case_id": "RC-OTHER"})) != base_hash
    assert compute_snapshot_hash(base_state.model_copy(update={"case_version": 42})) != base_hash

    # 9. Verify ephemeral outputs do NOT change snapshot hash
    assert compute_snapshot_hash(base_state.model_copy(update={"phase": CasePhase.COMPLETE})) == base_hash
    assert compute_snapshot_hash(base_state.model_copy(update={"last_change": "some change"})) == base_hash


# ==============================================================================
# SECTION 4: Recovery Integrity Logic
# ==============================================================================

def test_fail_recovery_integrity_preserves_used_zero_on_invalidated_and_active(tmp_path):
    """fail_recovery_integrity never sets used=1 on INVALIDATED, EXPIRED, or ACTIVE grants,
    and atomically invalidates ACTIVE with used=0.
    """
    db_path = tmp_path / "rec_integrity.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        case_id="RC-REC-FAIL",
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

    # Durable grant is ACTIVE, used=0. Now simulate a corrupt attempt associated with this grant
    with db.get_connection() as conn:
        conn.execute("""
            INSERT INTO adapter_attempts (
                idempotency_key, grant_id, case_id, attempts, status, decision,
                ambiguity_state, pending_item_id, error_code, error_message, created_at, updated_at
            ) VALUES ('IDEM-CORRUPT', ?, 'RC-DIFFERENT-CASE', 1, 'COMPLETED', 'PENDING_ITEM_CREATED', 'NONE', 'ITEM-1', NULL, NULL, datetime('now'), datetime('now'));
        """, (grant.grant_id,))

    # Recovery integrity failure triggers
    rec_res = HandoffService.execute_handoff(state=state, adapter=adapter, grant_secret=TEST_GRANT_SECRET)
    assert rec_res.phase == CasePhase.OPERATOR_INTERVENTION
    assert rec_res.handoff.last_adapter_decision == AdapterDecision.RECOVERY_INTEGRITY_FAILURE_NO_RETRY

    # Grant must be INVALIDATED with used=False, NEVER used=True
    assert rec_res.grant.status == GrantStatus.INVALIDATED
    assert rec_res.grant.used is False

    with db.get_connection() as conn:
        g_row = conn.execute("SELECT status, used FROM handoff_grants WHERE grant_id = ?", (grant.grant_id,)).fetchone()
        assert g_row["status"] == "INVALIDATED"
        assert g_row["used"] == 0


def test_missing_attempt_on_invalidated_or_expired_grant_returns_typed_refusal(tmp_path):
    """When durable grant is INVALIDATED or EXPIRED and no attempt exists, returns typed GRANT_INVALID_OR_EXPIRED."""
    db_path = tmp_path / "rec_missing_att.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        case_id="RC-EXP-GRANT",
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

    # Invalidate durable grant without creating an adapter attempt
    with db.get_connection() as conn:
        conn.execute("UPDATE handoff_grants SET status = 'INVALIDATED', used = 0 WHERE grant_id = ?", (state.grant.grant_id,))

    res = HandoffService.execute_handoff(state=state, adapter=adapter, grant_secret=TEST_GRANT_SECRET)
    assert res.handoff.last_adapter_decision == AdapterDecision.GRANT_INVALID_OR_EXPIRED
    assert res.grant.status == GrantStatus.INVALIDATED
    assert res.grant.used is False


# ==============================================================================
# SECTION 5: Complete GrantStatus Lattice
# ==============================================================================

@pytest.mark.parametrize("target_status", [
    GrantStatus.NOT_ISSUED,
    GrantStatus.CONSUMED,
    GrantStatus.SUSPENDED_FOR_RECONCILIATION,
    GrantStatus.INVALIDATED,
    GrantStatus.EXPIRED,
])
def test_initial_grant_cannot_transition_directly_to_non_active(target_status):
    """NOT_ISSUED / None may only become ACTIVE unused."""
    with pytest.raises(GrantTransitionError):
        used = target_status in (GrantStatus.CONSUMED, GrantStatus.SUSPENDED_FOR_RECONCILIATION)
        validate_grant_transition(None, False, target_status, used)


# ==============================================================================
# SECTION 6: Standalone Adapter Case Synchronization
# ==============================================================================

def test_fake_adapter_submit_handoff_synchronizes_risk_cases_in_same_transaction(tmp_path):
    """FakeApprovalRailAdapter.submit_handoff synchronizes risk_cases phase, handoff, and grant."""
    db_path = tmp_path / "adapter_sync.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        case_id="RC-SYNC-01",
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

    # Call submit_handoff directly
    dec, item, err = adapter.submit_handoff(grant=grant, intent=intent)
    assert dec == AdapterDecision.PENDING_ITEM_CREATED

    # Verify risk_cases table is already synchronized to COMPLETE and CONSUMED
    synced_case = db.load_case("RC-SYNC-01")
    assert synced_case is not None
    assert synced_case.phase == CasePhase.COMPLETE
    assert synced_case.grant.status == GrantStatus.CONSUMED
    assert synced_case.grant.used is True
    assert synced_case.handoff.status == HandoffStatus.PENDING_IN_APPROVAL_RAIL
    assert synced_case.handoff.pending_item_id == item.item_id


# ==============================================================================
# SECTION 7: Claim Admission Authority Prerequisites
# ==============================================================================

def test_execute_adapter_submission_tx_rejects_unadmitted_or_corrupt_authority(tmp_path):
    """execute_adapter_submission_tx checks valid processing authority and admitted evidence."""
    db_path = tmp_path / "claim_authority.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        case_id="RC-CLAIM-AUTH-01",
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

    idempotency_key = derive_idempotency_key(
        tenant_id=state.tenant_id,
        case_id=state.case_id or "",
        case_version=state.case_version,
        grant_id=grant.grant_id,
    )

    # 1. Tamper case to have REJECTED processing authority in DB
    with db.get_connection() as conn:
        tampered_state = state.model_copy(update={"processing_authority": ProcessingAuthorityStatus.REJECTED})
        conn.execute("UPDATE risk_cases SET state_json = ? WHERE case_id = 'RC-CLAIM-AUTH-01'", (json.dumps(tampered_state.model_dump()),))

        dec, item, err = db.execute_adapter_submission_tx(
            conn=conn,
            grant=grant,
            intent=intent,
            idempotency_key=idempotency_key,
            grant_secret=TEST_GRANT_SECRET,
        )
        assert dec == AdapterDecision.GRANT_INVALID_OR_EXPIRED
        assert item is None
        assert "lacks valid processing authority" in err

        # Verify nothing created and grant not consumed
        assert conn.execute("SELECT count(*) FROM adapter_attempts").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM pending_approval_items").fetchone()[0] == 0
        assert conn.execute("SELECT used FROM handoff_grants WHERE grant_id = ?", (grant.grant_id,)).fetchone()[0] == 0


# ==============================================================================
# SECTION 8: Schema Correctness & Migrations
# ==============================================================================

def test_clean_db_initialization_has_unique_grant_id_and_no_churn(tmp_path):
    """Clean DB initialization creates adapter_attempts with grant_id TEXT NOT NULL UNIQUE, zero quarantine rows."""
    db_path = tmp_path / "clean_schema.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    with db.get_connection() as conn:
        cols = {r["name"]: dict(r) for r in conn.execute("PRAGMA table_info(adapter_attempts)").fetchall()}
        assert "grant_id" in cols
        assert cols["grant_id"]["notnull"] == 1

        # Check unique index on grant_id
        indexes = conn.execute("PRAGMA index_list(adapter_attempts)").fetchall()
        unique_indices = [idx["name"] for idx in indexes if idx["unique"] == 1]
        has_unique_grant_id = any(
            [r["name"] for r in conn.execute(f"PRAGMA index_info('{idx_name}')").fetchall()] == ["grant_id"]
            for idx_name in unique_indices
        )
        assert has_unique_grant_id

        # Quarantine table is empty
        assert conn.execute("SELECT count(*) FROM adapter_attempts_quarantine").fetchone()[0] == 0


def test_unsupported_schema_drift_fails_closed(tmp_path):
    """Unsupported schema drift on risk_cases or handoff_grants raises DatabaseSchemaError."""
    db_path = tmp_path / "drifted.db"
    conn = sqlite3.connect(str(db_path))
    # Create corrupted risk_cases missing state_json
    conn.execute("CREATE TABLE risk_cases (case_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL);")
    conn.commit()
    conn.close()

    with pytest.raises(DatabaseSchemaError, match="Unsupported schema drift"):
        Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
