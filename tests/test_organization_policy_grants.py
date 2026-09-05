"""Acceptance tests for GitHub Issue #5: Scope policy, grants, handoffs, and audit to organizations."""

import pytest
from payoutproof.core.models import (
    RiskCaseState,
    PaymentIntent,
    PolicyEvaluationResult,
    Finding,
    TruthState,
)
from payoutproof.core.enums import (
    CasePhase,
    PolicyOutcome,
    FindingName,
    HandoffStatus,
)
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.policy.evaluator import PolicyGate
from payoutproof.grants.issuer import GrantIssuer, GrantVerifier
from payoutproof.storage.db import Database
from payoutproof.case_workflow.handoff_service import HandoffService
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
from payoutproof.core.crypto import derive_idempotency_key, compute_snapshot_hash
from tests.helpers import make_admitted_case_state, make_confirmed_intent

TEST_GRANT_SECRET = "test_grant_signing_secret_for_org_tests_32bytes!"
TEST_AUDIT_SECRET = "test_audit_checkpoint_secret_for_org_tests!"


def _make_ready_case(case_id: str, org_id: str, tenant_id: str = "tenant_pilot") -> RiskCaseState:
    intent = make_confirmed_intent()
    findings = [
        Finding(
            name=FindingName.INDEPENDENT_CALLBACK.value,
            truth_state=TruthState.SUPPORTED,
            detail="Counterparty verified via callback",
        ),
        Finding(
            name=FindingName.DESTINATION_APPROVAL.value,
            truth_state=TruthState.SUPPORTED,
            detail="Approved destination for organization",
            organization_id=org_id,
        ),
    ]
    state = make_admitted_case_state(
        case_id=case_id,
        tenant_id=tenant_id,
        organization_id=org_id,
        intent=intent,
        findings=findings,
    )
    eval_res = PolicyGate.evaluate(state)
    assert eval_res.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
    state = state.model_copy(update={
        "phase": CasePhase.READY_FOR_HUMAN_HANDOFF,
        "policy": eval_res,
    })
    eval_res_final = eval_res.model_copy(update={
        "evaluated_snapshot_hash": compute_snapshot_hash(state),
        "organization_id": org_id,
    })
    return state.model_copy(update={"policy": eval_res_final})


def test_approved_destination_scoped_to_organization():
    """Approved Destination finding is valid only when evaluated within the matching organization."""
    intent = make_confirmed_intent()
    callback_finding = Finding(
        name=FindingName.INDEPENDENT_CALLBACK.value,
        truth_state=TruthState.SUPPORTED,
        detail="Counterparty verified via callback",
    )
    finding_org_a = Finding(
        name=FindingName.DESTINATION_APPROVAL.value,
        truth_state=TruthState.SUPPORTED,
        detail="Approved for org_alpha",
        organization_id="org_alpha",
    )

    case_org_a = make_admitted_case_state(
        case_id="RC-TEST-DEST-A",
        organization_id="org_alpha",
        intent=intent,
        findings=[callback_finding, finding_org_a],
    )
    case_org_b = make_admitted_case_state(
        case_id="RC-TEST-DEST-B",
        organization_id="org_beta",
        intent=intent,
        findings=[callback_finding, finding_org_a],
    )

    # Evaluation in org_alpha accepts approved destination
    eval_a = PolicyGate.evaluate(case_org_a)
    assert eval_a.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF

    # Evaluation of org_beta with org_alpha's approved destination rejects it (fails closed to STEP_UP_REQUIRED)
    eval_b = PolicyGate.evaluate(case_org_b)
    assert eval_b.outcome == PolicyOutcome.STEP_UP_REQUIRED


def test_grant_issuance_and_hmac_binds_organization_id():
    """HandoffGrant stamps organization_id and HMAC signature binds it."""
    case_state = _make_ready_case("RC-TEST-GRANT-1", org_id="org_alpha")

    grant = GrantIssuer.issue_grant(case_state, secret=TEST_GRANT_SECRET)
    assert grant.organization_id == "org_alpha"
    assert grant.tenant_id == "tenant_pilot"
    assert grant.case_id == "RC-TEST-GRANT-1"

    # Verifies cleanly with matching organization
    valid, err = GrantVerifier.verify(
        grant=grant,
        current_intent_hash=case_state.intent.intent_hash,
        secret=TEST_GRANT_SECRET,
        expected_organization_id="org_alpha",
    )
    assert valid is True
    assert err is None

    # Fails when verified with substituted organization
    valid_cross, err_cross = GrantVerifier.verify(
        grant=grant,
        current_intent_hash=case_state.intent.intent_hash,
        secret=TEST_GRANT_SECRET,
        expected_organization_id="org_beta",
    )
    assert valid_cross is False
    assert "organization" in str(err_cross).lower()


def test_cross_tenant_grant_substitution_rejected():
    """Substituting a valid grant from org_A onto a case in org_B is rejected."""
    case_a = _make_ready_case("RC-TEST-X-A", org_id="org_alpha")
    grant_a = GrantIssuer.issue_grant(case_a, secret=TEST_GRANT_SECRET)

    case_b = _make_ready_case("RC-TEST-X-B", org_id="org_beta")

    # Tampering grant onto case_b fails verification
    valid, err = GrantVerifier.verify(
        grant=grant_a,
        current_intent_hash=case_b.intent.intent_hash,
        secret=TEST_GRANT_SECRET,
        expected_organization_id=case_b.organization_id,
    )
    assert valid is False


def test_idempotency_key_derivation_distinguishes_organizations():
    """derive_idempotency_key produces different keys for different organization scopes."""
    key_alpha = derive_idempotency_key(
        tenant_id="tenant_pilot",
        case_id="RC-SAME-CASE",
        case_version=1,
        grant_id="HG-SAME-GRANT",
        organization_id="org_alpha",
    )
    key_beta = derive_idempotency_key(
        tenant_id="tenant_pilot",
        case_id="RC-SAME-CASE",
        case_version=1,
        grant_id="HG-SAME-GRANT",
        organization_id="org_beta",
    )
    key_unscoped = derive_idempotency_key(
        tenant_id="tenant_pilot",
        case_id="RC-SAME-CASE",
        case_version=1,
        grant_id="HG-SAME-GRANT",
        organization_id=None,
    )

    assert key_alpha != key_beta
    assert key_alpha != key_unscoped
    assert key_beta != key_unscoped


def test_audit_verification_fails_closed_on_cross_tenant_substitution(tmp_path):
    """Audit ledger verification fails closed if an audit event from another case is substituted."""
    db = Database(db_path=tmp_path / "audit_tamper.db", audit_checkpoint_secret=TEST_AUDIT_SECRET)

    case_1 = StateMachine.initial_state(case_id="RC-AUDIT-1", organization_id="org_alpha")
    case_2 = StateMachine.initial_state(case_id="RC-AUDIT-2", organization_id="org_beta")
    db.save_case(case_1)
    db.save_case(case_2)

    # Valid initially
    assert db.verify_case_audit("RC-AUDIT-1")["is_valid"] is True
    assert db.verify_case_audit("RC-AUDIT-2")["is_valid"] is True

    # Tamper: inject an audit row from case_2 into case_1
    with db.get_connection() as conn:
        row_2 = conn.execute("SELECT * FROM audit_events WHERE case_id = 'RC-AUDIT-2' AND seq = 1").fetchone()
        conn.execute(
            "UPDATE audit_events SET current_hash = ? WHERE case_id = 'RC-AUDIT-1' AND seq = 1",
            (row_2["current_hash"],),
        )
        conn.commit()

    # Tampered audit fails closed
    verification = db.verify_case_audit("RC-AUDIT-1")
    assert verification["is_valid"] is False


def test_tenant_bound_workflow_survives_restart_and_creates_at_most_one_pending_item(tmp_path):
    """The organization-bound handoff workflow creates exactly one pending item and survives restart."""
    db_file = tmp_path / "workflow_restart.db"
    db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_SECRET,
    )

    case_state = _make_ready_case("RC-RESTART-01", org_id="org_alpha")
    db.save_case(case_state)

    # Issue grant via StateMachine
    case_state = StateMachine.reduce(case_state, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    assert case_state.grant is not None
    assert case_state.grant.organization_id == "org_alpha"
    db.save_case(case_state)

    # Execute handoff
    completed_state = HandoffService.execute_handoff(state=case_state, adapter=adapter, grant_secret=TEST_GRANT_SECRET)
    assert completed_state.phase == CasePhase.COMPLETE
    assert completed_state.handoff.status == HandoffStatus.PENDING_IN_APPROVAL_RAIL

    # Verify pending approval item in DB has organization_id
    pending_item = db.get_pending_item(grant_id=case_state.grant.grant_id)
    assert pending_item is not None
    assert pending_item.organization_id == "org_alpha"
    assert pending_item.case_id == "RC-RESTART-01"

    # Simulate server restart by creating a brand new Database and Adapter connection
    db_restarted = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_SECRET)
    adapter_restarted = FakeApprovalRailAdapter(
        db=db_restarted,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_SECRET,
    )

    # Reload case
    reloaded_state = db_restarted.load_case("RC-RESTART-01")
    assert reloaded_state is not None
    assert reloaded_state.organization_id == "org_alpha"
    assert reloaded_state.phase == CasePhase.COMPLETE

    # Attempt replay / recovery on reloaded case
    replayed_state = HandoffService.execute_handoff(
        state=reloaded_state,
        adapter=adapter_restarted,
        grant_secret=TEST_GRANT_SECRET,
    )
    # Remains COMPLETE, creates no duplicate item
    assert replayed_state.phase == CasePhase.COMPLETE

    all_items = db_restarted.get_all_pending_items()
    assert len(all_items) == 1
    assert list(all_items.values())[0].organization_id == "org_alpha"
