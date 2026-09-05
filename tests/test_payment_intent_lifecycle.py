"""Comprehensive test suite for Payment Intent Confirmation, Correction, and Invalidation (Issue #17).

Acceptance Criteria:
1. The review interface shows every material field, its provenance, confidence, conflicts, provider version, and unresolved state.
2. Operators can correct extracted values before confirmation, and the audit records original and corrected values safely.
3. Confirmation binds the exact counterparty, destination, amount, purpose, and originating instruction into a stable intent identity.
4. Any material edit after confirmation invalidates the prior evaluation and every associated Handoff Grant.
5. Invalidation clears intent_hash, revokes active grants, resets policy evaluation, and fails downstream handoffs closed.
6. Role-based access control adheres to the frozen action role matrix and maker-checker rules.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from payoutproof.api.app import create_app
from payoutproof.api.actions import ALLOWED_ACTIONS
from payoutproof.auth.oidc import OIDCProviderClient
from payoutproof.auth.roles import (
    ACTION_ROLE_MATRIX,
    Role,
    validate_matrix_covers_allowed_actions,
    role_can_dispatch,
)
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.core.config import AppConfig
from payoutproof.core.crypto import compute_intent_hash
from payoutproof.core.enums import (
    CasePhase,
    DestinationStatus,
    FindingName,
    GrantStatus,
    HandoffStatus,
    IntentStatus,
    PolicyOutcome,
    TruthState,
)
from payoutproof.core.models import Finding, PaymentIntent, RiskCaseState
from payoutproof.core.providers import FixedClock
from payoutproof.intent import correct_intent, confirm_intent, invalidate_intent
from payoutproof.storage.db import Database
from payoutproof.testing.fake_oidc import (
    FakeOIDCProvider,
    build_fake_oidc_app,
    TEST_ISSUER,
    TEST_CLIENT_ID,
    TEST_CLIENT_SECRET,
    TEST_REDIRECT_URI,
)
from tests.helpers import (
    TEST_GRANT_SECRET,
    TEST_AUDIT_CHECKPOINT_SECRET,
    make_authorized_bundle_action,
    make_valid_authority_record,
)


def test_action_matrix_completeness():
    """Verify that CORRECT_INTENT and INVALIDATE_INTENT are recognized in ALLOWED_ACTIONS and ACTION_ROLE_MATRIX."""
    validate_matrix_covers_allowed_actions()
    assert "CORRECT_INTENT" in ALLOWED_ACTIONS
    assert "INVALIDATE_INTENT" in ALLOWED_ACTIONS

    assert role_can_dispatch("CORRECT_INTENT", Role.PAYMENT_OPERATOR.value)
    assert not role_can_dispatch("CORRECT_INTENT", Role.FINANCE_CONTROL_OWNER.value)
    assert not role_can_dispatch("CORRECT_INTENT", Role.AUDITOR.value)

    assert role_can_dispatch("INVALIDATE_INTENT", Role.PAYMENT_OPERATOR.value)
    assert role_can_dispatch("INVALIDATE_INTENT", Role.FINANCE_CONTROL_OWNER.value)
    assert not role_can_dispatch("INVALIDATE_INTENT", Role.AUDITOR.value)


def test_intent_unit_lifecycle_pure_functions():
    """Unit test for correct_intent, confirm_intent, and invalidate_intent pure functions."""
    raw_intent = PaymentIntent(
        counterparty="Acme Corp",
        destination="026291800001191",
        amount="425000",
        currency="INR",
        purpose="Vendor invoice payment",
        instruction_reference="REF-001",
        provenance=["audio:file=sample.wav"],
        status=IntentStatus.EXTRACTED,
    )

    # 1. Pre-confirmation correction
    corrected, is_material = correct_intent(
        raw_intent,
        amount="500000",
        reason="Operator matched with tax invoice",
    )
    assert is_material is True
    assert corrected.amount == "500000"
    assert corrected.status == IntentStatus.EXTRACTED
    assert corrected.intent_hash is None
    assert any("operator_correction:Operator matched with tax invoice" in p for p in corrected.provenance)

    # 2. Confirmation freezes intent_hash
    confirmed = confirm_intent(corrected)
    assert confirmed.status == IntentStatus.CONFIRMED
    assert confirmed.intent_hash is not None
    assert confirmed.intent_hash == compute_intent_hash(confirmed)

    # 3. Post-confirmation material edit invalidates intent and clears hash
    post_edit, was_material = correct_intent(
        confirmed,
        destination="999999999999",
        reason="Account number typo",
    )
    assert was_material is True
    assert post_edit.status == IntentStatus.INVALIDATED
    assert post_edit.intent_hash is None
    assert post_edit.destination == "999999999999"

    # 4. Explicit invalidation
    explicit_inv = invalidate_intent(confirmed, reason="Suspected fraud call")
    assert explicit_inv.status == IntentStatus.INVALIDATED
    assert explicit_inv.intent_hash is None
    assert any("invalidation:Suspected fraud call" in p for p in explicit_inv.provenance)

    # 5. Missing required field prevents confirmation
    incomplete_intent = PaymentIntent(
        counterparty=None,
        destination="026291800001191",
        amount="425000",
        status=IntentStatus.EXTRACTED,
    )
    with pytest.raises(ValueError, match="missing required fields"):
        confirm_intent(incomplete_intent)


@pytest.fixture
def test_env(tmp_path):
    clock = FixedClock()
    db_path = tmp_path / "intent_lifecycle_test.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    fake_idp = FakeOIDCProvider(clock=clock)
    idp_app = build_fake_oidc_app(fake_idp)
    transport = TestClient(idp_app, base_url=TEST_ISSUER)

    oidc_client = OIDCProviderClient(
        issuer=TEST_ISSUER,
        client_id=TEST_CLIENT_ID,
        client_secret=TEST_CLIENT_SECRET,
        transport=transport,
        clock=clock,
    )

    config = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(db_path),
        oidc_issuer=TEST_ISSUER,
        oidc_client_id=TEST_CLIENT_ID,
        oidc_client_secret=TEST_CLIENT_SECRET,
        oidc_redirect_uri=TEST_REDIRECT_URI,
        session_ttl_seconds=3600,
    )

    app = create_app(
        config=config,
        db=db,
        clock=clock,
        oidc_client=oidc_client,
    )
    client = TestClient(app, base_url="http://127.0.0.1:9413")
    return {
        "app": app,
        "client": client,
        "db": db,
        "clock": clock,
        "fake_idp": fake_idp,
        "idp_client": TestClient(idp_app),
    }


def _login(env, persona: str) -> TestClient:
    client = env["client"]
    idp_client = env["idp_client"]

    login_res = client.get(f"/api/auth/login?persona={persona}", follow_redirects=False)
    assert login_res.status_code == 307
    redirect_url = login_res.headers["location"]

    idp_res = idp_client.get(redirect_url, follow_redirects=False)
    assert idp_res.status_code == 307
    callback_url = idp_res.headers["location"]

    callback_res = client.get(callback_url, follow_redirects=False)
    assert callback_res.status_code == 303
    session_cookie = callback_res.cookies["payoutproof_session"]

    return TestClient(env["app"], cookies={"payoutproof_session": session_cookie})


def test_full_intent_lifecycle_api(test_env):
    """Integration test verifying GET intent review, pre-confirmation correction, confirmation, and post-confirmation invalidation."""
    op_client = _login(test_env, "payment_operator")
    fco_client = _login(test_env, "finance_control_owner")

    case_id = "RC-INTENT-001"
    create_res = op_client.post("/api/cases", json={"case_id": case_id})
    assert create_res.status_code == 200

    # 2. Admit authorized bundle
    admit_act = make_authorized_bundle_action(
        case_id=case_id,
        authority=make_valid_authority_record().model_dump(),
    )
    res = op_client.post(f"/api/cases/{case_id}/dispatch", json=admit_act)
    assert res.status_code == 200

    # 3. Extract intent (simulate extraction)
    extract_act = {
        "type": "EXTRACT_INTENT",
        "payload": {
            "counterparty": "Acme Industrial Supplies",
            "destination": "026291800001191",
            "amount": "425000",
            "currency": "INR",
            "purpose": "Invoice INV-2026-089",
            "instruction_reference": "REF-AUDIO-001",
            "provenance": ["audio:segment=0-4500:conf=0.96"],
        }
    }
    res = op_client.post(f"/api/cases/{case_id}/dispatch", json=extract_act)
    assert res.status_code == 200
    assert res.json()["intent"]["status"] == IntentStatus.EXTRACTED.value

    # 4. GET /api/cases/{case_id}/intent - Review interface
    review_res = op_client.get(f"/api/cases/{case_id}/intent")
    assert review_res.status_code == 200
    review_data = review_res.json()
    assert review_data["status"] == IntentStatus.EXTRACTED.value
    assert review_data["unresolved"] is True
    assert review_data["can_confirm"] is True
    assert review_data["material_fields"]["counterparty"] == "Acme Industrial Supplies"
    assert review_data["material_fields"]["amount"] == "425000"
    assert review_data["material_fields"]["destination"] == "026291800001191"
    assert len(review_data["provenance"]) > 0

    # 5. Pre-confirmation correction via POST /api/cases/{case_id}/intent/correct
    correct_res = op_client.post(
        f"/api/cases/{case_id}/intent/correct",
        json={
            "amount": "450000",
            "reason": "Corrected for added delivery fee per purchase order",
        },
    )
    assert correct_res.status_code == 200
    state_after_correct = correct_res.json()
    assert state_after_correct["intent"]["amount"] == "450000"
    assert state_after_correct["intent"]["status"] == IntentStatus.EXTRACTED.value
    assert state_after_correct["intent"]["intent_hash"] is None

    # Check audit ledger contains PAYMENT_INTENT_CORRECTED
    events = state_after_correct["audit"]
    assert any(e["event_type"] == "PAYMENT_INTENT_CORRECTED" for e in events)

    # 6. Confirmation via POST /api/cases/{case_id}/intent/confirm
    confirm_res = op_client.post(f"/api/cases/{case_id}/intent/confirm")
    assert confirm_res.status_code == 200
    confirmed_state = confirm_res.json()
    assert confirmed_state["intent"]["status"] == IntentStatus.CONFIRMED.value
    frozen_hash = confirmed_state["intent"]["intent_hash"]
    assert frozen_hash is not None

    # Review endpoint reflects confirmed state
    review_confirmed = op_client.get(f"/api/cases/{case_id}/intent").json()
    assert review_confirmed["status"] == IntentStatus.CONFIRMED.value
    assert review_confirmed["intent_hash"] == frozen_hash
    assert review_confirmed["unresolved"] is False
    assert review_confirmed["can_confirm"] is False

    # 7. Add step-up evidence, evaluate policy, and issue grant as FCO
    # Add callback evidence
    res_cb = op_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "ADD_CALLBACK_EVIDENCE", "payload": {}})
    assert res_cb.status_code == 200
    # Add destination approval
    res_dest = fco_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "ADD_DESTINATION_APPROVAL", "payload": {}})
    assert res_dest.status_code == 200
    # Evaluate policy
    res_eval = fco_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "EVALUATE_POLICY", "payload": {}})
    assert res_eval.status_code == 200
    assert res_eval.json()["policy"]["outcome"] == PolicyOutcome.ELIGIBLE_FOR_HANDOFF.value
    # Issue grant
    res_grant = fco_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "ISSUE_GRANT", "payload": {}})
    assert res_grant.status_code == 200
    grant_state = res_grant.json()
    assert grant_state["grant"]["status"] == GrantStatus.ACTIVE.value
    assert grant_state["grant"]["bound_intent_hash"] == frozen_hash

    # 8. Post-confirmation material edit invalidates evaluation and active grant
    edit_res = op_client.post(
        f"/api/cases/{case_id}/intent/correct",
        json={
            "counterparty": "Acme Global Solutions",
            "reason": "Entity name correction",
        },
    )
    assert edit_res.status_code == 200
    invalidated_state = edit_res.json()
    assert invalidated_state["intent"]["status"] == IntentStatus.INVALIDATED.value
    assert invalidated_state["intent"]["intent_hash"] is None
    assert invalidated_state["intent"]["counterparty"] == "Acme Global Solutions"
    # Active grant is revoked/invalidated
    assert invalidated_state["grant"]["status"] == GrantStatus.INVALIDATED.value
    # Policy outcome resets to HOLD
    assert invalidated_state["policy"]["outcome"] == PolicyOutcome.HOLD.value
    assert invalidated_state["phase"] == CasePhase.OPERATOR_INTERVENTION.value

    # Audit ledger records MATERIAL_INTENT_EDITED
    events = invalidated_state["audit"]
    assert any(e["event_type"] == "MATERIAL_INTENT_EDITED" for e in events)

    # 9. Downstream handoff initiation must fail closed
    handoff_res = fco_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "INITIATE_HANDOFF", "payload": {}})
    assert handoff_res.status_code == 200
    # Refusal recorded, status remains NOT_STARTED or FAILED
    assert handoff_res.json()["handoff"]["status"] in (HandoffStatus.NOT_STARTED.value, HandoffStatus.FAILED.value)

    # 10. Re-confirmation after correction restores CONFIRMED status
    reconfirm_res = op_client.post(f"/api/cases/{case_id}/intent/confirm")
    assert reconfirm_res.status_code == 200
    reconfirmed_state = reconfirm_res.json()
    assert reconfirmed_state["intent"]["status"] == IntentStatus.CONFIRMED.value
    new_frozen_hash = reconfirmed_state["intent"]["intent_hash"]
    assert new_frozen_hash is not None
    assert new_frozen_hash != frozen_hash

    # 11. Explicit Invalidation via POST /api/cases/{case_id}/intent/invalidate
    inv_res = op_client.post(
        f"/api/cases/{case_id}/intent/invalidate",
        json={"reason": "Suspected phishing callback detected"},
    )
    assert inv_res.status_code == 200
    explicit_inv_state = inv_res.json()
    assert explicit_inv_state["intent"]["status"] == IntentStatus.INVALIDATED.value
    assert explicit_inv_state["intent"]["intent_hash"] is None
    assert explicit_inv_state["phase"] == CasePhase.OPERATOR_INTERVENTION.value
    assert any(e["event_type"] == "PAYMENT_INTENT_INVALIDATED" for e in explicit_inv_state["audit"])


def test_intent_lifecycle_rbac_enforcement(test_env):
    """Test that unauthorized roles cannot correct, confirm, or invalidate intent."""
    op_client = _login(test_env, "payment_operator")
    fco_client = _login(test_env, "finance_control_owner")
    auditor_client = _login(test_env, "auditor")

    case_id = "RC-RBAC-INTENT-001"
    create_res = op_client.post("/api/cases", json={"case_id": case_id})
    assert create_res.status_code == 200

    # FCO cannot correct intent (maker-checker boundary: FCO is checker, not maker)
    res = fco_client.post(f"/api/cases/{case_id}/intent/correct", json={"amount": "100000"})
    assert res.status_code == 403

    # FCO cannot confirm intent (maker action)
    res = fco_client.post(f"/api/cases/{case_id}/intent/confirm")
    assert res.status_code == 403

    # Auditor is strictly read-only and cannot mutate
    res = auditor_client.post(f"/api/cases/{case_id}/intent/correct", json={"amount": "100000"})
    assert res.status_code == 403
    res = auditor_client.post(f"/api/cases/{case_id}/intent/confirm")
    assert res.status_code == 403
    res = auditor_client.post(f"/api/cases/{case_id}/intent/invalidate", json={"reason": "test"})
    assert res.status_code == 403

    # Auditor CAN read review interface
    read_res = auditor_client.get(f"/api/cases/{case_id}/intent")
    assert read_res.status_code == 200
