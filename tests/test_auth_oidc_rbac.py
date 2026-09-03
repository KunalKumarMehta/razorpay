"""Comprehensive test suite for GitHub Issue #7: OIDC Authentication, Role-Bound Sessions, RBAC, and Maker-Checker.

Acceptance Criteria:
1. Every operator request resolves to an authenticated session; unauthenticated requests fail with HTTP 401.
2. Sessions are bound to an OIDC-issued identity and carry a role claim mapped to the frozen role vocabulary.
3. Every mutating and reading action enforces role permissions; unauthorized actions fail with HTTP 403.
4. Session lifetime is bounded, revocable, and audited.
5. Maker-checker constraint: The operator who confirmed the Payment Intent cannot initiate handoff on the same case.
"""

import httpx
import pytest
from fastapi.testclient import TestClient

from payoutproof.api.app import create_app
from payoutproof.auth.oidc import OIDCProviderClient
from payoutproof.auth.roles import Role
from payoutproof.core.config import AppConfig
from payoutproof.core.providers import FixedClock
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


@pytest.fixture
def auth_fixture(tmp_path):
    clock = FixedClock()  # 2024-01-01T00:00:00Z
    db_path = tmp_path / "auth_test.db"
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


def _login_as(auth_fixture, persona: str) -> TestClient:
    client = auth_fixture["client"]
    idp_client = auth_fixture["idp_client"]

    login_res = client.get(f"/api/auth/login?persona={persona}", follow_redirects=False)
    assert login_res.status_code == 307
    redirect_url = login_res.headers["location"]

    idp_res = idp_client.get(redirect_url, follow_redirects=False)
    assert idp_res.status_code == 307
    callback_url = idp_res.headers["location"]

    callback_res = client.get(callback_url, follow_redirects=False)
    assert callback_res.status_code == 303
    assert "payoutproof_session" in callback_res.cookies
    session_cookie = callback_res.cookies["payoutproof_session"]

    auth_client = TestClient(auth_fixture["app"], cookies={"payoutproof_session": session_cookie})
    return auth_client


def test_unauthenticated_request_fails(auth_fixture):
    """Criterion 1: Unauthenticated request to auth/me returns 401."""
    client = auth_fixture["client"]
    res = client.get("/api/auth/me")
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]


def test_oidc_login_and_me_profile(auth_fixture):
    """Criteria 1 & 2: OIDC login establishes session with correct role and organization."""
    client = _login_as(auth_fixture, "payment_operator")
    res = client.get("/api/auth/me")
    assert res.status_code == 200
    data = res.json()
    assert data["role"] == "PAYMENT_OPERATOR"
    assert data["subject"] == "test-sub-payment-operator"
    assert data["organization_id"] == "org_test"
    assert data["tenant_id"] == "tenant_test"


def test_session_revocation_via_logout(auth_fixture):
    """Criterion 4: Logout revokes session and subsequent requests return 401."""
    client = _login_as(auth_fixture, "payment_operator")
    assert client.get("/api/auth/me").status_code == 200

    logout_res = client.post("/api/auth/logout")
    assert logout_res.status_code == 200

    res_after = client.get("/api/auth/me")
    assert res_after.status_code == 401


def test_session_expiry(auth_fixture):
    """Criterion 4: Expired session is rejected with 401."""
    client = _login_as(auth_fixture, "payment_operator")
    assert client.get("/api/auth/me").status_code == 200

    auth_fixture["clock"].advance(3601)

    res_expired = client.get("/api/auth/me")
    assert res_expired.status_code == 401


def test_auditor_role_is_strictly_read_only(auth_fixture):
    """Criterion 3: Auditor can read cases and verify audit, but cannot mutate or create."""
    po_client = _login_as(auth_fixture, "payment_operator")
    res_create = po_client.post("/api/cases", json={"case_id": "RC-AUDITOR-TEST"})
    assert res_create.status_code == 200

    auditor_client = _login_as(auth_fixture, "auditor")

    res_read = auditor_client.get("/api/cases/RC-AUDITOR-TEST")
    assert res_read.status_code == 200

    res_audit = auditor_client.get("/api/audit/verify/RC-AUDITOR-TEST")
    assert res_audit.status_code == 200
    assert res_audit.json()["is_valid"] is True

    res_auditor_create = auditor_client.post("/api/cases", json={"case_id": "RC-AUDITOR-FAIL"})
    assert res_auditor_create.status_code == 403

    res_disp = auditor_client.post(
        "/api/cases/RC-AUDITOR-TEST/dispatch",
        json={"type": "EXTRACT_INTENT", "payload": {}},
    )
    assert res_disp.status_code == 403


def test_payment_operator_cannot_issue_grant_or_initiate_handoff(auth_fixture):
    """Criterion 3: Payment Operator cannot issue grant or initiate handoff."""
    po_client = _login_as(auth_fixture, "payment_operator")
    case_id = "RC-PO-PRIVILEGE-TEST"
    assert po_client.post("/api/cases", json={"case_id": case_id}).status_code == 200

    res_grant = po_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "ISSUE_GRANT", "payload": {}})
    assert res_grant.status_code == 403

    res_handoff = po_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "INITIATE_HANDOFF", "payload": {}})
    assert res_handoff.status_code == 403


def test_maker_checker_constraint_confirm_and_handoff_by_same_subject(auth_fixture):
    """Criterion 5: The operator who confirmed the Payment Intent cannot initiate handoff on the same case."""
    fake_idp = auth_fixture["fake_idp"]
    # Register persona who has finance control owner role but same subject as payment operator
    fake_idp.register_persona(
        persona="hybrid_finance",
        sub="test-sub-payment-operator",
        name="Same Person as Maker",
        role="FINANCE_CONTROL_OWNER",
        tenant_id="tenant_test",
        organization_id="org_test",
    )

    po_client = _login_as(auth_fixture, "payment_operator")
    fco_client = _login_as(auth_fixture, "finance_control_owner")
    hybrid_fco_client = _login_as(auth_fixture, "hybrid_finance")

    case_id = "RC-MAKER-CHECKER-01"
    assert po_client.post("/api/cases", json={"case_id": case_id}).status_code == 200

    admit_act = make_authorized_bundle_action(
        case_id=case_id,
        authority=make_valid_authority_record().model_dump(),
    )
    assert po_client.post(f"/api/cases/{case_id}/dispatch", json=admit_act).status_code == 200

    extract_act = {
        "type": "EXTRACT_INTENT",
        "payload": {"counterparty": "Kaveri Components", "destination": "HDFC ••4821", "amount": "425000"},
    }
    assert po_client.post(f"/api/cases/{case_id}/dispatch", json=extract_act).status_code == 200

    confirm_act = {"type": "CONFIRM_INTENT", "payload": {}}
    assert po_client.post(f"/api/cases/{case_id}/dispatch", json=confirm_act).status_code == 200

    assert po_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "ADD_CALLBACK_EVIDENCE", "payload": {}}).status_code == 200

    assert fco_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "ADD_DESTINATION_APPROVAL", "payload": {}}).status_code == 200

    eval_res = fco_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "EVALUATE_POLICY", "payload": {}})
    assert eval_res.status_code == 200

    grant_res = fco_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "ISSUE_GRANT", "payload": {}})
    assert grant_res.status_code == 200

    # The same subject who confirmed the intent cannot initiate handoff even with FCO role
    res_violation = hybrid_fco_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "INITIATE_HANDOFF", "payload": {}})
    assert res_violation.status_code == 403
    assert "maker-checker separation" in res_violation.json()["detail"]

    # A different subject with FCO role CAN initiate handoff
    res_success = fco_client.post(f"/api/cases/{case_id}/dispatch", json={"type": "INITIATE_HANDOFF", "payload": {}})
    assert res_success.status_code == 200
    assert res_success.json()["handoff"]["status"] in ("PENDING", "PENDING_IN_APPROVAL_RAIL")
