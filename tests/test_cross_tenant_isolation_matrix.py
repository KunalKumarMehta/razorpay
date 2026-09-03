"""Comprehensive Abuse Matrix and Isolation Verification for GitHub Issue #6.

Acceptance Criteria Verified:
1. No staging or production request can fall back to an implicit or default tenant.
2. Legacy unscoped interfaces are removed after all callers have migrated.
3. An abuse matrix attempts cross-tenant case, evidence, policy, grant, handoff, and audit operations using every role.
4. All cross-tenant attempts fail closed and the complete test suite remains green.
"""

import pytest
from fastapi.testclient import TestClient

from payoutproof.api.app import create_app
from payoutproof.core.config import AppConfig
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.core.crypto import compute_snapshot_hash
from payoutproof.core.enums import (
    CasePhase,
    PolicyOutcome,
    FindingName,
)
from payoutproof.core.models import (
    Finding,
    TruthState,
)
from payoutproof.grants.issuer import GrantIssuer, GrantVerifier
from payoutproof.policy.evaluator import PolicyGate
from payoutproof.storage.db import Database, DatabaseConsistencyError
from tests.helpers import (
    TEST_GRANT_SECRET,
    TEST_AUDIT_CHECKPOINT_SECRET,
    make_authorized_bundle_action,
    make_valid_authority_record,
    make_confirmed_intent,
    make_admitted_case_state,
)


@pytest.fixture
def matrix_client(tmp_path):
    db_path = tmp_path / "matrix_isolation.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    config = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(db_path),
    )
    app = create_app(config=config, db=db)
    return TestClient(app), db


# ==============================================================================
# CRITERION 1: No Request Can Fall Back to Implicit or Default Tenant
# ==============================================================================

def test_missing_or_blank_organization_header_rejected_on_all_guarded_routes(matrix_client):
    """Every non-exempt route strictly rejects missing, empty, or whitespace-only organization identity."""
    client, _ = matrix_client

    guarded_endpoints = [
        ("POST", "/api/cases", {"case_id": "RC-UNSCOPED-FAIL"}),
        ("GET", "/api/cases", None),
        ("GET", "/api/cases/RC-SOME-CASE", None),
        ("POST", "/api/cases/RC-SOME-CASE/dispatch", {"type": "RESET", "payload": {}}),
        ("GET", "/api/audit/verify/RC-SOME-CASE", None),
    ]

    for method, path, payload in guarded_endpoints:
        # 1. Header completely omitted
        if method == "POST":
            res_omitted = client.post(path, json=payload)
        else:
            res_omitted = client.get(path)
        assert res_omitted.status_code == 400, f"Expected 400 for {method} {path} without header, got {res_omitted.status_code}"
        assert "missing mandatory organization identity" in res_omitted.json()["detail"].lower()

        # 2. Header empty or whitespace
        for blank_val in ("", "   ", "\t\n"):
            headers = {"X-Organization-Id": blank_val}
            if method == "POST":
                res_blank = client.post(path, json=payload, headers=headers)
            else:
                res_blank = client.get(path, headers=headers)
            assert res_blank.status_code == 400, f"Expected 400 for {method} {path} with blank header '{blank_val}'"
            assert "missing mandatory organization identity" in res_blank.json()["detail"].lower()


def test_public_exempt_routes_accessible_without_organization_identity(matrix_client):
    """Liveness and release metadata endpoints are strictly public and exempt from tenancy requirement."""
    client, _ = matrix_client

    # /api/health succeeds without any organization header
    r_health = client.get("/api/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "HEALTHY"

    # /api/release succeeds without any organization header
    r_release = client.get("/api/release")
    assert r_release.status_code == 200
    assert "application_version" in r_release.json()


# ==============================================================================
# CRITERION 2: Legacy Unscoped Interfaces Removed
# ==============================================================================

def test_legacy_module_globals_removed():
    """Module-level singletons (db, adapter, _legacy_app) do not exist in api.app."""
    import payoutproof.api.app as app_mod
    assert not hasattr(app_mod, "db"), "legacy 'db' module attribute must be deleted"
    assert not hasattr(app_mod, "adapter"), "legacy 'adapter' module attribute must be deleted"
    assert not hasattr(app_mod, "_legacy_app"), "legacy '_legacy_app' module attribute must be deleted"


# ==============================================================================
# CRITERIA 3 & 4: Multi-Role Cross-Tenant Abuse Matrix Fails Closed
# ==============================================================================

ROLES_UNDER_TEST = [
    "Payment Operator",
    "Auditor",
    "Finance Control Owner",
    "Tenant Admin",
]


@pytest.mark.parametrize("role", ROLES_UNDER_TEST)
def test_cross_tenant_abuse_matrix_case_read_and_mutation(matrix_client, role):
    """An actor in org_attacker attempting to read or mutate a case in org_victim fails closed with HTTP 404."""
    client, db = matrix_client

    # Provision victim case under org_victim
    victim_case_id = f"RC-VICTIM-{role.replace(' ', '-').upper()}"
    res_create = client.post(
        "/api/cases",
        json={"case_id": victim_case_id, "tenant_id": "tenant_victim"},
        headers={"X-Organization-Id": "org_victim"},
    )
    assert res_create.status_code == 200
    assert res_create.json()["organization_id"] == "org_victim"

    # Attempt 1: Cross-tenant GET returns strict 404 (indistinguishable from missing case)
    attacker_headers = {
        "X-Organization-Id": "org_attacker",
        "X-Actor-Role": role,
    }
    res_get = client.get(f"/api/cases/{victim_case_id}", headers=attacker_headers)
    assert res_get.status_code == 404
    assert res_get.json()["detail"] == f"Case '{victim_case_id}' not found"

    # Non-existent comparison: verify exact same error envelope structure (zero existence leak)
    res_nonexistent = client.get("/api/cases/RC-DOES-NOT-EXIST", headers=attacker_headers)
    assert res_nonexistent.status_code == 404
    assert set(res_get.json().keys()) == set(res_nonexistent.json().keys())

    # Attempt 2: Cross-tenant Dispatch of mutating actions returns strict 404
    actions_to_abuse = [
        make_authorized_bundle_action(case_id=victim_case_id, authority=make_valid_authority_record().model_dump()),
        {"type": "EXTRACT_INTENT", "payload": {"counterparty": "Mallory", "amount": "999999"}},
        {"type": "CONFIRM_INTENT", "payload": {}},
        {"type": "INITIATE_HANDOFF", "payload": {}},
        {"type": "RESET", "payload": {}},
    ]

    for act in actions_to_abuse:
        res_disp = client.post(
            f"/api/cases/{victim_case_id}/dispatch",
            json=act,
            headers=attacker_headers,
        )
        assert res_disp.status_code == 404, f"Role '{role}' dispatch '{act['type']}' returned {res_disp.status_code}, expected 404"
        assert res_disp.json()["detail"] == f"Case '{victim_case_id}' not found"

    # Attempt 3: Cross-tenant Audit Verification returns strict 404
    res_audit = client.get(f"/api/audit/verify/{victim_case_id}", headers=attacker_headers)
    assert res_audit.status_code == 404
    assert res_audit.json()["detail"] == f"Case '{victim_case_id}' not found"


def test_cross_tenant_listing_strictly_partitions_organizations(matrix_client):
    """GET /api/cases exclusively lists cases belonging to the active organization."""
    client, _ = matrix_client

    # Seed 3 cases in org_alpha, 2 in org_beta
    for i in range(3):
        client.post(
            "/api/cases",
            json={"case_id": f"RC-ALPHA-{i}"},
            headers={"X-Organization-Id": "org_alpha"},
        )
    for i in range(2):
        client.post(
            "/api/cases",
            json={"case_id": f"RC-BETA-{i}"},
            headers={"X-Organization-Id": "org_beta"},
        )

    # org_alpha listing
    res_alpha = client.get("/api/cases", headers={"X-Organization-Id": "org_alpha"})
    assert res_alpha.status_code == 200
    alpha_cases = {c["case_id"] for c in res_alpha.json()}
    assert alpha_cases == {"RC-ALPHA-0", "RC-ALPHA-1", "RC-ALPHA-2"}

    # org_beta listing
    res_beta = client.get("/api/cases", headers={"X-Organization-Id": "org_beta"})
    assert res_beta.status_code == 200
    beta_cases = {c["case_id"] for c in res_beta.json()}
    assert beta_cases == {"RC-BETA-0", "RC-BETA-1"}

    # org_gamma (empty) listing
    res_gamma = client.get("/api/cases", headers={"X-Organization-Id": "org_gamma"})
    assert res_gamma.status_code == 200
    assert len(res_gamma.json()) == 0


def test_storage_level_cross_tenant_tampering_fails_closed(tmp_path):
    """Direct storage manipulation attempting cross-tenant case rescope fails closed."""
    db = Database(db_path=tmp_path / "tamper.db", audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    case_victim = StateMachine.initial_state(case_id="RC-STORAGE-VICTIM", organization_id="org_victim")
    db.save_case(case_victim)

    # Attempt to overwrite the case under a substituted organization
    case_tampered = case_victim.model_copy(update={"organization_id": "org_attacker"})
    with pytest.raises(DatabaseConsistencyError, match="conflicts with authoritative row organization_id"):
        db.save_case(case_tampered)


def test_cross_tenant_policy_and_grant_substitution_fails_closed():
    """Policy evaluation and grant issuance enforce strict organization identity."""
    # 1. Approved destination from org_alpha does NOT satisfy org_beta policy
    intent = make_confirmed_intent()
    callback_finding = Finding(
        name=FindingName.INDEPENDENT_CALLBACK.value,
        truth_state=TruthState.SUPPORTED,
        detail="Callback OK",
    )
    dest_finding_org_a = Finding(
        name=FindingName.DESTINATION_APPROVAL.value,
        truth_state=TruthState.SUPPORTED,
        detail="Approved for org_alpha",
        organization_id="org_alpha",
    )
    state_org_b = make_admitted_case_state(
        case_id="RC-CROSS-POLICY",
        organization_id="org_beta",
        intent=intent,
        findings=[callback_finding, dest_finding_org_a],
    )
    eval_b = PolicyGate.evaluate(state_org_b)
    assert eval_b.outcome == PolicyOutcome.STEP_UP_REQUIRED, "Foreign organization destination approval must fail closed"

    # 2. Grant issued for org_alpha fails HMAC verification when presented with org_beta
    eval_a = PolicyGate.evaluate(
        make_admitted_case_state(
            case_id="RC-GRANT-A",
            organization_id="org_alpha",
            intent=intent,
            findings=[callback_finding, dest_finding_org_a],
        )
    )
    ready_state = make_admitted_case_state(
        case_id="RC-GRANT-A",
        organization_id="org_alpha",
        intent=intent,
        findings=[callback_finding, dest_finding_org_a],
    ).model_copy(update={
        "phase": CasePhase.READY_FOR_HUMAN_HANDOFF,
        "policy": eval_a,
    })
    eval_a_final = eval_a.model_copy(update={
        "evaluated_snapshot_hash": compute_snapshot_hash(ready_state),
        "organization_id": "org_alpha",
    })
    ready_state = ready_state.model_copy(update={"policy": eval_a_final})
    grant_a = GrantIssuer.issue_grant(ready_state, secret=TEST_GRANT_SECRET)

    # Verifying grant with mismatched organization returns valid=False
    valid, err = GrantVerifier.verify(
        grant=grant_a,
        current_intent_hash=intent.intent_hash,
        secret=TEST_GRANT_SECRET,
        expected_organization_id="org_beta",
    )
    assert valid is False
    assert "organization" in str(err).lower()
