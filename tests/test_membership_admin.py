"""Comprehensive acceptance and safety test suite for Issue #8:
Administer organization membership without Money Action authority.
"""

from datetime import datetime, timedelta, timezone
import secrets
import pytest
from fastapi.testclient import TestClient

from payoutproof.api.app import create_app
from payoutproof.core.config import DEFAULT_TEST_MEMBERSHIP_SECRET, AppConfig
from payoutproof.core.enums import (
    AdapterDecision,
    CasePhase,
    GrantStatus,
    HandoffStatus,
    MembershipRole,
    PolicyOutcome,
)
from payoutproof.core.models import RiskCaseState
from payoutproof.storage.db import Database
from tests.helpers import (
    TEST_AUDIT_CHECKPOINT_SECRET,
    TEST_GRANT_SECRET,
    make_authorized_bundle_action,
    make_valid_authority_record,
)

MEMBERSHIP_TABLES = (
    "organization_members",
    "member_roles",
    "membership_invitations",
    "membership_audit_events",
    "membership_audit_checkpoints",
)


def seed_admin_member(
    db: Database,
    organization_id: str = "org_pilot",
    email: str = "admin@pilot.test",
    display_name: str = "Pilot Admin",
    secret: str = DEFAULT_TEST_MEMBERSHIP_SECRET,
):
    """Seed an out-of-band first administrator and mint a valid bearer token."""
    member_id = f"mem_{secrets.token_hex(8)}"
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    expires_iso = (now_dt + timedelta(days=1)).isoformat()

    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO organization_members (
                member_id, organization_id, email, display_name, status, token_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'ACTIVE', 0, ?, ?)
            """,
            (member_id, organization_id, email, display_name, now_iso, now_iso),
        )
        conn.execute(
            """
            INSERT INTO member_roles (
                organization_id, member_id, role, granted_by, granted_at
            ) VALUES (?, ?, 'TENANT_ADMINISTRATOR', 'system_bootstrap', ?)
            """,
            (organization_id, member_id, now_iso),
        )
        conn.commit()

    token = Database._mint_membership_token(
        membership_secret=secret,
        member_id=member_id,
        organization_id=organization_id,
        token_version=0,
        issued_at=now_iso,
        expires_at=expires_iso,
    )
    return member_id, token


@pytest.fixture
def membership_app(tmp_path):
    db_path = tmp_path / "membership_test.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    config = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        membership_secret=DEFAULT_TEST_MEMBERSHIP_SECRET,
        db_path=str(db_path),
    )
    app = create_app(config=config, db=db)
    client = TestClient(app)
    return {"app": app, "client": client, "db": db, "config": config}


def test_barrier_one_dropping_membership_leaves_money_actions_operational(membership_app):
    """SYSTEM INVARIANT: Invariant 1 (Zero Autonomous Money Actions).

    Dropping all 5 membership tables leaves the Money Action surface 100% operational.
    """
    client = membership_app["client"]
    db = membership_app["db"]

    with db.get_connection() as conn:
        tables = {
            r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        }
    assert set(MEMBERSHIP_TABLES).issubset(tables)

    # Mechanically drop all 5 membership tables
    with db.get_connection() as conn:
        for table in MEMBERSHIP_TABLES:
            conn.execute(f"DROP TABLE IF EXISTS {table};")

    case_id = "RC-BARRIER-NO-MEMBERSHIP-01"

    org_headers = {"X-Organization-Id": "org_default"}

    # 1. Create case
    r = client.post("/api/cases", headers=org_headers, json={"case_id": case_id, "tenant_id": "tenant_01", "organization_id": "org_default"})
    assert r.status_code == 200

    # 2. Admit evidence
    r = client.post(
        f"/api/cases/{case_id}/dispatch",
        headers=org_headers,
        json=make_authorized_bundle_action(
            case_id=case_id,
            authority=make_valid_authority_record().model_dump(),
        ),
    )
    assert r.status_code == 200

    # 3. Extract + confirm + callback evidence + destination approval
    r = client.post(
        f"/api/cases/{case_id}/dispatch",
        headers=org_headers,
        json={
            "type": "EXTRACT_INTENT",
            "payload": {
                "counterparty": "Kaveri Components",
                "destination": "HDFC ••4821",
                "amount": "425000",
            },
        },
    )
    assert r.status_code == 200
    for action in ("CONFIRM_INTENT", "ADD_CALLBACK_EVIDENCE", "ADD_DESTINATION_APPROVAL"):
        r = client.post(f"/api/cases/{case_id}/dispatch", headers=org_headers, json={"type": action, "payload": {}})
        assert r.status_code == 200

    # 4. Policy Gate
    r = client.post(f"/api/cases/{case_id}/dispatch", headers=org_headers, json={"type": "EVALUATE_POLICY", "payload": {}})
    assert r.status_code == 200
    assert r.json()["policy"]["outcome"] == PolicyOutcome.ELIGIBLE_FOR_HANDOFF.value

    # 5. Grant issuance
    r = client.post(f"/api/cases/{case_id}/dispatch", headers=org_headers, json={"type": "ISSUE_GRANT", "payload": {}})
    assert r.status_code == 200
    assert r.json()["grant"]["status"] == GrantStatus.ACTIVE.value

    # 6. Handoff initiation
    r = client.post(f"/api/cases/{case_id}/dispatch", headers=org_headers, json={"type": "INITIATE_HANDOFF", "payload": {}})
    assert r.status_code == 200
    state = r.json()
    assert state["phase"] == CasePhase.COMPLETE.value
    assert state["handoff"]["status"] in ("PENDING", "PENDING_IN_APPROVAL_RAIL")
    assert state["grant"]["status"] == GrantStatus.CONSUMED.value
    assert state["grant"]["used"] is True

    # 7. Audit verification
    r = client.get(f"/api/audit/verify/{case_id}", headers=org_headers)
    assert r.status_code == 200
    assert r.json()["is_valid"] is True


def test_invitation_lifecycle_invite_accept_and_member_listing(membership_app):
    """Criterion 1: Tenant Administrators can invite, remove, and assign supported roles."""
    client = membership_app["client"]
    db = membership_app["db"]
    org_id = "org_pilot"

    admin_id, admin_token = seed_admin_member(db, organization_id=org_id)
    headers = {"Authorization": f"Bearer {admin_token}", "X-Organization-Id": org_id}

    # 1. Invite a member
    invite_payload = {
        "email": "operator@pilot.test",
        "role": MembershipRole.PAYMENT_OPERATOR.value,
    }
    r = client.post("/api/memberships/invitations", headers=headers, json=invite_payload)
    assert r.status_code == 200
    data = r.json()
    assert "invitation_id" in data
    assert "invitation_secret" in data
    assert data["status"] == "PENDING"
    inv_id = data["invitation_id"]
    inv_sec = data["invitation_secret"]

    # 2. Accept the invitation
    accept_payload = {
        "invitation_id": inv_id,
        "invitation_secret": inv_sec,
        "display_name": "Rohan Operator",
    }
    r_accept = client.post(
        "/api/memberships/invitations/accept",
        headers={"X-Organization-Id": org_id},
        json=accept_payload,
    )
    assert r_accept.status_code == 200
    member_data = r_accept.json()
    assert "bearer_token" in member_data
    assert member_data["email"] == "operator@pilot.test"
    op_token = member_data["bearer_token"]

    # 3. List members
    r_list = client.get("/api/memberships/members", headers=headers)
    assert r_list.status_code == 200
    members = r_list.json()
    assert len(members) == 2
    emails = {m["email"] for m in members}
    assert "admin@pilot.test" in emails
    assert "operator@pilot.test" in emails

    # Op member can query their own roles
    op_headers = {"Authorization": f"Bearer {op_token}", "X-Organization-Id": org_id}
    r_roles = client.get(f"/api/memberships/members/{member_data['member_id']}/roles", headers=op_headers)
    assert r_roles.status_code == 200
    assert r_roles.json()["roles"] == [MembershipRole.PAYMENT_OPERATOR.value]


def test_revocation_bound_immediate_on_removal(membership_app):
    """Criterion 3: Removing a member invalidates or revokes active access immediately."""
    client = membership_app["client"]
    db = membership_app["db"]
    org_id = "org_pilot"

    admin_id, admin_token = seed_admin_member(db, organization_id=org_id)
    admin_headers = {"Authorization": f"Bearer {admin_token}", "X-Organization-Id": org_id}

    # Invite and accept second member
    r = client.post(
        "/api/memberships/invitations",
        headers=admin_headers,
        json={"email": "temp@pilot.test", "role": MembershipRole.VIEWER.value},
    )
    inv = r.json()
    r_acc = client.post(
        "/api/memberships/invitations/accept",
        headers={"X-Organization-Id": org_id},
        json={
            "invitation_id": inv["invitation_id"],
            "invitation_secret": inv["invitation_secret"],
            "display_name": "Temp Viewer",
        },
    )
    temp_token = r_acc.json()["bearer_token"]
    temp_member_id = r_acc.json()["member_id"]
    temp_headers = {"Authorization": f"Bearer {temp_token}", "X-Organization-Id": org_id}

    # Active member can query their roles
    assert client.get(f"/api/memberships/members/{temp_member_id}/roles", headers=temp_headers).status_code == 200

    # Admin removes member
    r_rem = client.post(
        f"/api/memberships/members/{temp_member_id}/remove",
        headers=admin_headers,
        json={"reason": "Rotation completed"},
    )
    assert r_rem.status_code == 200
    assert r_rem.json()["status"] == "REMOVED"

    # Removed member's token fails IMMEDIATELY on the very next call
    r_blocked = client.get(f"/api/memberships/members/{temp_member_id}/roles", headers=temp_headers)
    assert r_blocked.status_code == 401


def test_elevation_and_zero_existence_oracle(membership_app):
    """Criterion 2: Membership and role changes require elevated authorization."""
    client = membership_app["client"]
    db = membership_app["db"]
    org_id = "org_pilot"

    admin_id, admin_token = seed_admin_member(db, organization_id=org_id)
    admin_headers = {"Authorization": f"Bearer {admin_token}", "X-Organization-Id": org_id}

    # Invite non-admin member
    r = client.post(
        "/api/memberships/invitations",
        headers=admin_headers,
        json={"email": "nonadmin@pilot.test", "role": MembershipRole.VIEWER.value},
    )
    inv = r.json()
    r_acc = client.post(
        "/api/memberships/invitations/accept",
        headers={"X-Organization-Id": org_id},
        json={
            "invitation_id": inv["invitation_id"],
            "invitation_secret": inv["invitation_secret"],
            "display_name": "Viewer",
        },
    )
    viewer_token = r_acc.json()["bearer_token"]
    viewer_headers = {"Authorization": f"Bearer {viewer_token}", "X-Organization-Id": org_id}

    # Non-admin attempting admin mutation -> 403 Forbidden
    r_forbidden = client.post(
        "/api/memberships/invitations",
        headers=viewer_headers,
        json={"email": "intruder@pilot.test", "role": MembershipRole.VIEWER.value},
    )
    assert r_forbidden.status_code == 403

    # Cross-tenant request -> 401 or 404 (indistinguishable refusal, zero-existence oracle)
    cross_headers = {"Authorization": f"Bearer {admin_token}", "X-Organization-Id": "org_other"}
    r_cross = client.post(
        "/api/memberships/invitations",
        headers=cross_headers,
        json={"email": "cross@pilot.test", "role": MembershipRole.VIEWER.value},
    )
    assert r_cross.status_code in (401, 404)


def test_last_admin_lock_and_self_mutation_guard(membership_app):
    """Last administrator cannot demote or remove themselves."""
    client = membership_app["client"]
    db = membership_app["db"]
    org_id = "org_pilot"

    admin_id, admin_token = seed_admin_member(db, organization_id=org_id)
    headers = {"Authorization": f"Bearer {admin_token}", "X-Organization-Id": org_id}

    # 1. Admin cannot remove themselves
    r_self_rem = client.post(
        f"/api/memberships/members/{admin_id}/remove",
        headers=headers,
        json={"reason": "Self removal attempt"},
    )
    assert r_self_rem.status_code in (400, 403, 409)

    # 2. Admin cannot demote themselves away from TENANT_ADMINISTRATOR
    r_self_demote = client.post(
        f"/api/memberships/members/{admin_id}/roles",
        headers=headers,
        json={"roles": [MembershipRole.VIEWER.value]},
    )
    assert r_self_demote.status_code in (400, 403, 409)


def test_membership_audit_chain_and_tamper_verification(membership_app):
    """Criterion 2 & Invariants: All membership changes append tamper-evident audit events."""
    client = membership_app["client"]
    db = membership_app["db"]
    org_id = "org_pilot"

    admin_id, admin_token = seed_admin_member(db, organization_id=org_id)
    headers = {"Authorization": f"Bearer {admin_token}", "X-Organization-Id": org_id}

    # Invite member
    client.post(
        "/api/memberships/invitations",
        headers=headers,
        json={"email": "audit_user@pilot.test", "role": MembershipRole.PAYMENT_OPERATOR.value},
    )

    # Verify audit chain passes
    r_verify = client.get("/api/memberships/audit/verify", headers=headers)
    assert r_verify.status_code == 200
    res = r_verify.json()
    assert res["is_valid"] is True
    assert res["event_count"] >= 1

    # Tamper with an audit event
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE membership_audit_events SET summary = 'TAMPERED SUMMARY' WHERE organization_id = ?",
            (org_id,),
        )
        conn.commit()

    # Tampered audit chain fails verification
    r_tampered = client.get("/api/memberships/audit/verify", headers=headers)
    assert r_tampered.status_code == 200
    res_tampered = r_tampered.json()
    assert res_tampered["is_valid"] is False
    assert res_tampered["trust_state"] == "CORRUPTED"
