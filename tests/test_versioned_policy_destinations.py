"""Comprehensive tests for versioned policy and Approved Destinations (Issue #9)."""

from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from payoutproof.core.models import (
    ApprovedDestinationRecord,
    DestinationApprovalSnapshot,
    PaymentIntent,
)
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.core.enums import (
    PolicyConfigStatus,
    DestinationRecordStatus,
    PolicyOutcome,
    ReasonCode,
    CasePhase,
)
from payoutproof.policy.config import (
    PolicyConfig,
    mint_policy_config,
)
from payoutproof.policy.evaluator import PolicyGate, POLICY_VERSION
from payoutproof.storage.db import (
    Database,
    DestinationTransitionError,
    DestinationRecordError,
    PolicyConfigTransitionError,
    PolicyConfigTamperError,
)
from payoutproof.core.config import AppConfig
from payoutproof.api.app import create_app
from tests.helpers import TEST_GRANT_SECRET, TEST_AUDIT_CHECKPOINT_SECRET


def test_destination_record_effective_window_logic():
    """Verify half-open [valid_from, valid_to) window and UTC awareness."""
    base_t = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    t_start = (base_t).isoformat()
    t_end = (base_t + timedelta(days=30)).isoformat()

    rec = ApprovedDestinationRecord(
        destination_id="PP-DEST-001",
        tenant_id="tenant_default",
        organization_id="org_alpha",
        counterparty="Vendor Alpha",
        destination="0123456789",
        destination_type="BANK_ACCOUNT",
        status=DestinationRecordStatus.ACTIVE,
        valid_from=t_start,
        valid_to=t_end,
        policy_config_id="PP-POLCFG-1",
        policy_config_hash="a" * 64,
        record_hash="b" * 64,
        created_at=t_start,
        updated_at=t_start,
    )

    # 1. Before valid_from: not effective
    t_before = base_t - timedelta(seconds=1)
    assert not rec.is_effective_at(t_before)

    # 2. Exactly at valid_from: effective
    assert rec.is_effective_at(base_t)

    # 3. Inside window: effective
    t_inside = base_t + timedelta(days=15)
    assert rec.is_effective_at(t_inside)

    # 4. Exactly at valid_to: not effective (half-open)
    t_at_end = base_t + timedelta(days=30)
    assert not rec.is_effective_at(t_at_end)

    # 5. After valid_to: not effective
    t_after = base_t + timedelta(days=31)
    assert not rec.is_effective_at(t_after)

    # 6. Status CREATED: never effective
    rec_created = rec.model_copy(update={"status": DestinationRecordStatus.CREATED})
    assert not rec_created.is_effective_at(t_inside)

    # 7. Status RETIRED: never effective
    rec_retired = rec.model_copy(update={"status": DestinationRecordStatus.RETIRED})
    assert not rec_retired.is_effective_at(t_inside)


def test_destination_lifecycle_in_database(tmp_path):
    """Test destination transitions: CREATED -> ACTIVE -> RETIRED, and CREATED -> RETIRED."""
    db_path = tmp_path / "dest_test.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    # 1. Setup active policy config
    cfg = mint_policy_config(
        organization_id="org_alpha",
        config_id="PP-POLCFG-1",
        created_by="fco_user",
        version_id="PP-POLICY-V1",
    )
    with db.get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        db.create_policy_config_tx(conn, policy_config=cfg, actor="fco_user")
        conn.commit()
    db.activate_policy_config(config_id="PP-POLCFG-1", organization_id="org_alpha", actor="fco_user")

    # 2. Create destination
    dest = db.create_destination_record(
        organization_id="org_alpha",
        tenant_id="tenant_default",
        counterparty="Vendor Alpha",
        destination="0123456789",
        destination_type="BANK_ACCOUNT",
        valid_from="2026-01-01T00:00:00+00:00",
        valid_to=None,
        policy_config=cfg,
        actor="fco_user",
    )
    assert dest.status == DestinationRecordStatus.CREATED

    # 3. Activate destination
    act = db.activate_destination_record(
        destination_id=dest.destination_id,
        organization_id="org_alpha",
        actor="fco_user",
    )
    assert act.status == DestinationRecordStatus.ACTIVE

    # 4. Effective snapshot lookup
    snap = db.get_effective_destination_snapshot(
        counterparty="Vendor Alpha",
        destination="0123456789",
        organization_id="org_alpha",
    )
    assert snap is not None
    assert snap.destination_id == dest.destination_id
    assert snap.is_effective_at(datetime.now(timezone.utc))

    # 5. Retire destination
    ret = db.retire_destination_record(
        destination_id=dest.destination_id,
        organization_id="org_alpha",
        actor="fco_user",
    )
    assert ret.status == DestinationRecordStatus.RETIRED

    # 6. RETIRED cannot be activated
    with pytest.raises(DestinationTransitionError):
        db.activate_destination_record(
            destination_id=dest.destination_id,
            organization_id="org_alpha",
            actor="fco_user",
        )

    # 7. CREATED -> RETIRED (allowed cancellation)
    dest2 = db.create_destination_record(
        organization_id="org_alpha",
        tenant_id="tenant_default",
        counterparty="Vendor Beta",
        destination="9876543210",
        destination_type="BANK_ACCOUNT",
        valid_from="2026-01-01T00:00:00+00:00",
        valid_to=None,
        policy_config=cfg,
        actor="fco_user",
    )
    ret2 = db.retire_destination_record(
        destination_id=dest2.destination_id,
        organization_id="org_alpha",
        actor="fco_user",
    )
    assert ret2.status == DestinationRecordStatus.RETIRED


def test_policy_config_single_active_and_monotonicity(tmp_path):
    """Test policy config single ACTIVE constraint, monotonicity, and audit chain."""
    db_path = tmp_path / "pol_test.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    cfg1 = mint_policy_config(
        organization_id="org_beta",
        config_id="PP-POLCFG-1",
        created_by="fco_user",
        version_id="PP-POLICY-V1",
    )
    db.create_policy_config(policy_config=cfg1, actor="fco_user")
    db.activate_policy_config(config_id="PP-POLCFG-1", organization_id="org_beta", actor="fco_user")

    # Creating V3 before V2 is rejected (monotonicity)
    cfg3 = mint_policy_config(
        organization_id="org_beta",
        config_id="PP-POLCFG-3",
        created_by="fco_user",
        version_id="PP-POLICY-V3",
    )
    with pytest.raises(PolicyConfigTransitionError):
        db.create_policy_config(policy_config=cfg3, actor="fco_user")

    # Create V2
    cfg2 = mint_policy_config(
        organization_id="org_beta",
        config_id="PP-POLCFG-2",
        created_by="fco_user",
        version_id="PP-POLICY-V2",
    )
    db.create_policy_config(policy_config=cfg2, actor="fco_user")

    # Activating V2 while V1 is ACTIVE is rejected (single active invariant)
    with pytest.raises(PolicyConfigTransitionError):
        db.activate_policy_config(config_id="PP-POLCFG-2", organization_id="org_beta", actor="fco_user")

    # Retire V1 then activate V2 succeeds
    db.retire_policy_config(config_id="PP-POLCFG-1", organization_id="org_beta", actor="fco_user")
    act2 = db.activate_policy_config(config_id="PP-POLCFG-2", organization_id="org_beta", actor="fco_user")
    assert act2.status == PolicyConfigStatus.ACTIVE

    # Verify config audit chain
    audit = db.verify_config_audit(organization_id="org_beta")
    assert audit is not None
    assert audit["is_valid"] is True
    assert audit["event_count"] >= 4


def test_policy_gate_with_destination_snapshot_and_config():
    """Verify PolicyGate applies step-up on unapproved destination and records provenance."""
    from tests.helpers import make_admitted_case_state, make_confirmed_intent

    eval_time = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    intent = make_confirmed_intent(
        counterparty="Kaveri Components",
        destination="HDFC 4821",
        amount="10000.00",
    )
    state = make_admitted_case_state(
        case_id="RC-POLICY-01",
        intent=intent,
        organization_id="org_delta",
    )

    cfg = mint_policy_config(
        organization_id="org_delta",
        config_id="PP-POLCFG-1",
        created_by="fco",
        version_id="PP-POLICY-V1",
    )

    # 1. Unapproved destination -> STEP_UP_REQUIRED
    res_unapproved = PolicyGate.evaluate(
        state=state,
        evaluation_time=eval_time,
        policy_config=cfg,
        destination_snapshot=None,
    )
    assert res_unapproved.outcome == PolicyOutcome.STEP_UP_REQUIRED
    assert ReasonCode.UNAPPROVED_DESTINATION in res_unapproved.reasons
    assert res_unapproved.policy_config_id == "PP-POLCFG-1"

    # 2. Approved destination snapshot effective -> does not fail for destination
    snap = DestinationApprovalSnapshot(
        destination_id="PP-DEST-001",
        organization_id="org_delta",
        tenant_id="tenant_default",
        counterparty="Kaveri Components",
        destination="HDFC 4821",
        destination_type="BANK_ACCOUNT",
        status=DestinationRecordStatus.ACTIVE,
        valid_from="2026-01-01T00:00:00+00:00",
        valid_to="2026-12-31T23:59:59+00:00",
        policy_config_id="PP-POLCFG-1",
        policy_config_hash=cfg.content_hash,
        record_hash="c" * 64,
        snapshot_captured_at=eval_time.isoformat(),
    )
    res_approved = PolicyGate.evaluate(
        state=state,
        evaluation_time=eval_time,
        policy_config=cfg,
        destination_snapshot=snap,
    )
    # Still requires callback, but destination reason is NOT present
    assert ReasonCode.UNAPPROVED_DESTINATION not in res_approved.reasons
    assert res_approved.destination_snapshot is not None
    assert res_approved.destination_snapshot["destination_id"] == "PP-DEST-001"


def test_destination_and_policy_api_endpoints(tmp_path):
    """Verify REST endpoints for destination records and policy configs."""
    db_path = tmp_path / "api_test.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    cfg = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(db_path),
    )
    app = create_app(config=cfg, db=db)
    client = TestClient(app, headers={"X-Organization-Id": "org_api"})

    # 1. Create policy config via API
    r_cfg = client.post(
        "/api/policy/configs",
        json={
            "grant_ttl_seconds": 3600,
            "require_independent_callback": True,
            "require_approved_destination": True,
        },
    )
    assert r_cfg.status_code == 200
    config_id = r_cfg.json()["config_id"]

    # 2. Activate config
    r_act = client.post(f"/api/policy/configs/{config_id}/activate")
    assert r_act.status_code == 200
    assert r_act.json()["status"] == "ACTIVE"

    # 3. Read active config
    r_active = client.get("/api/policy/configs/active")
    assert r_active.status_code == 200
    assert r_active.json()["config_id"] == config_id

    # 4. Create destination record
    r_dest = client.post(
        "/api/destinations",
        json={
            "tenant_id": "tenant_default",
            "counterparty": "Supplier Gamma",
            "destination": "ACC-12345",
            "destination_type": "BANK_ACCOUNT",
            "valid_from": "2026-01-01T00:00:00+00:00",
        },
    )
    assert r_dest.status_code == 200
    dest_id = r_dest.json()["destination_id"]

    # 5. Activate destination
    r_dest_act = client.post(f"/api/destinations/{dest_id}/activate")
    assert r_dest_act.status_code == 200
    assert r_dest_act.json()["status"] == "ACTIVE"

    # 6. List destinations
    r_list = client.get("/api/destinations")
    assert r_list.status_code == 200
    assert len(r_list.json()) >= 1

    # 7. Cross-org zero existence (404)
    client_other = TestClient(app, headers={"X-Organization-Id": "org_other"})
    r_cross = client_other.get(f"/api/destinations/{dest_id}")
    assert r_cross.status_code == 404
