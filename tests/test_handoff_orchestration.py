"""Tests for server-owned handoff orchestration, client outcome removal, and concurrency protection."""

import json
import concurrent.futures
import pytest
from fastapi.testclient import TestClient

from payoutproof.core.enums import (
    CasePhase,
    PolicyOutcome,
    GrantStatus,
    HandoffStatus,
    AdapterDecision,
    DemoFakeAdapterMode,
    IntentStatus,
)
from payoutproof.core.models import PaymentIntent, PolicyEvaluationResult
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.case_workflow.handoff_service import HandoffService
from payoutproof.core.config import AppConfig
from payoutproof.api.app import create_app
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
from payoutproof.grants.issuer import GrantIssuer
from tests.helpers import (
    make_authorized_bundle_action,
    make_valid_authority_record,
    make_admitted_case_state,
    make_confirmed_intent,
    TEST_GRANT_SECRET,
    TEST_AUDIT_CHECKPOINT_SECRET,
)


@pytest.fixture
def client(app):
    return TestClient(app)


def _setup_eligible_case_via_api(client: TestClient, case_id: str) -> dict:
    """Helper to advance a case to ELIGIBLE_FOR_HANDOFF with an active grant."""
    # 0. Create case explicitly
    r_create = client.post("/api/cases", json={"case_id": case_id, "tenant_id": "tenant_01"})
    assert r_create.status_code == 200
    # 1. Admit
    admit_act = make_authorized_bundle_action(
        case_id=case_id,
        authority=make_valid_authority_record().model_dump(),
    )
    r = client.post(f"/api/cases/{case_id}/dispatch", json=admit_act)
    assert r.status_code == 200
    # 2. Extract
    r = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "EXTRACT_INTENT", "payload": {"counterparty": "Kaveri Components", "destination": "HDFC ••4821", "amount": "425000"}})
    assert r.status_code == 200
    # 3. Confirm
    r = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "CONFIRM_INTENT", "payload": {}})
    assert r.status_code == 200
    # 4. Callback
    r = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "ADD_CALLBACK_EVIDENCE", "payload": {}})
    assert r.status_code == 200
    # 5. Destination approval
    r = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "ADD_DESTINATION_APPROVAL", "payload": {}})
    assert r.status_code == 200
    # 6. Evaluate
    r = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "EVALUATE_POLICY", "payload": {}})
    assert r.status_code == 200
    assert r.json()["policy"]["outcome"] == PolicyOutcome.ELIGIBLE_FOR_HANDOFF.value
    # 7. Issue grant
    r = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "ISSUE_GRANT", "payload": {}})
    assert r.status_code == 200
    assert r.json()["grant"]["status"] == GrantStatus.ACTIVE.value
    return r.json()


def test_api_rejects_removed_command_names_without_state_mutation(client):
    case_id = "RC-TEST-REMOVED-CMDS"
    state_before = _setup_eligible_case_via_api(client, case_id)
    version_before = state_before["case_version"]
    audit_len_before = len(state_before["audit"])

    # 1. HANDOFF_ACCEPTED must be rejected with HTTP 400
    res1 = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "HANDOFF_ACCEPTED", "payload": {"pending_item_id": "INJECTED-1"}})
    assert res1.status_code == 400
    assert "removed" in res1.json()["detail"].lower()

    # 2. HANDOFF_AMBIGUOUS must be rejected with HTTP 400
    res2 = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "HANDOFF_AMBIGUOUS", "payload": {}})
    assert res2.status_code == 400
    assert "removed" in res2.json()["detail"].lower()

    # 3. REPLAY_GRANT must be rejected with HTTP 400
    res3 = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "REPLAY_GRANT", "payload": {}})
    assert res3.status_code == 400
    assert "removed" in res3.json()["detail"].lower()

    # Verify state in DB remains completely unmutated
    state_after = client.get(f"/api/cases/{case_id}").json()
    assert state_after["case_version"] == version_before
    assert len(state_after["audit"]) == audit_len_before
    assert state_after["phase"] == CasePhase.READY_FOR_HUMAN_HANDOFF.value
    assert state_after["handoff"]["status"] == HandoffStatus.NOT_STARTED.value
    assert state_after["grant"]["status"] == GrantStatus.ACTIVE.value


def test_api_rejects_malicious_payload_fields_without_state_mutation(client, monkeypatch):
    case_id = "RC-TEST-MALICIOUS-PAYLOAD"
    state_before = _setup_eligible_case_via_api(client, case_id)
    version_before = state_before["case_version"]

    malicious_payloads = [
        {"pending_item_id": "ATTACKER-ITEM-001"},
        {"adapter_decision": "PENDING_ITEM_CREATED"},
        {"outcome": "ELIGIBLE_FOR_HANDOFF"},
        {"grant_status": "CONSUMED"},
        {"used": True},
        {"state": "MALICIOUS_OVERRIDE"},
        {"phase": "COMPLETE"},
        {"case_version": 999},
        {"last_adapter_decision": "PENDING_ITEM_CREATED"},
    ]

    for bad_field in malicious_payloads:
        # Test on INITIATE_HANDOFF
        res = client.post(
            f"/api/cases/{case_id}/dispatch",
            json={"type": "INITIATE_HANDOFF", "payload": bad_field},
        )
        assert res.status_code == 400, f"Expected 400 for payload: {bad_field}"
        assert "disallowed" in res.json()["detail"].lower()

        # Test on ordinary action (e.g. RESET)
        res_reset = client.post(
            f"/api/cases/{case_id}/dispatch",
            json={"type": "RESET", "payload": bad_field},
        )
        assert res_reset.status_code == 400
        assert "disallowed" in res_reset.json()["detail"].lower()

    # Non-handoff action rejecting fake_adapter_mode
    res_fake_mode = client.post(
        f"/api/cases/{case_id}/dispatch",
        json={"type": "CONFIRM_INTENT", "payload": {"fake_adapter_mode": "SIMULATE_AMBIGUITY"}},
    )
    assert res_fake_mode.status_code == 400
    assert "only permitted for initiate_handoff" in res_fake_mode.json()["detail"].lower()

    # When demo modes enabled on app, arbitrary fake_adapter_mode value is rejected
    demo_cfg = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        enable_demo_adapter_modes=True,
    )
    demo_app = create_app(config=demo_cfg, db=client.app.state.db)
    demo_client = TestClient(demo_app)
    res_arbitrary_mode = demo_client.post(
        f"/api/cases/{case_id}/dispatch",
        json={"type": "INITIATE_HANDOFF", "payload": {"fake_adapter_mode": "ARBITRARY_DECISION"}},
    )
    assert res_arbitrary_mode.status_code == 400
    assert "invalid fake_adapter_mode" in res_arbitrary_mode.json()["detail"].lower()

    # Verify state in DB remains unmutated
    state_after = client.get(f"/api/cases/{case_id}").json()
    assert state_after["case_version"] == version_before
    assert state_after["handoff"]["status"] == HandoffStatus.NOT_STARTED.value


def test_happy_api_path_calls_adapter_and_creates_single_server_item(client):
    case_id = "RC-TEST-API-HAPPY-01"
    _setup_eligible_case_via_api(client, case_id)

    # Dispatch INITIATE_HANDOFF with no outcome/item payload
    res = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "INITIATE_HANDOFF", "payload": {}})
    assert res.status_code == 200
    state = res.json()

    # Verify adapter was invoked server-side and mapped into authoritative state
    assert state["phase"] == CasePhase.COMPLETE.value
    assert state["handoff"]["status"] == HandoffStatus.PENDING_IN_APPROVAL_RAIL.value
    assert state["handoff"]["last_adapter_decision"] == AdapterDecision.PENDING_ITEM_CREATED.value
    assert state["handoff"]["pending_item_id"] is not None
    assert state["handoff"]["pending_item_id"].startswith(f"RAIL-PENDING-{case_id}-")
    assert state["grant"]["status"] == GrantStatus.CONSUMED.value
    assert state["grant"]["used"] is True

    # Persisted DB state matches
    db_state = client.get(f"/api/cases/{case_id}").json()
    assert db_state["phase"] == CasePhase.COMPLETE.value
    assert db_state["handoff"]["pending_item_id"] == state["handoff"]["pending_item_id"]


def test_second_initiation_cannot_create_another_item(client):
    case_id = "RC-TEST-API-NO-DOUBLE-PENDING"
    _setup_eligible_case_via_api(client, case_id)

    # First initiation succeeds and creates one item
    res1 = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "INITIATE_HANDOFF", "payload": {}})
    assert res1.status_code == 200
    first_item_id = res1.json()["handoff"]["pending_item_id"]
    assert first_item_id is not None

    # Second initiation attempt with consumed grant must be refused safely
    res2 = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "INITIATE_HANDOFF", "payload": {}})
    assert res2.status_code == 200
    state2 = res2.json()
    assert "Refused" in state2["last_change"]
    assert state2["handoff"]["pending_item_id"] == first_item_id


def test_ambiguity_api_path_enters_reconciliation_and_preserves_eligibility(client, monkeypatch):
    case_id = "RC-TEST-API-AMBIG-01"
    _setup_eligible_case_via_api(client, case_id)

    # Explicitly enable demo simulation mode via injected AppConfig
    demo_cfg = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        enable_demo_adapter_modes=True,
    )
    demo_app = create_app(config=demo_cfg, db=client.app.state.db)
    demo_client = TestClient(demo_app)

    # Dispatch INITIATE_HANDOFF requesting demo-only ambiguous simulation
    res = demo_client.post(
        f"/api/cases/{case_id}/dispatch",
        json={"type": "INITIATE_HANDOFF", "payload": {"fake_adapter_mode": "SIMULATE_AMBIGUITY"}},
    )
    assert res.status_code == 200
    state = res.json()

    # Enters RECONCILIATION_REQUIRED, preserves historical eligibility
    assert state["phase"] == CasePhase.RECONCILIATION_REQUIRED.value
    assert state["handoff"]["status"] == HandoffStatus.RECONCILIATION_REQUIRED.value
    assert state["handoff"]["last_adapter_decision"] == AdapterDecision.DOWNSTREAM_STATUS_UNKNOWN_NO_RETRY.value
    assert state["handoff"]["pending_item_id"] is None
    assert state["policy"]["outcome"] == PolicyOutcome.ELIGIBLE_FOR_HANDOFF.value  # historical eligibility intact!
    assert state["grant"]["status"] == GrantStatus.SUSPENDED_FOR_RECONCILIATION.value
    assert state["grant"]["used"] is True

    # Second initiation cannot retry or create another item
    res_retry = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "INITIATE_HANDOFF", "payload": {}})
    assert res_retry.status_code == 200
    retry_state = res_retry.json()
    assert "Refused" in retry_state["last_change"]
    assert retry_state["phase"] == CasePhase.RECONCILIATION_REQUIRED.value
    assert retry_state["handoff"]["pending_item_id"] is None


def test_adapter_concurrency_lock_protection_fifteen_threads():
    adapter = FakeApprovalRailAdapter(
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
    state = make_admitted_case_state(
        case_id="RC-CONCUR-LOCK-15",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    grant = GrantIssuer.issue_grant(state, secret=TEST_GRANT_SECRET)
    state = state.model_copy(update={"grant": grant})
    adapter.db.save_case(state)

    def submit_worker(worker_id: int):
        return adapter.submit_handoff(
            grant=grant,
            intent=intent,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(submit_worker, i) for i in range(15)]
        results = [f.result() for f in futures]

    created = [r for r in results if r[0] == AdapterDecision.PENDING_ITEM_CREATED]
    rejected = [r for r in results if r[0] == AdapterDecision.REPLAY_REJECTED]

    assert len(created) == 1
    assert len(rejected) == 14
    assert len(adapter.pending_rail_items) == 1
    assert created[0][1] is not None
    assert created[0][1].status == "PENDING_FINANCE_APPROVAL"



def test_internal_transition_mapping_rejects_impossible_decisions_fail_closed():
    """Internal transition mapping rejects impossible/unexpected decisions fail closed."""
    s = StateMachine.initial_state(case_id="RC-FAILCLOSED-01")

    # 1. Non-enum value must raise ValueError
    with pytest.raises(ValueError, match="fail closed"):
        StateMachine.apply_adapter_decision(s, "INVALID_STRING_DECISION")  # type: ignore

    with pytest.raises(ValueError, match="fail closed"):
        StateMachine.apply_adapter_decision(s, None)  # type: ignore

    # 2. FRESH_HUMAN_GESTURE_ACCEPTED is an initiation status, not an adapter completion decision
    with pytest.raises(ValueError, match="fail closed"):
        StateMachine.apply_adapter_decision(s, AdapterDecision.FRESH_HUMAN_GESTURE_ACCEPTED)

    # 3. PENDING_ITEM_CREATED without pending_item_id must fail closed
    with pytest.raises(ValueError, match="pending_item_id is required"):
        StateMachine.apply_adapter_decision(s, AdapterDecision.PENDING_ITEM_CREATED, pending_item_id=None)

    # 4. REPLAY_REJECTED refuses safely with no new pending item
    s_replay = StateMachine.apply_adapter_decision(
        s,
        AdapterDecision.REPLAY_REJECTED,
        error_message="Duplicate submission prevented",
    )
    assert s_replay.handoff.last_adapter_decision == AdapterDecision.REPLAY_REJECTED
    assert s_replay.handoff.pending_item_id is None
    assert s_replay.phase != CasePhase.COMPLETE

    # 5. GRANT_INVALID_OR_EXPIRED refuses safely with no new pending item
    s_invalid = StateMachine.apply_adapter_decision(
        s,
        AdapterDecision.GRANT_INVALID_OR_EXPIRED,
        error_message="Signature mismatch",
    )
    assert s_invalid.handoff.last_adapter_decision == AdapterDecision.GRANT_INVALID_OR_EXPIRED
    assert s_invalid.handoff.pending_item_id is None
    assert s_invalid.phase == CasePhase.OPERATOR_INTERVENTION


def test_successful_handoff_survives_restart_and_reconstruction(tmp_path):
    """Successful API/service handoff then reconstruct Database+adapter: COMPLETE, used/CONSUMED, exactly one pending item."""
    from payoutproof.storage.db import Database
    from payoutproof.core.crypto import derive_idempotency_key

    db_path = tmp_path / "restart_success.db"
    db1 = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter1 = FakeApprovalRailAdapter(
        db=db1,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    # Setup case and grant
    intent = make_confirmed_intent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
    )
    s = make_admitted_case_state(
        case_id="RC-RESTART-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    db1.save_case(s)
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    db1.save_case(s)

    # Execute handoff
    s_done = HandoffService.execute_handoff(state=s, adapter=adapter1, grant_secret=TEST_GRANT_SECRET)
    assert s_done.phase == CasePhase.COMPLETE
    assert s_done.grant.status == GrantStatus.CONSUMED
    assert s_done.grant.used is True
    pending_item_id = s_done.handoff.pending_item_id
    assert pending_item_id is not None

    # Reconstruct fresh Database and FakeApprovalRailAdapter
    db2 = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter2 = FakeApprovalRailAdapter(
        db=db2,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    reloaded = db2.load_case("RC-RESTART-01")
    assert reloaded is not None
    assert reloaded.phase == CasePhase.COMPLETE
    assert reloaded.grant is not None
    assert reloaded.grant.status == GrantStatus.CONSUMED
    assert reloaded.grant.used is True
    assert reloaded.handoff.status == HandoffStatus.PENDING_IN_APPROVAL_RAIL
    assert reloaded.handoff.pending_item_id == pending_item_id

    # Pending items query reads SQLite
    all_items = adapter2.pending_rail_items
    assert len(all_items) == 1
    assert pending_item_id in all_items
    assert all_items[pending_item_id].status == "PENDING_FINANCE_APPROVAL"


def test_ambiguous_handoff_survives_restart_and_refuses_retry(tmp_path):
    """Ambiguous handoff then reconstruct: RECONCILIATION_REQUIRED, used/suspended, zero pending items, retry refused."""
    from payoutproof.storage.db import Database

    db_path = tmp_path / "restart_ambig.db"
    db1 = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter1 = FakeApprovalRailAdapter(
        db=db1,
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
    s = make_admitted_case_state(
        case_id="RC-AMBIG-RESTART-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    db1.save_case(s)
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    db1.save_case(s)

    # Execute ambiguous handoff
    s_ambig = HandoffService.execute_handoff(state=s, adapter=adapter1, grant_secret=TEST_GRANT_SECRET, simulate_ambiguity=True)
    assert s_ambig.phase == CasePhase.RECONCILIATION_REQUIRED
    assert s_ambig.grant.status == GrantStatus.SUSPENDED_FOR_RECONCILIATION
    assert s_ambig.grant.used is True
    assert s_ambig.handoff.pending_item_id is None

    # Reconstruct fresh Database and FakeApprovalRailAdapter
    db2 = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter2 = FakeApprovalRailAdapter(
        db=db2,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    reloaded = db2.load_case("RC-AMBIG-RESTART-01")
    assert reloaded is not None
    assert reloaded.phase == CasePhase.RECONCILIATION_REQUIRED
    assert reloaded.grant is not None
    assert reloaded.grant.status == GrantStatus.SUSPENDED_FOR_RECONCILIATION
    assert reloaded.grant.used is True
    assert reloaded.handoff.pending_item_id is None

    # Zero pending items exist in SQLite
    assert len(adapter2.pending_rail_items) == 0

    # Blind retry is refused
    retry_state = HandoffService.execute_handoff(state=reloaded, adapter=adapter2, grant_secret=TEST_GRANT_SECRET)
    assert retry_state.phase == CasePhase.RECONCILIATION_REQUIRED
    assert "Refused" in retry_state.last_change
    assert retry_state.handoff.pending_item_id is None
    assert len(adapter2.pending_rail_items) == 0


def test_malicious_api_payload_idempotency_key_is_http_400_and_derived_key_is_bound(client):
    """Malicious API payload idempotency_key is HTTP 400; internal deterministic key is stable and bound to authoritative fields."""
    from payoutproof.core.crypto import derive_idempotency_key

    case_id = "RC-MALICIOUS-IDEM-01"
    _setup_eligible_case_via_api(client, case_id)

    # 1. Reject client payload containing idempotency_key on INITIATE_HANDOFF
    res = client.post(
        f"/api/cases/{case_id}/dispatch",
        json={"type": "INITIATE_HANDOFF", "payload": {"idempotency_key": "ATTACKER-FORGED-KEY"}},
    )
    assert res.status_code == 400
    assert "disallowed" in res.json()["detail"].lower()
    assert "idempotency_key" in res.json()["detail"]

    # 2. Reject client payload containing idempotency_key on non-handoff actions
    res_other = client.post(
        f"/api/cases/{case_id}/dispatch",
        json={"type": "CONFIRM_INTENT", "payload": {"idempotency_key": "ATTACKER-FORGED-KEY"}},
    )
    assert res_other.status_code == 400
    assert "disallowed" in res_other.json()["detail"].lower()

    # 3. Verify pure StateMachine rejects client-supplied idempotency_key in payload
    case_state = client.get(f"/api/cases/{case_id}").json()
    from payoutproof.core.models import RiskCaseState
    state_obj = RiskCaseState.model_validate(case_state)
    reduced = StateMachine.reduce(state_obj, {"type": "INITIATE_HANDOFF", "payload": {"idempotency_key": "FORGED"}})
    assert "Refused" in reduced.last_change
    assert "strictly server-owned" in reduced.last_change

    # 4. Verify server-owned derivation is deterministic and bound to authoritative fields
    key1 = derive_idempotency_key("tenant_01", "RC-01", 1, "GRANT-01")
    key2 = derive_idempotency_key("tenant_01", "RC-01", 1, "GRANT-01")
    assert key1 == key2

    # Different tenant -> different key
    assert derive_idempotency_key("tenant_02", "RC-01", 1, "GRANT-01") != key1
    # Different case -> different key
    assert derive_idempotency_key("tenant_01", "RC-02", 1, "GRANT-01") != key1
    # Different version -> different key
    assert derive_idempotency_key("tenant_01", "RC-01", 2, "GRANT-01") != key1
    # Different grant -> different key
    assert derive_idempotency_key("tenant_01", "RC-01", 1, "GRANT-02") != key1

    # 5. Normal dispatch completes with server-owned key stored internally
    res_ok = client.post(f"/api/cases/{case_id}/dispatch", json={"type": "INITIATE_HANDOFF", "payload": {}})
    assert res_ok.status_code == 200
    expected_key = derive_idempotency_key(
        state_obj.tenant_id,
        state_obj.case_id or "",
        state_obj.case_version,
        state_obj.grant.grant_id,
    )
    assert res_ok.json()["handoff"]["idempotency_key"] == expected_key


def test_simulated_stale_case_json_recovery_converges_without_second_item(tmp_path):
    """Simulated stale case_json + durable adapter_attempt recovery converges state without second item."""
    from payoutproof.storage.db import Database
    from payoutproof.core.crypto import derive_idempotency_key

    db_path = tmp_path / "stale_recovery.db"
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
    s = make_admitted_case_state(
        case_id="RC-STALE-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    s = s.model_copy(update={"phase": CasePhase.READY_FOR_HUMAN_HANDOFF})
    db.save_case(s)
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    db.save_case(s)
    grant = s.grant
    assert grant is not None

    # Step 1: Simulate that adapter attempt succeeded and committed into SQLite
    dec, item, err = adapter.submit_handoff(grant=grant, intent=intent)
    assert dec == AdapterDecision.PENDING_ITEM_CREATED
    assert item is not None
    committed_item_id = item.item_id

    # Step 2: Simulate crash gap: risk_cases.state_json is STALE (still in READY_FOR_HUMAN_HANDOFF)
    # The database has the attempt and pending item, but risk_cases was not saved before simulated crash
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE risk_cases SET phase = 'READY_FOR_HUMAN_HANDOFF', state_json = ? WHERE case_id = 'RC-STALE-01'",
            (json.dumps(s.model_dump()),),
        )
    with db.get_connection() as conn:
        stale_case = db.load_case_tx(conn, "RC-STALE-01")
    assert stale_case is not None
    assert stale_case.phase == CasePhase.READY_FOR_HUMAN_HANDOFF

    # Step 3: A retry or recovery arrives (execute_handoff called with stale state)
    recovered_state = HandoffService.execute_handoff(state=stale_case, adapter=adapter, grant_secret=TEST_GRANT_SECRET)

    # State converges to COMPLETE with recorded pending item
    assert recovered_state.phase == CasePhase.COMPLETE
    assert recovered_state.handoff.status == HandoffStatus.PENDING_IN_APPROVAL_RAIL
    assert recovered_state.handoff.pending_item_id == committed_item_id

    # Crucial: NO second item was created in SQLite!
    assert len(adapter.pending_rail_items) == 1
    with db.get_connection() as conn:
        assert conn.execute("SELECT count(*) FROM pending_approval_items").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM adapter_attempts").fetchone()[0] == 1



def test_transaction_rollback_proves_no_half_consumed_grant_attempt_or_pending_item(tmp_path):
    """Transaction rollback test: inject/force a failure before commit and prove no half-consumed grant, attempt, or pending item remains."""
    from payoutproof.storage.db import Database
    import unittest.mock as mock

    db_path = tmp_path / "rollback_test.db"
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
    s = make_admitted_case_state(
        case_id="RC-ROLLBACK-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    s = s.model_copy(update={"phase": CasePhase.READY_FOR_HUMAN_HANDOFF})
    db.save_case(s)
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    db.save_case(s)
    grant_id = s.grant.grant_id



    # Force a failure right before commit inside HandoffService
    original_save = db.save_case_tx

    def failing_save_case_tx(conn, state):
        if state.phase == CasePhase.COMPLETE:
            raise RuntimeError("Simulated crash/network failure right before commit")
        return original_save(conn, state)

    with mock.patch.object(db, "save_case_tx", side_effect=failing_save_case_tx):
        with pytest.raises(RuntimeError, match="Simulated crash/network failure"):
            HandoffService.execute_handoff(state=s, adapter=adapter, grant_secret=TEST_GRANT_SECRET)

    # Prove rollback: grant was NOT left consumed
    with db.get_connection() as conn:
        g_row = conn.execute("SELECT used, status FROM handoff_grants WHERE grant_id = ?", (grant_id,)).fetchone()
        assert g_row is not None
        assert g_row["used"] == 0
        assert g_row["status"] == "ACTIVE"

        # No orphaned adapter_attempt
        attempt_count = conn.execute("SELECT count(*) FROM adapter_attempts").fetchone()[0]
        assert attempt_count == 0

        # No orphaned pending_approval_item
        item_count = conn.execute("SELECT count(*) FROM pending_approval_items").fetchone()[0]
        assert item_count == 0

        # Case phase remains unmutated
        case_row = conn.execute("SELECT phase FROM risk_cases WHERE case_id = 'RC-ROLLBACK-01'").fetchone()
        assert case_row["phase"] == CasePhase.READY_FOR_HUMAN_HANDOFF.value


def test_api_health_status_distinguishes_liveness_from_maturity(client):
    """/api/health distinguishes liveness from capability maturity without premature READY claims."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()

    # Liveness
    assert data["status"] == "HEALTHY"
    assert "WAL active" in data["database"]

    # Maturity is IN_DEVELOPMENT, not READY
    assert data["maturity"] == "IN_DEVELOPMENT"

    caps = data["capabilities"]
    assert caps["admission"] == "IN_DEVELOPMENT"
    assert caps["policy_gate"] == "IN_DEVELOPMENT"
    assert caps["grant_issuer"] == "IN_DEVELOPMENT"
    assert caps["audit_chain"] == "IN_DEVELOPMENT"
    assert caps["fake_adapter"] == "IN_DEVELOPMENT"
    # Durable replay slice is accurately evidenced
    assert caps["durable_replay_protection"] == "UNIT_TESTED"


def test_reset_same_case_id_cannot_inherit_old_attempt_or_pending_item(tmp_path):
    """Mandatory Regression Test 2: Terminal case cannot be reset with same case_id.
    Candidate reset is rejected (StaleCaseStateError / reducer refusal) and full durable state unchanged.
    """
    from payoutproof.storage.db import Database, StaleCaseStateError

    db_path = tmp_path / "reset_isolation.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    # 1. Complete handoff for RC-RESET-01
    intent = make_confirmed_intent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
    )
    s = make_admitted_case_state(
        case_id="RC-RESET-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    db.save_case(s)
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    db.save_case(s)

    completed_state = HandoffService.execute_handoff(state=s, adapter=adapter, grant_secret=TEST_GRANT_SECRET)
    assert completed_state.phase == CasePhase.COMPLETE
    old_pending_item_id = completed_state.handoff.pending_item_id
    assert old_pending_item_id is not None

    # 2. Reducer refuses to reset case with existing grant / handoff / complete phase
    refused_reset = StateMachine.reduce(completed_state, {"type": "RESET"})
    assert "Refused" in refused_reset.last_change
    assert refused_reset.phase == CasePhase.COMPLETE

    # 3. Direct DB save of a reset candidate state lacking grant raises StaleCaseStateError
    reset_state = StateMachine.initial_state(case_id="RC-RESET-01", tenant_id="tenant_01")
    with pytest.raises(StaleCaseStateError):
        db.save_case(reset_state)

    # 4. Durable DB state remains completely unchanged and intact
    loaded = db.load_case("RC-RESET-01")
    assert loaded is not None
    assert loaded.phase == CasePhase.COMPLETE
    assert loaded.grant is not None
    assert loaded.grant.status == GrantStatus.CONSUMED
    assert loaded.handoff.pending_item_id == old_pending_item_id
    with db.get_connection() as conn:
        assert conn.execute("SELECT count(*) FROM adapter_attempts WHERE case_id = 'RC-RESET-01'").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM pending_approval_items WHERE case_id = 'RC-RESET-01'").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM handoff_grants WHERE case_id = 'RC-RESET-01' AND used = 1").fetchone()[0] == 1


def test_exact_stale_state_crash_recovery_reconstructs_coherent_handoff(tmp_path):
    """Mandatory Regression Test 5: Exact stale-state crash recovery produces a coherent reconstructed handoff
    with server-derived key, attempts >= 1, initiation audit then outcome audit, and exactly one item.
    """
    from payoutproof.storage.db import Database
    from payoutproof.core.crypto import derive_idempotency_key

    db_path = tmp_path / "coherent_recovery.db"
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
    s = make_admitted_case_state(
        case_id="RC-COHERENT-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    s = s.model_copy(update={"phase": CasePhase.READY_FOR_HUMAN_HANDOFF})
    db.save_case(s)
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    db.save_case(s)
    grant = s.grant
    assert grant is not None

    # Step 1: Adapter completes and commits
    dec, item, err = adapter.submit_handoff(grant=grant, intent=intent)
    assert dec == AdapterDecision.PENDING_ITEM_CREATED
    assert item is not None

    # Step 2: Simulate crash before state was updated (stale case remains in READY_FOR_HUMAN_HANDOFF)
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE risk_cases SET phase = 'READY_FOR_HUMAN_HANDOFF', state_json = ? WHERE case_id = 'RC-COHERENT-01'",
            (json.dumps(s.model_dump()),),
        )
        conn.execute("DELETE FROM audit_events WHERE case_id = 'RC-COHERENT-01' AND seq > 2")
        from payoutproof.core.crypto import compute_checkpoint_mac
        tip_s = s.audit[-1].current_hash
        mac_s = compute_checkpoint_mac(TEST_AUDIT_CHECKPOINT_SECRET, "RC-COHERENT-01", 2, tip_s, "TRUSTED")
        conn.execute(
            "UPDATE case_audit_checkpoints SET event_count = 2, tip_hash = ?, checkpoint_mac = ? WHERE case_id = 'RC-COHERENT-01'",
            (tip_s, mac_s),
        )
    stale_case = db.load_case("RC-COHERENT-01")
    assert stale_case is not None
    assert stale_case.phase == CasePhase.READY_FOR_HUMAN_HANDOFF

    # Step 3: Run recovery via HandoffService
    recovered = HandoffService.execute_handoff(state=stale_case, adapter=adapter, grant_secret=TEST_GRANT_SECRET)

    # Verify complete coherent state reconstruction
    assert recovered.phase == CasePhase.COMPLETE
    assert recovered.handoff.status == HandoffStatus.PENDING_IN_APPROVAL_RAIL
    assert recovered.handoff.attempts >= 1
    expected_key = derive_idempotency_key(recovered.tenant_id, recovered.case_id or "", recovered.case_version, grant.grant_id)
    assert recovered.handoff.idempotency_key == expected_key
    assert recovered.handoff.pending_item_id == item.item_id
    assert recovered.grant.status == GrantStatus.CONSUMED
    assert recovered.grant.used is True

    # Audit chain check: initiation audit then outcome audit
    event_types = [ev.event_type for ev in recovered.audit]
    assert "HANDOFF_INITIATED" in event_types
    assert "HANDOFF_CONFIRMED" in event_types
    init_idx = event_types.index("HANDOFF_INITIATED")
    conf_idx = event_types.index("HANDOFF_CONFIRMED")
    assert init_idx < conf_idx

    # Exactly one item exists in SQLite
    assert len(adapter.pending_rail_items) == 1


def test_attempt_with_mismatched_case_or_key_cannot_reconcile(tmp_path):
    """Mandatory Regression Test 6: Attempt with wrong case_id/key cannot reconcile current state."""
    import sqlite3
    from payoutproof.storage.db import Database
    from payoutproof.case_workflow.handoff_service import HandoffService
    from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
    from payoutproof.core.models import PaymentIntent, PolicyEvaluationResult
    from payoutproof.core.enums import PolicyOutcome, IntentStatus
    from tests.helpers import make_admitted_case_state

    db_path = tmp_path / "mismatch_rec.db"
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
    s = make_admitted_case_state(
        case_id="RC-MISMATCH-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    s = s.model_copy(update={"phase": CasePhase.READY_FOR_HUMAN_HANDOFF})
    db.save_case(s)
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    db.save_case(s)
    grant = s.grant
    assert grant is not None

    # Manually insert an attempt with corrupted/mismatched case_id / key
    with db.get_connection() as conn:
        conn.execute("""
            INSERT INTO adapter_attempts (
                idempotency_key, grant_id, case_id, attempts, status, decision,
                ambiguity_state, pending_item_id, error_code, error_message, created_at, updated_at
            ) VALUES ('IDEM-WRONG-KEY', ?, 'RC-DIFFERENT-CASE', 1, 'COMPLETED', 'PENDING_ITEM_CREATED', 'NONE', 'RAIL-FAKE-01', NULL, NULL, datetime('now'), datetime('now'));
        """, (grant.grant_id,))

    # Attempt to reconcile
    res = HandoffService.execute_handoff(state=s, adapter=adapter, grant_secret=TEST_GRANT_SECRET)
    # Refuses safely fail-closed, does not transition to COMPLETE with corrupted item
    assert res.phase != CasePhase.COMPLETE
    assert res.handoff.pending_item_id is None
    assert res.handoff.last_adapter_decision == AdapterDecision.RECOVERY_INTEGRITY_FAILURE_NO_RETRY


def test_fake_adapter_mode_gating_and_disabled_rejection(client, monkeypatch):
    """Mandatory Regression Test 9 & Test G: fake_adapter_mode absent or disabled => HTTP 400; explicitly enabled test retains ambiguity path."""
    case_id = "RC-TEST-MODE-GATE"
    _setup_eligible_case_via_api(client, case_id)

    # 1. Config with demo modes disabled -> must return HTTP 400
    res_disabled = client.post(
        f"/api/cases/{case_id}/dispatch",
        json={"type": "INITIATE_HANDOFF", "payload": {"fake_adapter_mode": "SIMULATE_AMBIGUITY"}},
    )
    assert res_disabled.status_code == 400
    assert "disabled" in res_disabled.json()["detail"].lower()

    # 2. Mutating environment variable cannot enable demo modes on existing app
    monkeypatch.setenv("PAYOUTPROOF_ENABLE_DEMO_ADAPTER_MODES", "1")
    res_env_mutation = client.post(
        f"/api/cases/{case_id}/dispatch",
        json={"type": "INITIATE_HANDOFF", "payload": {"fake_adapter_mode": "SIMULATE_AMBIGUITY"}},
    )
    assert res_env_mutation.status_code == 400
    assert "disabled" in res_env_mutation.json()["detail"].lower()

    # 3. Explicitly injected enable_demo_adapter_modes=True in AppConfig -> succeeds
    demo_cfg = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        enable_demo_adapter_modes=True,
    )
    demo_app = create_app(config=demo_cfg, db=client.app.state.db)
    demo_client = TestClient(demo_app)
    res_enabled = demo_client.post(
        f"/api/cases/{case_id}/dispatch",
        json={"type": "INITIATE_HANDOFF", "payload": {"fake_adapter_mode": "SIMULATE_AMBIGUITY"}},
    )
    assert res_enabled.status_code == 200
    assert res_enabled.json()["phase"] == CasePhase.RECONCILIATION_REQUIRED.value


def test_recovery_with_missing_or_corrupt_pending_item_fails_closed(tmp_path):
    """Mandatory Regression Test F (part 1): Recovery with missing or corrupt pending item cannot COMPLETE."""
    from payoutproof.storage.db import Database
    from payoutproof.core.crypto import derive_idempotency_key

    db_path = tmp_path / "corrupt_item_rec.db"
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
    s = make_admitted_case_state(
        case_id="RC-CORRUPT-ITEM-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    s = s.model_copy(update={"phase": CasePhase.READY_FOR_HUMAN_HANDOFF})
    db.save_case(s)
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    db.save_case(s)
    grant = s.grant
    assert grant is not None

    # Step 1: Submit adapter attempt
    dec, item, err = adapter.submit_handoff(grant=grant, intent=intent)
    assert dec == AdapterDecision.PENDING_ITEM_CREATED
    assert item is not None

    # Step 2: Delete the pending approval item row in SQLite to simulate corruption/loss
    with db.get_connection() as conn:
        conn.execute("DELETE FROM pending_approval_items WHERE item_id = ?", (item.item_id,))

    # Step 3: Attempt recovery
    stale_case = db.load_case("RC-CORRUPT-ITEM-01")
    assert stale_case is not None
    recovered = HandoffService.execute_handoff(state=stale_case, adapter=adapter, grant_secret=TEST_GRANT_SECRET)

    # Recovery must fail closed and NOT transition to COMPLETE
    assert recovered.phase != CasePhase.COMPLETE
    assert recovered.handoff.pending_item_id is None
    assert recovered.handoff.last_adapter_decision == AdapterDecision.RECOVERY_INTEGRITY_FAILURE_NO_RETRY


def test_ambiguity_recovery_with_unexpected_pending_item_or_inconsistent_grant_fails_closed(tmp_path):
    """Mandatory Regression Test F (part 2): Ambiguity with an unexpected pending item or wrong durable grant state cannot enter reconciliation as if valid."""
    from payoutproof.storage.db import Database
    from payoutproof.core.crypto import derive_idempotency_key

    db_path = tmp_path / "inconsistent_ambig.db"
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
    s = make_admitted_case_state(
        case_id="RC-INCONSISTENT-AMBIG-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    s = s.model_copy(update={"phase": CasePhase.READY_FOR_HUMAN_HANDOFF})
    db.save_case(s)
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    db.save_case(s)
    grant = s.grant
    assert grant is not None

    # 1. Execute ambiguous handoff
    s_ambig = HandoffService.execute_handoff(state=s, adapter=adapter, grant_secret=TEST_GRANT_SECRET, simulate_ambiguity=True)
    assert s_ambig.phase == CasePhase.RECONCILIATION_REQUIRED

    # 2. Inject an unexpected pending item for this grant and reset state_json to stale crash gap
    import json
    with db.get_connection() as conn:
        conn.execute("""
            INSERT INTO pending_approval_items (
                item_id, case_id, grant_id, idempotency_key, counterparty, destination, amount, currency, purpose, status, created_at
            ) VALUES ('INJECTED-ITEM', 'RC-INCONSISTENT-AMBIG-01', ?, 'IDEM-INJECTED', 'CP', 'DEST', '100', 'INR', 'PURPOSE', 'PENDING_FINANCE_APPROVAL', datetime('now'))
        """, (grant.grant_id,))
        conn.execute(
            "UPDATE risk_cases SET state_json = ?, phase = 'READY_FOR_HUMAN_HANDOFF' WHERE case_id = 'RC-INCONSISTENT-AMBIG-01'",
            (json.dumps(s.model_dump()),),
        )

    # 3. Re-run recovery: must fail closed because an unexpected item exists
    stale_case = s.model_copy(update={"phase": CasePhase.READY_FOR_HUMAN_HANDOFF})
    rec_res = HandoffService.execute_handoff(state=stale_case, adapter=adapter, grant_secret=TEST_GRANT_SECRET)
    assert rec_res.phase != CasePhase.COMPLETE
    assert rec_res.phase != CasePhase.RECONCILIATION_REQUIRED
