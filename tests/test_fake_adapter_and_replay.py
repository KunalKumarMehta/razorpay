"""Tests for Fake Action Adapter, replay prevention, and ambiguity reconciliation."""

import concurrent.futures
import pytest
from payoutproof.core.models import PaymentIntent, RiskCaseState, PolicyEvaluationResult, HandoffGrant
from payoutproof.core.enums import IntentStatus, PolicyOutcome, AdapterDecision, GrantStatus, DestinationStatus
from payoutproof.grants.issuer import GrantIssuer
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
from payoutproof.storage.db import Database
from tests.helpers import (
    make_admitted_case_state,
    make_confirmed_intent,
    TEST_GRANT_SECRET,
    TEST_AUDIT_CHECKPOINT_SECRET,
)


def test_fake_adapter_creates_single_pending_item():
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
        case_id="RC-ADAPT-01",
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

    decision, item, err = adapter.submit_handoff(
        grant=grant,
        intent=intent,
    )

    assert decision == AdapterDecision.PENDING_ITEM_CREATED
    assert item is not None
    assert item.status == "PENDING_FINANCE_APPROVAL"
    assert err is None


def test_fake_adapter_rejects_replay_of_consumed_grant():
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
        case_id="RC-ADAPT-02",
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

    # First attempt succeeds
    decision1, item1, err1 = adapter.submit_handoff(grant=grant, intent=intent)
    assert decision1 == AdapterDecision.PENDING_ITEM_CREATED

    # Replay attempt with same grant fails
    decision2, item2, err2 = adapter.submit_handoff(grant=grant, intent=intent)
    assert decision2 == AdapterDecision.REPLAY_REJECTED
    assert item2 is None
    assert "already been consumed" in (err2 or "").lower()


def test_twenty_concurrent_calls_with_independent_databases_and_adapters(tmp_path):
    """20 independent DB/adapter instances, no caller key input: one success, 19 replay rejections,
    one attempt/item, durable terminal grant.
    """
    db_file = tmp_path / "concurrent_shared.db"
    main_db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    intent = make_confirmed_intent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
    )
    state = make_admitted_case_state(
        case_id="RC-CONCUR-20",
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
    main_db.save_case(state)

    # Launch 20 concurrent threads, each with its own Database and Adapter instance pointing to db_file
    def worker_attempt(worker_id: int):
        thread_db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
        thread_adapter = FakeApprovalRailAdapter(
            db=thread_db,
            grant_secret=TEST_GRANT_SECRET,
            audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        )
        return thread_adapter.submit_handoff(
            grant=grant,
            intent=intent,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(worker_attempt, i) for i in range(20)]
        results = [f.result() for f in futures]

    created = [r for r in results if r[0] == AdapterDecision.PENDING_ITEM_CREATED]
    rejected = [r for r in results if r[0] == AdapterDecision.REPLAY_REJECTED]

    # Exactly 1 winner, 19 losing calls
    assert len(created) == 1
    assert len(rejected) == 19
    assert created[0][1] is not None
    assert created[0][1].status == "PENDING_FINANCE_APPROVAL"

    # SQLite is the authoritative replay store: exactly one attempt, one pending item, grant used
    with main_db.get_connection() as conn:
        attempt_count = conn.execute("SELECT count(*) FROM adapter_attempts").fetchone()[0]
        item_count = conn.execute("SELECT count(*) FROM pending_approval_items").fetchone()[0]
        grant_row = conn.execute("SELECT used, status FROM handoff_grants WHERE grant_id = ?", (grant.grant_id,)).fetchone()

    assert attempt_count == 1
    assert item_count == 1
    assert grant_row is not None
    assert grant_row["used"] == 1
    assert grant_row["status"] == "CONSUMED"


def test_stale_active_state_save_cannot_reopen_consumed_grant(tmp_path):
    """Mandatory Regression Test 1: Consume grant through adapter; save previously captured stale ACTIVE state;
    query handoff_grants and prove used=1 and terminal status remain. Retry remains rejected.
    """
    db_file = tmp_path / "stale_save.db"
    db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
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
    state = make_admitted_case_state(
        case_id="RC-MONOTONIC-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    grant = GrantIssuer.issue_grant(state, secret=TEST_GRANT_SECRET)
    stale_active_state = state.model_copy(update={"grant": grant})
    db.save_case(stale_active_state)

    # Consume grant through adapter
    dec, item, err = adapter.submit_handoff(grant=grant, intent=intent)
    assert dec == AdapterDecision.PENDING_ITEM_CREATED

    # Now attempt to save previously captured stale ACTIVE state - must be rejected
    from payoutproof.storage.db import StaleCaseStateError
    with pytest.raises(StaleCaseStateError):
        db.save_case(stale_active_state)

    # Query handoff_grants table directly and prove used=1 and CONSUMED remain
    with db.get_connection() as conn:
        g_row = conn.execute("SELECT used, status FROM handoff_grants WHERE grant_id = ?", (grant.grant_id,)).fetchone()
        assert g_row is not None
        assert g_row["used"] == 1
        assert g_row["status"] == "CONSUMED"

    # Retry remains rejected
    retry_dec, retry_item, retry_err = adapter.submit_handoff(grant=grant, intent=intent)
    assert retry_dec == AdapterDecision.REPLAY_REJECTED
    assert retry_item is None


def test_unpersisted_grant_adapter_call_creates_zero_records(tmp_path):
    """Mandatory Regression Test 3: Adapter call with a signed but never-persisted grant
    returns non-success and creates zero handoff_grants, attempts, and pending items.
    """
    db_file = tmp_path / "unpersisted.db"
    db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
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
    state = make_admitted_case_state(
        case_id="RC-UNPERSISTED-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    # Grant is signed in-memory, but NEVER persisted to db!
    grant = GrantIssuer.issue_grant(state, secret=TEST_GRANT_SECRET)

    decision, item, err = adapter.submit_handoff(grant=grant, intent=intent)
    assert decision != AdapterDecision.PENDING_ITEM_CREATED
    assert decision == AdapterDecision.GRANT_INVALID_OR_EXPIRED
    assert item is None

    # Prove zero handoff_grants, adapter_attempts, or pending_approval_items were created
    with db.get_connection() as conn:
        assert conn.execute("SELECT count(*) FROM handoff_grants").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM adapter_attempts").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM pending_approval_items").fetchone()[0] == 0


def test_forged_grant_sharing_persisted_id_is_rejected_without_mutation(tmp_path):
    """Mandatory Regression Test 4: Adapter call with a forged supplied grant object sharing a
    persisted grant_id but altered bound field is rejected without mutation.
    """
    db_file = tmp_path / "forged.db"
    db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
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
    state = make_admitted_case_state(
        case_id="RC-FORGED-01",
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
    db.save_case(state)

    # Forge the grant object: same grant_id, but altered bound_intent_hash or tenant_id
    forged_grant = grant.model_copy(update={"tenant_id": "tenant_attacker"})

    decision, item, err = adapter.submit_handoff(grant=forged_grant, intent=intent)
    assert decision == AdapterDecision.GRANT_INVALID_OR_EXPIRED
    assert item is None
    assert "mismatch" in (err or "").lower() or "verification failed" in (err or "").lower()

    # Verify no mutation occurred on the authentic durable grant
    with db.get_connection() as conn:
        g_row = conn.execute("SELECT * FROM handoff_grants WHERE grant_id = ?", (grant.grant_id,)).fetchone()
        assert g_row is not None
        assert g_row["used"] == 0
        assert g_row["status"] == "ACTIVE"
        assert g_row["tenant_id"] == "tenant_01"
        assert conn.execute("SELECT count(*) FROM adapter_attempts").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM pending_approval_items").fetchone()[0] == 0


def test_mutated_intent_amount_with_old_hash_rejected_without_item_or_grant_consumption(tmp_path):
    """Mandatory Regression Test A: Persist valid grant; pass intent with mutated amount but retained old hash ->
    non-success, zero attempts/items, grant remains ACTIVE/unused."""
    from payoutproof.core.crypto import compute_intent_hash

    db_file = tmp_path / "mutated_amount.db"
    db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    intent = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        status=IntentStatus.CONFIRMED,
    )
    real_hash = compute_intent_hash(intent)
    intent = intent.model_copy(update={"intent_hash": real_hash})

    state = make_admitted_case_state(
        case_id="RC-MUTATE-AMT-01",
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
    db.save_case(state)

    # Mutate intent amount to 999999 while keeping old hash
    mutated_intent = intent.model_copy(update={"amount": "999999", "intent_hash": real_hash})

    decision, item, err = adapter.submit_handoff(grant=grant, intent=mutated_intent)
    assert decision != AdapterDecision.PENDING_ITEM_CREATED
    assert decision == AdapterDecision.INTENT_MISMATCH
    assert item is None

    # Prove zero attempts or pending items created, grant remains ACTIVE and unused
    with db.get_connection() as conn:
        assert conn.execute("SELECT count(*) FROM adapter_attempts").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM pending_approval_items").fetchone()[0] == 0
        g_row = conn.execute("SELECT used, status FROM handoff_grants WHERE grant_id = ?", (grant.grant_id,)).fetchone()
        assert g_row is not None
        assert g_row["used"] == 0
        assert g_row["status"] == "ACTIVE"


@pytest.mark.parametrize("field,mutated_val", [
    ("amount", "999999"),
    ("destination", "ICICI ••9999"),
    ("counterparty", "Malicious Imposter"),
    ("purpose", "Unauthorized transfer"),
    ("instruction_reference", "FORGED-REF"),
    ("provenance", ["Forged provenance span"]),
    ("status", IntentStatus.EXTRACTED),
    ("destination_status", DestinationStatus.SUSPICIOUS_OR_CHANGED),
])
def test_parameterized_mutated_intent_fields_rejected_and_inconsistent_persisted_case_rejected(tmp_path, field, mutated_val):
    """Mandatory Regression Test B: Persist valid grant; mutate each material canonical field in parameterized tests
    while retaining old hash -> all rejected. Also reject a persisted case whose intent fields/hash are internally inconsistent.
    """
    from payoutproof.core.crypto import compute_intent_hash
    from payoutproof.core.enums import DestinationStatus

    db_file = tmp_path / f"mutated_{field}.db"
    db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    intent = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        instruction_reference="VOICE-17",
        provenance=["VOICE-17: span 00:04"],
        status=IntentStatus.CONFIRMED,
    )
    real_hash = compute_intent_hash(intent)
    intent = intent.model_copy(update={"intent_hash": real_hash})

    state = make_admitted_case_state(
        case_id=f"RC-MUTATE-{field.upper()}",
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
    db.save_case(state)

    # Mutate the specific field while retaining old intent_hash
    mutated_intent = intent.model_copy(update={field: mutated_val, "intent_hash": real_hash})

    dec, item, err = adapter.submit_handoff(grant=grant, intent=mutated_intent)
    assert dec == AdapterDecision.INTENT_MISMATCH
    assert item is None

    # Verify nothing was mutated or created
    with db.get_connection() as conn:
        assert conn.execute("SELECT count(*) FROM adapter_attempts").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM pending_approval_items").fetchone()[0] == 0
        g_row = conn.execute("SELECT used, status FROM handoff_grants WHERE grant_id = ?", (grant.grant_id,)).fetchone()
        assert g_row["used"] == 0
        assert g_row["status"] == "ACTIVE"


def test_internally_inconsistent_persisted_case_intent_rejected(tmp_path):
    """Mandatory Regression Test B (part 2): Reject a persisted case whose intent fields/hash are internally inconsistent."""
    import json
    from payoutproof.core.crypto import compute_intent_hash

    db_file = tmp_path / "inconsistent_case.db"
    db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    adapter = FakeApprovalRailAdapter(
        db=db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    intent = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        status=IntentStatus.CONFIRMED,
    )
    real_hash = compute_intent_hash(intent)
    intent = intent.model_copy(update={"intent_hash": real_hash})

    state = make_admitted_case_state(
        case_id="RC-INCONSISTENT-01",
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
    db.save_case(state)

    # Manually tamper persisted case JSON to have amount 999999 but retain old intent_hash in risk_cases
    with db.get_connection() as conn:
        tampered_state = state.model_copy(update={
            "intent": intent.model_copy(update={"amount": "999999", "intent_hash": real_hash})
        })
        conn.execute("UPDATE risk_cases SET state_json = ? WHERE case_id = 'RC-INCONSISTENT-01'", (json.dumps(tampered_state.model_dump()),))

    dec, item, err = adapter.submit_handoff(grant=grant, intent=intent)
    assert dec == AdapterDecision.INTENT_MISMATCH
    assert item is None
    assert "inconsistent" in (err or "").lower() or "mismatch" in (err or "").lower()
