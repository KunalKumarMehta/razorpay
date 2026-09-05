"""Tests for SQLite WAL persistence and case reloading."""

import pytest
import tempfile
from pathlib import Path
from payoutproof.storage.db import Database
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.core.models import PaymentIntent, HandoffGrant
from payoutproof.core.enums import CasePhase, IntentStatus, GrantStatus, ProcessingAuthorityStatus, AdapterDecision
from tests.helpers import make_authorized_bundle_action, TEST_GRANT_SECRET, TEST_AUDIT_CHECKPOINT_SECRET


def test_sqlite_persistence_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_payoutproof.db"
        db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

        # Create and step a case
        s = StateMachine.initial_state(case_id="RC-STORE-01")
        s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-STORE-01"))
        s = StateMachine.reduce(s, {"type": "EXTRACT_INTENT", "payload": {"counterparty": "Apex Tech", "destination": "HDFC ••5544", "amount": "300000"}})
        s = StateMachine.reduce(s, {"type": "CONFIRM_INTENT"})
        s = StateMachine.reduce(s, {"type": "ADD_CALLBACK_EVIDENCE"})
        s = StateMachine.reduce(s, {"type": "ADD_DESTINATION_APPROVAL"})
        s = StateMachine.reduce(s, {"type": "EVALUATE_POLICY"})
        s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)

        # Save to SQLite
        db.save_case(s)

        # Reload from SQLite
        reloaded = db.load_case("RC-STORE-01")
        assert reloaded is not None
        assert reloaded.case_id == "RC-STORE-01"
        assert reloaded.case_version == s.case_version
        assert reloaded.processing_authority == ProcessingAuthorityStatus.VALID
        assert reloaded.authority_record is not None
        assert reloaded.authority_record.processing_route == s.authority_record.processing_route
        assert reloaded.intent.counterparty == "Apex Tech"
        assert reloaded.intent.status == IntentStatus.CONFIRMED
        assert reloaded.grant is not None
        assert reloaded.grant.status == GrantStatus.ACTIVE
        assert len(reloaded.audit) == len(s.audit)

        # Check list cases
        cases = db.list_cases()
        assert len(cases) == 1
        assert cases[0]["case_id"] == "RC-STORE-01"


def test_database_migration_from_older_schema(tmp_path):
    """Database migration test for an older adapter_attempts schema."""
    import sqlite3
    from payoutproof.storage.db import Database

    db_file = tmp_path / "old_schema.db"

    # 1. Create older SQLite database schema without new columns and without pending_approval_items
    conn = sqlite3.connect(db_file)
    conn.executescript("""
        CREATE TABLE risk_cases (
            case_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            case_version INTEGER NOT NULL,
            phase TEXT NOT NULL,
            state_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            actor TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details_json TEXT NOT NULL,
            UNIQUE(case_id, seq)
        );

        CREATE TABLE handoff_grants (
            grant_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            bound_intent_hash TEXT NOT NULL,
            bound_snapshot_hash TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            outcome TEXT NOT NULL,
            nonce TEXT UNIQUE NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            signature TEXT NOT NULL,
            status TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE adapter_attempts (
            idempotency_key TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            grant_id TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL,
            last_decision TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)

    # Insert an existing pre-migration attempt row
    conn.execute("""
        INSERT INTO adapter_attempts (idempotency_key, case_id, grant_id, attempts, status, last_decision, created_at, updated_at)
        VALUES ('IDEM-OLD-01', 'RC-OLD-01', 'GRANT-OLD-01', 1, 'COMPLETED', 'PENDING_ITEM_CREATED', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')
    """)
    conn.commit()
    conn.close()

    # 2. Instantiate Database - triggers automatic safe idempotent migration
    db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    with db.get_connection() as c:
        # Check that pending_approval_items table was created
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "pending_approval_items" in tables

        # Check that missing columns were added to adapter_attempts
        cols = {r["name"] for r in c.execute("PRAGMA table_info(adapter_attempts)").fetchall()}
        assert "decision" in cols
        assert "ambiguity_state" in cols
        assert "pending_item_id" in cols
        assert "error_code" in cols
        assert "error_message" in cols

        # Check that old row data was migrated correctly
        row = c.execute("SELECT * FROM adapter_attempts WHERE idempotency_key = 'IDEM-OLD-01'").fetchone()
        assert row is not None
        assert row["decision"] == "PENDING_ITEM_CREATED"

        # Check unique constraint on grant_id in adapter_attempts
        indexes = {r["name"] for r in c.execute("PRAGMA index_list(adapter_attempts)").fetchall()}
        assert "idx_adapter_attempts_grant_id" in indexes

        # Attempting to insert duplicate grant_id raises IntegrityError
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("""
                INSERT INTO adapter_attempts (idempotency_key, case_id, grant_id, attempts, status, decision, created_at, updated_at)
                VALUES ('IDEM-DUPLICATE-GRANT', 'RC-OLD-02', 'GRANT-OLD-01', 1, 'COMPLETED', 'PENDING_ITEM_CREATED', '2026-09-02T00:00:00Z', '2026-09-02T00:00:00Z')
            """)


def test_old_schema_duplicate_grant_migration_and_quarantine(tmp_path):
    """Mandatory Regression Test 8: Old-schema duplicate-grant migration succeeds,
    canonical+quarantine counts are asserted, unknown decision never produces recovery;
    reconstruct Database twice.
    """
    import sqlite3
    from payoutproof.storage.db import Database
    from payoutproof.case_workflow.handoff_service import HandoffService
    from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
    from payoutproof.core.models import PaymentIntent, PolicyEvaluationResult
    from payoutproof.core.enums import PolicyOutcome, IntentStatus
    from payoutproof.grants.issuer import GrantIssuer
    from tests.helpers import make_admitted_case_state, TEST_GRANT_SECRET

    db_file = tmp_path / "legacy_duplicates.db"

    conn = sqlite3.connect(db_file)
    conn.executescript("""
        CREATE TABLE risk_cases (
            case_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            case_version INTEGER NOT NULL,
            phase TEXT NOT NULL,
            state_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            actor TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details_json TEXT NOT NULL,
            UNIQUE(case_id, seq)
        );

        CREATE TABLE handoff_grants (
            grant_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            bound_intent_hash TEXT NOT NULL,
            bound_snapshot_hash TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            outcome TEXT NOT NULL,
            nonce TEXT UNIQUE NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            signature TEXT NOT NULL,
            status TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE adapter_attempts (
            idempotency_key TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            grant_id TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL,
            last_decision TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)

    # Insert duplicate grant rows for GRANT-DUP-01
    conn.execute("""
        INSERT INTO adapter_attempts (idempotency_key, case_id, grant_id, attempts, status, last_decision, created_at, updated_at)
        VALUES ('IDEM-DUP-01A', 'RC-LEGACY-01', 'GRANT-DUP-01', 1, 'COMPLETED', 'PENDING_ITEM_CREATED', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')
    """)
    conn.execute("""
        INSERT INTO adapter_attempts (idempotency_key, case_id, grant_id, attempts, status, last_decision, created_at, updated_at)
        VALUES ('IDEM-DUP-01B', 'RC-LEGACY-01', 'GRANT-DUP-01', 1, 'COMPLETED', 'PENDING_ITEM_CREATED', '2026-09-01T00:01:00Z', '2026-09-01T00:01:00Z')
    """)
    # Insert row with missing/null last_decision
    conn.execute("""
        INSERT INTO adapter_attempts (idempotency_key, case_id, grant_id, attempts, status, last_decision, created_at, updated_at)
        VALUES ('IDEM-NULL-02', 'RC-LEGACY-02', 'GRANT-NULL-02', 1, 'UNKNOWN_STATUS', NULL, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')
    """)
    conn.commit()
    conn.close()

    # 1. First database construction triggers migration
    db1 = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    with db1.get_connection() as c:
        # Canonical attempt count for GRANT-DUP-01 is 1
        dup_canonical = c.execute("SELECT count(*) FROM adapter_attempts WHERE grant_id = 'GRANT-DUP-01'").fetchone()[0]
        assert dup_canonical == 1

        # Quarantine count is 1
        quarantine_rows = c.execute("SELECT * FROM adapter_attempts_quarantine").fetchall()
        assert len(quarantine_rows) == 1
        assert quarantine_rows[0]["original_grant_id"] == "GRANT-DUP-01"
        assert quarantine_rows[0]["quarantine_reason"] == "DUPLICATE_GRANT_ID_CONFLICT"

        # NULL last_decision row was migrated with decision = 'UNKNOWN'
        null_row = c.execute("SELECT * FROM adapter_attempts WHERE grant_id = 'GRANT-NULL-02'").fetchone()
        assert null_row is not None
        assert null_row["decision"] == "UNKNOWN"

    # 2. Reconstruct Database twice to prove idempotency
    db2 = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with db2.get_connection() as c:
        assert c.execute("SELECT count(*) FROM adapter_attempts WHERE grant_id = 'GRANT-DUP-01'").fetchone()[0] == 1
        assert c.execute("SELECT count(*) FROM adapter_attempts_quarantine").fetchone()[0] == 1

    # 3. Test that unknown legacy decision never produces recovery
    intent = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        status=IntentStatus.CONFIRMED,
        intent_hash="sample_hash_legacy_rec",
    )
    s_legacy = make_admitted_case_state(
        case_id="RC-LEGACY-02",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    # Attach a signed active grant matching GRANT-NULL-02 from the migrated UNKNOWN attempt row
    grant_unknown = HandoffGrant(
        grant_id="GRANT-NULL-02",
        tenant_id="tenant_01",
        case_id="RC-LEGACY-02",
        bound_intent_hash=intent.intent_hash,
        bound_snapshot_hash="dummy_snapshot_hash_legacy",
        policy_version="PP-POLICY-V1",
        outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
        nonce="dummy_nonce_02",
        issued_at="2026-09-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
        signature="dummy_signature",
        status=GrantStatus.ACTIVE,
        used=False,
    )
    s_legacy = s_legacy.model_copy(update={"grant": grant_unknown})
    db2.save_case(s_legacy)

    adapter2 = FakeApprovalRailAdapter(db=db2, grant_secret=TEST_GRANT_SECRET)
    s_post = HandoffService.execute_handoff(state=s_legacy, adapter=adapter2, grant_secret=TEST_GRANT_SECRET)
    assert s_post.phase != CasePhase.COMPLETE
    assert s_post.handoff.pending_item_id is None
    assert s_post.handoff.last_adapter_decision == AdapterDecision.RECOVERY_INTEGRITY_FAILURE_NO_RETRY


def test_grant_monotonicity_invalidated_consumed_suspended_and_used(tmp_path):
    """Mandatory Regression Test C: Save INVALIDATED state then stale ACTIVE -> durable INVALIDATED remains.
    Repeat for CONSUMED and SUSPENDED; used monotonic.
    """
    from payoutproof.core.models import PolicyEvaluationResult
    from payoutproof.core.enums import PolicyOutcome
    from payoutproof.grants.issuer import GrantIssuer
    from payoutproof.storage.db import StaleCaseStateError
    from tests.helpers import make_admitted_case_state, make_confirmed_intent, TEST_GRANT_SECRET, TEST_AUDIT_CHECKPOINT_SECRET

    db_file = tmp_path / "grant_monotonicity.db"
    db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    intent = make_confirmed_intent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
    )

    # 1. Test INVALIDATED -> stale ACTIVE
    state1 = make_admitted_case_state(
        case_id="RC-MONO-INV",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    grant1 = GrantIssuer.issue_grant(state1, secret=TEST_GRANT_SECRET)
    active_state1 = state1.model_copy(update={"grant": grant1})
    db.save_case(active_state1)

    invalidated_grant1 = grant1.model_copy(update={"status": GrantStatus.INVALIDATED, "used": False})
    inv_state1 = state1.model_copy(update={"grant": invalidated_grant1})
    db.save_case(inv_state1)

    with db.get_connection() as conn:
        g = conn.execute("SELECT status, used FROM handoff_grants WHERE grant_id = ?", (grant1.grant_id,)).fetchone()
        assert g["status"] == "INVALIDATED"
        assert g["used"] == 0

    # Attempt to overwrite with stale ACTIVE state - must raise StaleCaseStateError
    with pytest.raises(StaleCaseStateError):
        db.save_case(active_state1)
    with db.get_connection() as conn:
        g = conn.execute("SELECT status, used FROM handoff_grants WHERE grant_id = ?", (grant1.grant_id,)).fetchone()
        assert g["status"] == "INVALIDATED"
        assert g["used"] == 0

    # 2. Test CONSUMED (used=1) -> stale ACTIVE (used=0)
    state2 = make_admitted_case_state(
        case_id="RC-MONO-CONS",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    grant2 = GrantIssuer.issue_grant(state2, secret=TEST_GRANT_SECRET)
    active_state2 = state2.model_copy(update={"grant": grant2})
    db.save_case(active_state2)

    consumed_grant2 = grant2.model_copy(update={"status": GrantStatus.CONSUMED, "used": True})
    cons_state2 = state2.model_copy(update={"grant": consumed_grant2})
    db.save_case(cons_state2)

    with db.get_connection() as conn:
        g = conn.execute("SELECT status, used FROM handoff_grants WHERE grant_id = ?", (grant2.grant_id,)).fetchone()
        assert g["status"] == "CONSUMED"
        assert g["used"] == 1

    # Stale ACTIVE write must raise StaleCaseStateError and not revert status to ACTIVE or used to 0
    with pytest.raises(StaleCaseStateError):
        db.save_case(active_state2)
    with db.get_connection() as conn:
        g = conn.execute("SELECT status, used FROM handoff_grants WHERE grant_id = ?", (grant2.grant_id,)).fetchone()
        assert g["status"] == "CONSUMED"
        assert g["used"] == 1

    # 3. Test SUSPENDED_FOR_RECONCILIATION (used=1) -> stale ACTIVE (used=0)
    state3 = make_admitted_case_state(
        case_id="RC-MONO-SUSP",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    grant3 = GrantIssuer.issue_grant(state3, secret=TEST_GRANT_SECRET)
    active_state3 = state3.model_copy(update={"grant": grant3})
    db.save_case(active_state3)

    susp_grant3 = grant3.model_copy(update={"status": GrantStatus.SUSPENDED_FOR_RECONCILIATION, "used": True})
    susp_state3 = state3.model_copy(update={"grant": susp_grant3})
    db.save_case(susp_state3)

    with db.get_connection() as conn:
        g = conn.execute("SELECT status, used FROM handoff_grants WHERE grant_id = ?", (grant3.grant_id,)).fetchone()
        assert g["status"] == "SUSPENDED_FOR_RECONCILIATION"
        assert g["used"] == 1

    # Stale ACTIVE write must raise StaleCaseStateError and not revert status to ACTIVE or used to 0
    with pytest.raises(StaleCaseStateError):
        db.save_case(active_state3)
    with db.get_connection() as conn:
        g = conn.execute("SELECT status, used FROM handoff_grants WHERE grant_id = ?", (grant3.grant_id,)).fetchone()
        assert g["status"] == "SUSPENDED_FOR_RECONCILIATION"
        assert g["used"] == 1


def test_intermediate_v1_migration_rebuilds_nullable_decision_and_quarantines_empty_grant(tmp_path):
    """Mandatory Regression Test D: Intermediate v1 nullable-full-column schema is rebuilt to strict constraints;
    invalid empty-grant legacy row quarantined; double construction stable.
    """
    import sqlite3
    from payoutproof.storage.db import Database

    db_file = tmp_path / "intermediate_v1.db"
    conn = sqlite3.connect(db_file)

    # Intermediate v1 schema: all current column names present, but decision is NULLABLE (notnull=0)
    # and missing unique constraint on grant_id
    conn.executescript("""
        CREATE TABLE risk_cases (
            case_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            case_version INTEGER NOT NULL,
            phase TEXT NOT NULL,
            state_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            actor TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details_json TEXT NOT NULL,
            UNIQUE(case_id, seq)
        );

        CREATE TABLE handoff_grants (
            grant_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            bound_intent_hash TEXT NOT NULL,
            bound_snapshot_hash TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            outcome TEXT NOT NULL,
            nonce TEXT UNIQUE NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            signature TEXT NOT NULL,
            status TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE adapter_attempts (
            idempotency_key TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            grant_id TEXT NOT NULL,
            status TEXT NOT NULL,
            decision TEXT,
            ambiguity_state TEXT,
            pending_item_id TEXT,
            error_code TEXT,
            error_message TEXT,
            attempts INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)

    # Insert a valid attempt row
    conn.execute("""
        INSERT INTO adapter_attempts (idempotency_key, case_id, grant_id, status, decision, attempts, created_at, updated_at)
        VALUES ('IDEM-V1-01', 'RC-V1-01', 'GRANT-V1-01', 'COMPLETED', 'PENDING_ITEM_CREATED', 1, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')
    """)
    # Insert an invalid row with empty grant_id
    conn.execute("""
        INSERT INTO adapter_attempts (idempotency_key, case_id, grant_id, status, decision, attempts, created_at, updated_at)
        VALUES ('IDEM-V1-EMPTY', 'RC-V1-02', '', 'UNKNOWN', NULL, 1, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')
    """)
    # Insert an invalid row with null decision
    conn.execute("""
        INSERT INTO adapter_attempts (idempotency_key, case_id, grant_id, status, decision, attempts, created_at, updated_at)
        VALUES ('IDEM-V1-NULLDEC', 'RC-V1-03', 'GRANT-V1-03', 'UNKNOWN', NULL, 1, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')
    """)
    conn.commit()
    conn.close()

    # 1. First DB construction rebuilds schema
    db1 = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    with db1.get_connection() as c:
        # Verify PRAGMA table_info has decision NOT NULL (notnull == 1)
        info = {r["name"]: dict(r) for r in c.execute("PRAGMA table_info(adapter_attempts)").fetchall()}
        assert info["decision"]["notnull"] == 1
        assert info["grant_id"]["notnull"] == 1

        # Verify unique index on grant_id exists
        indexes = {r["name"] for r in c.execute("PRAGMA index_list(adapter_attempts)").fetchall() if r["unique"] == 1}
        assert "idx_adapter_attempts_grant_id" in indexes

        # Verify valid rows are preserved and canonicalized
        canonical_rows = c.execute("SELECT * FROM adapter_attempts ORDER BY idempotency_key").fetchall()
        assert len(canonical_rows) == 2
        assert canonical_rows[0]["idempotency_key"] == "IDEM-V1-01"
        assert canonical_rows[0]["decision"] == "PENDING_ITEM_CREATED"
        assert canonical_rows[1]["idempotency_key"] == "IDEM-V1-NULLDEC"
        assert canonical_rows[1]["decision"] == "UNKNOWN"

        # Verify empty grant row was quarantined
        q_rows = c.execute("SELECT * FROM adapter_attempts_quarantine").fetchall()
        assert len(q_rows) == 1
        assert q_rows[0]["quarantine_reason"] == "MISSING_GRANT_ID"
        assert q_rows[0]["original_idempotency_key"] == "IDEM-V1-EMPTY"

    # 2. Reconstruct Database second time to prove idempotency
    db2 = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with db2.get_connection() as c:
        assert c.execute("SELECT count(*) FROM adapter_attempts").fetchone()[0] == 2
        assert c.execute("SELECT count(*) FROM adapter_attempts_quarantine").fetchone()[0] == 1
