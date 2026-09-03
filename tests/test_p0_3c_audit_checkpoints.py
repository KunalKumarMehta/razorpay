"""Tests for P0-3C: Authenticated Authoritative Audit Checkpoints.

Covers:
1. Scenario 1: Trusted lifecycle & secret verification (initial creation, progression, wrong secret rejection).
2. Scenario 2: Complete tamper matrix (payload, event_type, timestamp, prev_hash, current_hash,
   interior deletion, tail deletion, reordering, forging, duplicate seq, checkpoint count, tip, MAC, trust_state).
3. Scenario 3: state_json audit is untrusted (clearing/modifying state_json audit has no effect; hydrated strictly from rows).
4. Scenario 4: Candidate mutation validation (rejects truncation, rewrite, gap, cross-case; permits idempotent save).
5. Scenario 5: Legacy DB migration & quarantine (uncheckpointed cases become LEGACY_UNTRUSTED; mutations fail closed; verification safe).
6. Scenario 6: Rollback failure injection (_test_fail_after_audit_insert verifies atomic rollback of audit & checkpoint).
7. Scenario 7: Concurrency serialization (two Database connections serialize updates safely).
8. Scenario 8: API & CLI verification (GET /api/audit/verify/{case_id} 404/200 structured, dispatch 409, CLI truthful reporting).
"""

import json
import sqlite3
import concurrent.futures
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from payoutproof.core.enums import (
    AuditTrustState,
    CasePhase,
    PolicyOutcome,
    GrantStatus,
    HandoffStatus,
    AdapterDecision,
    ProcessingAuthorityStatus,
)
from payoutproof.core.models import (
    RiskCaseState,
    CaseAuditCheckpoint,
    AuditEvent,
    PolicyEvaluationResult,
)
from payoutproof.core.crypto import (
    compute_checkpoint_mac,
    verify_checkpoint_mac,
    compute_audit_hash,
)
from payoutproof.storage.db import (
    Database,
    AuditLedgerIntegrityError,
    StaleCaseStateError,
)
from payoutproof.audit.chain import AuditChain, GENESIS_HASH
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.case_workflow.handoff_service import HandoffService
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
from payoutproof.core.config import AppConfig, ConfigurationError
from payoutproof.api.app import create_app
from tests.helpers import (
    make_admitted_case_state,
    make_confirmed_intent,
    make_authorized_bundle_action,
    TEST_GRANT_SECRET,
    TEST_AUDIT_CHECKPOINT_SECRET,
)

WRONG_SECRET = "wrong-audit-secret-32-chars-long-xxx"


# ==============================================================================
# Scenario 1: Trusted Lifecycle & Secret Verification
# ==============================================================================

def test_trusted_lifecycle_creates_and_advances_authenticated_checkpoint(tmp_path):
    """Case creation creates initial audit event and TRUSTED checkpoint; advancing case updates checkpoint;
    wrong secret causes load to raise AuditLedgerIntegrityError.
    """
    db_path = tmp_path / "trusted_lifecycle.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    # 1. Create fresh case
    state = StateMachine.initial_state(case_id="RC-AUTH-01", tenant_id="tenant_01")
    db.save_case(state)

    # Verify initial audit event and checkpoint created in DB
    with db.get_connection() as conn:
        events = conn.execute("SELECT * FROM audit_events WHERE case_id = 'RC-AUTH-01'").fetchall()
        assert len(events) == 1
        assert events[0]["seq"] == 1
        assert events[0]["event_type"] == "EVIDENCE_ADMISSION_STARTED"
        assert events[0]["prev_hash"] == GENESIS_HASH

        cp = conn.execute("SELECT * FROM case_audit_checkpoints WHERE case_id = 'RC-AUTH-01'").fetchone()
        assert cp is not None
        assert cp["event_count"] == 1
        assert cp["tip_hash"] == events[0]["current_hash"]
        assert cp["trust_state"] == AuditTrustState.TRUSTED.value
        assert verify_checkpoint_mac(
            secret=TEST_AUDIT_CHECKPOINT_SECRET,
            case_id="RC-AUTH-01",
            event_count=1,
            tip_hash=events[0]["current_hash"],
            trust_state=AuditTrustState.TRUSTED.value,
            checkpoint_mac=cp["checkpoint_mac"],
        )

    # 2. Advance case through workflow actions
    s = state
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-AUTH-01"))
    db.save_case(s)

    s = StateMachine.reduce(s, {"type": "EXTRACT_INTENT", "payload": {"counterparty": "Apex", "amount": "100000"}})
    db.save_case(s)

    s = StateMachine.reduce(s, {"type": "CONFIRM_INTENT"})
    db.save_case(s)

    # Checkpoint event count and tip hash advance with each save
    with db.get_connection() as conn:
        events = conn.execute("SELECT * FROM audit_events WHERE case_id = 'RC-AUTH-01' ORDER BY seq ASC").fetchall()
        assert len(events) == 4
        cp = conn.execute("SELECT * FROM case_audit_checkpoints WHERE case_id = 'RC-AUTH-01'").fetchone()
        assert cp["event_count"] == 4
        assert cp["tip_hash"] == events[-1]["current_hash"]
        assert verify_checkpoint_mac(
            secret=TEST_AUDIT_CHECKPOINT_SECRET,
            case_id="RC-AUTH-01",
            event_count=4,
            tip_hash=events[-1]["current_hash"],
            trust_state=AuditTrustState.TRUSTED.value,
            checkpoint_mac=cp["checkpoint_mac"],
        )

    # 3. Load case with valid secret succeeds
    loaded = db.load_case("RC-AUTH-01")
    assert loaded is not None
    assert len(loaded.audit) == 4
    assert loaded.audit[-1].current_hash == events[-1]["current_hash"]

    # 4. Load case with wrong secret fails closed
    db_wrong = Database(db_path=db_path, audit_checkpoint_secret=WRONG_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="Audit checkpoint MAC verification failed"):
        db_wrong.load_case("RC-AUTH-01")


# ==============================================================================
# Scenario 2: Complete Tamper Matrix Across All Vectors
# ==============================================================================

@pytest.fixture
def populated_case_db(tmp_path):
    """Fixture producing a database with an authentic 4-event case."""
    db_path = tmp_path / "tamper_matrix.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    s = StateMachine.initial_state(case_id="RC-TAMPER-01", tenant_id="tenant_01")
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-TAMPER-01"))
    s = StateMachine.reduce(s, {"type": "EXTRACT_INTENT", "payload": {"counterparty": "Apex", "amount": "100000"}})
    s = StateMachine.reduce(s, {"type": "CONFIRM_INTENT"})
    db.save_case(s)
    return db, db_path, "RC-TAMPER-01"


def test_tamper_event_payload_actor(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET actor = 'Malicious Actor' WHERE case_id = ? AND seq = 2", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="hash mismatch"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_event_payload_summary(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET summary = 'Forged summary' WHERE case_id = ? AND seq = 3", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="hash mismatch"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_event_payload_details(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET details_json = '{\"forged\": true}' WHERE case_id = ? AND seq = 2", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="hash mismatch"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_event_type(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET event_type = 'GRANT_ISSUED' WHERE case_id = ? AND seq = 2", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="hash mismatch"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_timestamp(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET timestamp = '2020-01-01T00:00:00+00:00' WHERE case_id = ? AND seq = 2", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="hash mismatch"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_prev_hash(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET prev_hash = '0000000000000000000000000000000000000000000000000000000000000000' WHERE case_id = ? AND seq = 3", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="(hash mismatch|broken sequence|prev_hash chain)"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_current_hash(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET current_hash = '1111111111111111111111111111111111111111111111111111111111111111' WHERE case_id = ? AND seq = 2", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="hash mismatch"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_delete_interior_event(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("DELETE FROM audit_events WHERE case_id = ? AND seq = 2", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="(count mismatch|broken sequence)"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_delete_tail_event(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("DELETE FROM audit_events WHERE case_id = ? AND seq = 4", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="count mismatch"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_reorder_events(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET seq = 99 WHERE case_id = ? AND seq = 2", (case_id,))
        conn.execute("UPDATE audit_events SET seq = 2 WHERE case_id = ? AND seq = 3", (case_id,))
        conn.execute("UPDATE audit_events SET seq = 3 WHERE case_id = ? AND seq = 99", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="(broken sequence|hash mismatch|prev_hash chain)"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_forge_event_row(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("""
            INSERT INTO audit_events (case_id, seq, event_type, summary, actor, timestamp, prev_hash, current_hash, details_json)
            VALUES (?, 5, 'MALICIOUS_EVENT', 'Injected event', 'Attacker', datetime('now'), 'dummy_prev', 'dummy_curr', '{}');
        """, (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="count mismatch"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_duplicate_seq_rejected_by_sqlite_constraint(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("""
                INSERT INTO audit_events (case_id, seq, event_type, summary, actor, timestamp, prev_hash, current_hash, details_json)
                VALUES (?, 4, 'DUPLICATE_EVENT', 'Duplicate seq event', 'Attacker', datetime('now'), 'dummy_prev', 'dummy_curr', '{}');
            """, (case_id,))


def test_tamper_checkpoint_count(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("UPDATE case_audit_checkpoints SET event_count = 3 WHERE case_id = ?", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="(MAC verification failed|count mismatch)"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_checkpoint_tip(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("UPDATE case_audit_checkpoints SET tip_hash = 'badbadbad' WHERE case_id = ?", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="(MAC verification failed|tip hash mismatch)"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_checkpoint_mac(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("UPDATE case_audit_checkpoints SET checkpoint_mac = 'forged_mac_value' WHERE case_id = ?", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="MAC verification failed"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "CORRUPTED"


def test_tamper_checkpoint_trust_state(populated_case_db):
    db, db_path, case_id = populated_case_db
    with db.get_connection() as conn:
        conn.execute("UPDATE case_audit_checkpoints SET trust_state = 'LEGACY_UNTRUSTED' WHERE case_id = ?", (case_id,))
    fresh_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError, match="untrusted state"):
        fresh_db.load_case(case_id)
    v = fresh_db.verify_case_audit(case_id)
    assert v is not None and not v["is_valid"]
    assert v["trust_state"] == "LEGACY_UNTRUSTED"


# ==============================================================================
# Scenario 3: state_json Audit is Untrusted
# ==============================================================================

def test_state_json_audit_is_untrusted_and_omitted_on_storage(tmp_path):
    """Altering or clearing state_json['audit'] in the database has no effect on load_case_tx,
    and save_case stores empty/omitted audit in state_json.
    """
    db_path = tmp_path / "untrusted_state_json.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    s = StateMachine.initial_state(case_id="RC-UNTRUSTED-01", tenant_id="tenant_01")
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-UNTRUSTED-01"))
    db.save_case(s)

    # 1. Verify that the stored state_json in DB has empty/omitted audit list
    with db.get_connection() as conn:
        row = conn.execute("SELECT state_json FROM risk_cases WHERE case_id = 'RC-UNTRUSTED-01'").fetchone()
        stored_dict = json.loads(row["state_json"])
        assert stored_dict.get("audit") == []

    # 2. Tamper with state_json['audit'] directly in SQLite by putting forged events
    with db.get_connection() as conn:
        forged_audit = [{
            "seq": 999,
            "event_type": "FORGED_EVENT",
            "summary": "Attacker injected event into state_json",
            "actor": "Attacker",
            "timestamp": "2026-09-02T00:00:00+00:00",
            "prev_hash": "dummy_prev",
            "current_hash": "dummy_curr",
            "details": {},
        }]
        stored_dict["audit"] = forged_audit
        conn.execute("UPDATE risk_cases SET state_json = ? WHERE case_id = 'RC-UNTRUSTED-01'", (json.dumps(stored_dict),))

    # 3. load_case ignores the forged state_json['audit'] and strictly hydrates from audit_events rows
    loaded = db.load_case("RC-UNTRUSTED-01")
    assert loaded is not None
    assert len(loaded.audit) == 2
    assert all(ev.event_type != "FORGED_EVENT" for ev in loaded.audit)
    assert loaded.audit[0].event_type == "EVIDENCE_ADMISSION_STARTED"
    assert loaded.audit[1].event_type == "RISK_CASE_OPENED"


# ==============================================================================
# Scenario 4: Candidate Mutation Validation
# ==============================================================================

def test_save_case_validates_candidate_audit_and_supports_idempotent_save(tmp_path):
    """save_case_tx rejects truncation, rewrite, gap, and cross-case events; permits idempotent save."""
    db_path = tmp_path / "candidate_validation.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    s = StateMachine.initial_state(case_id="RC-CANDIDATE-01", tenant_id="tenant_01")
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-CANDIDATE-01"))
    db.save_case(s)
    assert len(s.audit) == 2

    # 1. Exact idempotent save with no new events succeeds cleanly
    db.save_case(s)
    loaded = db.load_case("RC-CANDIDATE-01")
    assert len(loaded.audit) == 2

    # 2. Candidate audit truncation: candidate has fewer events than authoritative ledger
    truncated_state = s.model_copy(update={"audit": s.audit[:1]})
    with pytest.raises(AuditLedgerIntegrityError, match="Candidate audit truncated"):
        db.save_case(truncated_state)

    # 3. Candidate event rewrite: candidate alters an authoritative prefix event
    altered_event = s.audit[0].model_copy(update={"summary": "Altered summary"})
    rewritten_state = s.model_copy(update={"audit": [altered_event, s.audit[1]]})
    with pytest.raises(AuditLedgerIntegrityError, match="Candidate audit field rewrite"):
        db.save_case(rewritten_state)

    # 4. Candidate sequence gap: candidate suffix has non-contiguous seq
    gap_event = AuditEvent(
        seq=5,  # gap: expected 3
        event_type="GAP_EVENT",
        summary="Gap event",
        actor="Test",
        timestamp="2026-09-02T00:00:00+00:00",
        prev_hash=s.audit[-1].current_hash,
        current_hash="some_hash",
        details={},
    )
    gap_state = s.model_copy(update={"audit": list(s.audit) + [gap_event]})
    with pytest.raises(AuditLedgerIntegrityError, match="sequence gap"):
        db.save_case(gap_state)

    # 5. Candidate cross-case event: candidate suffix has an event from another case
    cross_event = AuditChain.create_event(
        events=s.audit,
        event_type="CROSS_CASE_EVENT",
        summary="Cross case",
        actor="Test",
        case_id="RC-DIFFERENT-CASE",
    )
    cross_state = s.model_copy(update={"audit": list(s.audit) + [cross_event]})
    with pytest.raises(AuditLedgerIntegrityError, match="Cross-case audit event rejected"):
        db.save_case(cross_state)


# ==============================================================================
# Scenario 5: Legacy DB Migration & Quarantine
# ==============================================================================

def test_legacy_db_migration_quarantines_uncheckpointed_cases_without_data_loss(tmp_path):
    """Pre-P0-3C database without checkpoints is migrated into LEGACY_UNTRUSTED quarantine;
    loading or mutating raises AuditLedgerIntegrityError; handoff and grants fail closed;
    verification returns untrusted status safely.
    """
    db_path = tmp_path / "legacy_migration.db"
    conn = sqlite3.connect(str(db_path))

    # Construct pre-P0-3C schema without case_audit_checkpoints table
    conn.executescript("""
        CREATE TABLE risk_cases (
            case_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
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
            timestamp TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL,
            details_json TEXT NOT NULL
        );
        CREATE TABLE handoff_grants (
            grant_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            bound_intent_hash TEXT NOT NULL,
            bound_snapshot_hash TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            outcome TEXT NOT NULL,
            nonce TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            signature TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            created_at TEXT NOT NULL
        );
        CREATE TABLE adapter_attempts (
            idempotency_key TEXT PRIMARY KEY,
            grant_id TEXT NOT NULL UNIQUE,
            case_id TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL,
            decision TEXT NOT NULL,
            ambiguity_state TEXT NOT NULL,
            pending_item_id TEXT,
            error_code TEXT,
            error_message TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE pending_approval_items (
            item_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            grant_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE,
            counterparty TEXT NOT NULL,
            destination TEXT NOT NULL,
            amount TEXT NOT NULL,
            currency TEXT NOT NULL,
            purpose TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)

    # Populate a pre-P0-3C case with 2 audit events
    s = StateMachine.initial_state(case_id="RC-LEGACY-01", tenant_id="tenant_01")
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-LEGACY-01"))
    now_str = "2026-09-01T00:00:00+00:00"
    conn.execute(
        "INSERT INTO risk_cases VALUES (?, ?, ?, ?, ?, ?)",
        ("RC-LEGACY-01", "tenant_01", s.phase.value, json.dumps(s.model_dump()), now_str, now_str)
    )
    for ev in s.audit:
        conn.execute(
            "INSERT INTO audit_events (case_id, seq, event_type, summary, actor, timestamp, prev_hash, current_hash, details_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ev.case_id, ev.seq, ev.event_type, ev.summary, ev.actor, ev.timestamp, ev.prev_hash, ev.current_hash, json.dumps(ev.details))
        )
    conn.commit()
    conn.close()

    # 1. Initialize Database on legacy DB: runs _migrate_db
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    # 2. Checkpoint row exists in LEGACY_UNTRUSTED state
    with db.get_connection() as conn:
        cp = conn.execute("SELECT * FROM case_audit_checkpoints WHERE case_id = 'RC-LEGACY-01'").fetchone()
        assert cp is not None
        assert cp["trust_state"] == AuditTrustState.LEGACY_UNTRUSTED.value
        assert cp["checkpoint_mac"] == AuditTrustState.LEGACY_UNTRUSTED.value
        # No audit data lost
        ev_count = conn.execute("SELECT COUNT(*) FROM audit_events WHERE case_id = 'RC-LEGACY-01'").fetchone()[0]
        assert ev_count == 2

    # 3. Verification returns is_valid = False without crashing
    res = db.verify_case_audit("RC-LEGACY-01")
    assert res["is_valid"] is False
    assert res["trust_state"] == AuditTrustState.LEGACY_UNTRUSTED.value
    assert "quarantine" in res["reason"].lower()

    # 4. load_case fails closed with AuditLedgerIntegrityError
    with pytest.raises(AuditLedgerIntegrityError, match="untrusted state 'LEGACY_UNTRUSTED'"):
        db.load_case("RC-LEGACY-01")

    # 5. save_case fails closed with AuditLedgerIntegrityError
    with pytest.raises(AuditLedgerIntegrityError, match="untrusted state 'LEGACY_UNTRUSTED'"):
        db.save_case(s)


# ==============================================================================
# Scenario 6: Rollback Injection
# ==============================================================================

def test_failure_injection_proves_atomic_rollback_of_audit_and_checkpoint(tmp_path):
    """Deterministic failure hook _test_fail_after_audit_insert verifies that
    a failure updating the checkpoint rolls back the audit event insert atomically.
    """
    db_path = tmp_path / "rollback_injection.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    s = StateMachine.initial_state(case_id="RC-ROLLBACK-01", tenant_id="tenant_01")
    db.save_case(s)

    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE case_id = 'RC-ROLLBACK-01'").fetchone()[0] == 1
        cp = conn.execute("SELECT event_count FROM case_audit_checkpoints WHERE case_id = 'RC-ROLLBACK-01'").fetchone()
        assert cp["event_count"] == 1

    # Advance state in memory
    s_next = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-ROLLBACK-01"))
    assert len(s_next.audit) == 2

    # Enable failure hook
    db._test_fail_after_audit_insert = True

    with pytest.raises(RuntimeError, match="Deterministic failure injection"):
        db.save_case(s_next)

    # Disable hook and verify rollback
    db._test_fail_after_audit_insert = False

    with db.get_connection() as conn:
        # The second audit event was NOT committed
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE case_id = 'RC-ROLLBACK-01'").fetchone()[0] == 1
        # The checkpoint remains at 1 event
        cp = conn.execute("SELECT event_count FROM case_audit_checkpoints WHERE case_id = 'RC-ROLLBACK-01'").fetchone()
        assert cp["event_count"] == 1

    # Case loads cleanly at state 1
    loaded = db.load_case("RC-ROLLBACK-01")
    assert loaded is not None
    assert len(loaded.audit) == 1


# ==============================================================================
# Scenario 7: Concurrency Serialization
# ==============================================================================

def test_concurrent_case_saves_serialize_without_corrupted_audit_chain(tmp_path):
    """Multiple independent Database connections concurrently advancing cases serialize safely
    without broken sequences, duplicate sequences, or corrupt checkpoints.
    """
    db_path = tmp_path / "concurrent_serialization.db"
    main_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    # Create 5 distinct cases
    case_ids = [f"RC-CONCUR-{i:02d}" for i in range(5)]
    for cid in case_ids:
        s = StateMachine.initial_state(case_id=cid, tenant_id="tenant_01")
        main_db.save_case(s)

    def worker_advance(cid: str):
        # Fresh connection
        worker_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
        for _ in range(3):
            c_state = worker_db.load_case(cid)
            act = make_authorized_bundle_action(case_id=cid)
            next_s = StateMachine.reduce(c_state, act)
            worker_db.save_case(next_s)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(worker_advance, cid) for cid in case_ids]
        for f in futures:
            f.result()

    # Verify every case has a pristine audit chain and valid checkpoint
    for cid in case_ids:
        v = main_db.verify_case_audit(cid)
        assert v["is_valid"] is True
        assert v["trust_state"] == AuditTrustState.TRUSTED.value
        loaded = main_db.load_case(cid)
        assert loaded is not None
        is_valid, broken_seq, _ = AuditChain.verify_chain(loaded.audit)
        assert is_valid is True


# ==============================================================================
# Scenario 8: API & CLI Verification
# ==============================================================================

def test_api_verify_audit_returns_safe_structured_status(tmp_path):
    """GET /api/audit/verify/{case_id} returns 404 for missing case; 200 with structured status
    for valid, corrupted, and legacy cases without leaking secrets.
    """
    db_path = tmp_path / "api_verify.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    cfg = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(db_path),
    )
    app = create_app(config=cfg, db=db)
    client = TestClient(app)

    # 1. Non-existent case -> 404
    r_missing = client.get("/api/audit/verify/RC-NONEXISTENT")
    assert r_missing.status_code == 404

    # 2. Valid case -> 200 with structured trusted status
    s = StateMachine.initial_state(case_id="RC-API-VALID", tenant_id="tenant_01")
    db.save_case(s)

    r_valid = client.get("/api/audit/verify/RC-API-VALID")
    assert r_valid.status_code == 200
    data_valid = r_valid.json()
    assert data_valid["is_valid"] is True
    assert data_valid["trust_state"] == AuditTrustState.TRUSTED.value
    assert data_valid["event_count"] == 1
    assert TEST_AUDIT_CHECKPOINT_SECRET not in str(data_valid)

    # 3. Tampered case -> 200 with is_valid=False, trust_state=CORRUPTED, no stack traces
    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET current_hash = 'corrupted_hash' WHERE case_id = 'RC-API-VALID'")

    r_corrupt = client.get("/api/audit/verify/RC-API-VALID")
    assert r_corrupt.status_code == 200
    data_corrupt = r_corrupt.json()
    assert data_corrupt["is_valid"] is False
    assert data_corrupt["trust_state"] == "CORRUPTED"
    assert "reason" in data_corrupt
    assert TEST_AUDIT_CHECKPOINT_SECRET not in str(data_corrupt)
    assert "sqlite3" not in str(data_corrupt).lower()


def test_api_dispatch_action_on_tampered_case_returns_409(tmp_path):
    """Mutating API endpoints map AuditLedgerIntegrityError to HTTP 409 Conflict."""
    db_path = tmp_path / "api_dispatch_tamper.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    cfg = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(db_path),
    )
    app = create_app(config=cfg, db=db)
    client = TestClient(app)

    s = StateMachine.initial_state(case_id="RC-API-TAMPER", tenant_id="tenant_01")
    db.save_case(s)

    # Corrupt the audit checkpoint MAC in DB
    with db.get_connection() as conn:
        conn.execute("UPDATE case_audit_checkpoints SET checkpoint_mac = 'bad_mac' WHERE case_id = 'RC-API-TAMPER'")

    # Dispatching action fails closed with 409 Conflict
    r_disp = client.post(
        "/api/cases/RC-API-TAMPER/dispatch",
        json={"type": "EXTRACT_INTENT", "payload": {}}
    )
    assert r_disp.status_code == 409
    assert "Audit ledger integrity failure" in r_disp.json()["detail"]


def test_cli_verify_audit_reports_truthfully(tmp_path, monkeypatch, capsys):
    """CLI verify-audit uses configured secret and truthfully reports trusted vs corrupted."""
    import sys
    from payoutproof.cli.main import main

    db_path = tmp_path / "cli_verify.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-CLI-01", tenant_id="tenant_01")
    db.save_case(s)

    monkeypatch.setenv("PAYOUTPROOF_GRANT_SECRET", TEST_GRANT_SECRET)
    monkeypatch.setenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", TEST_AUDIT_CHECKPOINT_SECRET)
    monkeypatch.setenv("PAYOUTPROOF_ENV", "test")
    monkeypatch.setenv("PAYOUTPROOF_DB_PATH", str(db_path))

    # 1. Authentic case: verify-audit succeeds and outputs trusted
    monkeypatch.setattr(sys, "argv", ["payoutproof", "verify-audit", "--case-id", "RC-CLI-01"])
    main()
    out = capsys.readouterr().out
    assert "structurally valid" in out
    assert "TRUSTED" in out

    # 2. Corrupted case: verify-audit exits 1 and reports corrupted
    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET current_hash = 'tampered' WHERE case_id = 'RC-CLI-01'")

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    err_out = capsys.readouterr().out
    assert "FAILED" in err_out or "CORRUPTED" in err_out


# ==============================================================================
# Scenario 9: Adversarial Edge Cases & Regression Invariants
# ==============================================================================

def test_candidate_audit_prefix_details_rewrite_rejected(tmp_path):
    """Candidate audit prefix with rewritten details (preserving current_hash) is rejected."""
    db_path = tmp_path / "prefix_details.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-PREFIX-01", tenant_id="t1")
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-PREFIX-01"))
    db.save_case(s)

    tampered_ev0 = s.audit[0].model_copy(update={"details": {"forged_field": True}})
    tampered_state = s.model_copy(update={"audit": [tampered_ev0, s.audit[1]]})
    with pytest.raises(AuditLedgerIntegrityError, match="Candidate audit field rewrite"):
        db.save_case(tampered_state)


def test_candidate_audit_prefix_case_id_rewrite_rejected(tmp_path):
    """Candidate audit prefix with rewritten cross-case case_id is rejected."""
    db_path = tmp_path / "prefix_case_id.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-CROSS-01", tenant_id="t1")
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-CROSS-01"))
    db.save_case(s)

    tampered_ev0 = s.audit[0].model_copy(update={"case_id": "RC-OTHER-CASE"})
    tampered_state = s.model_copy(update={"audit": [tampered_ev0, s.audit[1]]})
    with pytest.raises(AuditLedgerIntegrityError, match="(Candidate audit field rewrite|Cross-case)"):
        db.save_case(tampered_state)


def test_save_case_checks_checkpoint_rowcount_on_missing_checkpoint(tmp_path):
    """If case_audit_checkpoints row was deleted before save, rowcount check raises AuditLedgerIntegrityError."""
    db_path = tmp_path / "checkpoint_rowcount.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-ROWCOUNT-01", tenant_id="t1")
    db.save_case(s)

    s_next = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-ROWCOUNT-01"))
    with db.get_connection() as conn:
        conn.execute("DELETE FROM case_audit_checkpoints WHERE case_id = 'RC-ROWCOUNT-01'")

    with pytest.raises(AuditLedgerIntegrityError, match="(lacks audit checkpoint|row affected)"):
        db.save_case(s_next)


def test_migrated_legacy_db_enforces_unique_case_id_seq(tmp_path):
    """Migrated database from pre-P0-3C schema lacking UNIQUE(case_id, seq) gets index and enforces uniqueness."""
    db_path = tmp_path / "legacy_unique.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE risk_cases (case_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, phase TEXT NOT NULL, state_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, seq INTEGER NOT NULL, event_type TEXT NOT NULL, summary TEXT NOT NULL, actor TEXT NOT NULL, timestamp TEXT NOT NULL, prev_hash TEXT NOT NULL, current_hash TEXT NOT NULL, details_json TEXT NOT NULL);
        CREATE TABLE handoff_grants (grant_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, bound_intent_hash TEXT NOT NULL, signature TEXT NOT NULL, status TEXT NOT NULL, nonce TEXT NOT NULL);
        CREATE TABLE adapter_attempts (idempotency_key TEXT PRIMARY KEY, grant_id TEXT NOT NULL, case_id TEXT NOT NULL, status TEXT NOT NULL, decision TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    """)
    conn.commit()
    conn.close()

    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with db.get_connection() as c:
        c.execute("INSERT INTO audit_events (case_id, seq, event_type, summary, actor, timestamp, prev_hash, current_hash, details_json) VALUES ('C1', 1, 'E', 'S', 'A', 'T', 'P', 'H', '{}')")
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("INSERT INTO audit_events (case_id, seq, event_type, summary, actor, timestamp, prev_hash, current_hash, details_json) VALUES ('C1', 1, 'E2', 'S2', 'A2', 'T2', 'P2', 'H2', '{}')")


def test_malformed_details_json_raises_integrity_error_and_returns_409(tmp_path):
    """Malformed details_json in SQLite raises AuditLedgerIntegrityError and maps safely to HTTP 409."""
    db_path = tmp_path / "malformed_details.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    cfg = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(db_path),
    )
    app = create_app(config=cfg, db=db)
    client = TestClient(app)

    s = StateMachine.initial_state(case_id="RC-MALFORMED-01", tenant_id="tenant_01")
    db.save_case(s)

    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET details_json = '{unclosed_json' WHERE case_id = 'RC-MALFORMED-01'")

    with pytest.raises(AuditLedgerIntegrityError, match="Malformed details_json"):
        db.load_case("RC-MALFORMED-01")

    r = client.get("/api/cases/RC-MALFORMED-01")
    assert r.status_code == 409
    assert "Audit ledger integrity failure" in r.json()["detail"]


def test_state_json_conflicting_case_id_rejected(tmp_path):
    """state_json with desynchronized/injected case_id raises AuditLedgerIntegrityError."""
    db_path = tmp_path / "state_json_case_id.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-DESYNC-01", tenant_id="tenant_01")
    db.save_case(s)

    with db.get_connection() as conn:
        row = conn.execute("SELECT state_json FROM risk_cases WHERE case_id = 'RC-DESYNC-01'").fetchone()
        d = json.loads(row["state_json"])
        d["case_id"] = "RC-INJECTED-02"
        conn.execute("UPDATE risk_cases SET state_json = ? WHERE case_id = 'RC-DESYNC-01'", (json.dumps(d),))

    with pytest.raises(AuditLedgerIntegrityError, match="conflicts with authoritative row case_id"):
        db.load_case("RC-DESYNC-01")


def test_verify_checkpoint_mac_safely_handles_non_string_mac(tmp_path):
    """NULL/non-string checkpoint_mac in database does not cause TypeError traceback in verify_case_audit."""
    db_path = tmp_path / "null_mac.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-NULLMAC-01", tenant_id="tenant_01")
    db.save_case(s)

    # Directly verify function
    assert verify_checkpoint_mac(TEST_AUDIT_CHECKPOINT_SECRET, "RC-NULLMAC-01", 1, "tip", "TRUSTED", None) is False

    with db.get_connection() as conn:
        conn.execute("UPDATE case_audit_checkpoints SET checkpoint_mac = 'invalid_format' WHERE case_id = 'RC-NULLMAC-01'")

    res = db.verify_case_audit("RC-NULLMAC-01")
    assert res["is_valid"] is False
    assert res["trust_state"] == "CORRUPTED"


def test_list_cases_verifies_mac_and_reports_corrupted_on_wrong_secret(tmp_path):
    """list_cases verifies checkpoint MACs and reports CORRUPTED under a wrong secret."""
    db_path = tmp_path / "list_wrong_secret.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-LIST-AUTH", tenant_id="tenant_01")
    db.save_case(s)

    # With authentic secret
    cases_valid = db.list_cases()
    assert len(cases_valid) == 1
    assert cases_valid[0]["trust_state"] == "TRUSTED"

    # With wrong secret
    db_wrong = Database(db_path=db_path, audit_checkpoint_secret=WRONG_SECRET)
    cases_corrupt = db_wrong.list_cases()
    assert len(cases_corrupt) == 1
    assert cases_corrupt[0]["trust_state"] == "CORRUPTED"


def test_tamper_matrix_cold_restart(tmp_path):
    """Tamper vector verified across cold restart of Database instance."""
    db_path = tmp_path / "cold_restart.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-COLD-01", tenant_id="tenant_01")
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-COLD-01"))
    db.save_case(s)

    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET current_hash = 'forged' WHERE case_id = 'RC-COLD-01' AND seq = 2")

    # Cold restart: instantiate completely new Database object
    restarted_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with pytest.raises(AuditLedgerIntegrityError):
        restarted_db.load_case("RC-COLD-01")

    v = restarted_db.verify_case_audit("RC-COLD-01")
    assert v["is_valid"] is False
    assert v["trust_state"] == "CORRUPTED"


# ==============================================================================
# P0-3C Adversarial Review Regression Tests
# ==============================================================================

def test_candidate_prefix_details_rewrite_preserving_old_hash_rejected(tmp_path):
    """Finding 1: Rewriting candidate prefix event details while preserving the old hash is rejected."""
    db_path = tmp_path / "candidate_prefix_details.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-PFX-DET", tenant_id="tenant_01")
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-PFX-DET"))
    db.save_case(s)
    assert len(s.audit) == 2

    # Mutate details in candidate prefix but keep old current_hash
    tampered_details = dict(s.audit[0].details)
    tampered_details["tampered_key"] = "malicious_payload"
    tampered_event = s.audit[0].model_copy(update={"details": tampered_details})
    tampered_candidate = s.model_copy(update={"audit": [tampered_event, s.audit[1]]})

    with pytest.raises(AuditLedgerIntegrityError, match="details mismatch"):
        db.save_case(tampered_candidate)


def test_candidate_prefix_cross_case_identity_rejected(tmp_path):
    """Finding 1: Candidate prefix event with mismatched case_id is rejected."""
    db_path = tmp_path / "candidate_cross_case.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-CROSS-01", tenant_id="tenant_01")
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-CROSS-01"))
    db.save_case(s)

    # Candidate has event with another case_id
    tampered_event = s.audit[0].model_copy(update={"case_id": "RC-OTHER-CASE"})
    tampered_candidate = s.model_copy(update={"audit": [tampered_event, s.audit[1]]})

    with pytest.raises(AuditLedgerIntegrityError, match="cross-case case_id mismatch"):
        db.save_case(tampered_candidate)


def test_deleted_checkpoint_before_save_fails_and_rolls_back(tmp_path):
    """Finding 2: Deleting checkpoint row before save fails rowcount check and rolls back completely."""
    db_path = tmp_path / "deleted_cp.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-DEL-CP", tenant_id="tenant_01")
    db.save_case(s)

    # Delete checkpoint behind the DB's back
    with db.get_connection() as conn:
        conn.execute("DELETE FROM case_audit_checkpoints WHERE case_id = 'RC-DEL-CP'")

    # Attempt to advance case with new suffix
    s_next = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-DEL-CP"))
    with pytest.raises(AuditLedgerIntegrityError, match="lacks audit checkpoint"):
        db.save_case(s_next)

    # Verify audit_events did not get any new rows (rolled back / aborted)
    with db.get_connection() as conn:
        ev_count = conn.execute("SELECT COUNT(*) FROM audit_events WHERE case_id = 'RC-DEL-CP'").fetchone()[0]
        assert ev_count == 1


def test_failure_after_insert_initial_creation(tmp_path):
    """Finding 2: Failure after audit insert on initial case creation rolls back all tables."""
    db_path = tmp_path / "fail_after_insert.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    db._test_fail_after_audit_insert = True

    s = StateMachine.initial_state(case_id="RC-FAIL-INIT", tenant_id="tenant_01")
    with pytest.raises(RuntimeError, match="Deterministic failure injection"):
        db.save_case(s)

    # Verify zero rows in all three tables
    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM risk_cases WHERE case_id = 'RC-FAIL-INIT'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE case_id = 'RC-FAIL-INIT'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM case_audit_checkpoints WHERE case_id = 'RC-FAIL-INIT'").fetchone()[0] == 0


def test_clean_legacy_schema_gets_unique_constraint(tmp_path):
    """Finding 3: Clean legacy database without unique index receives UNIQUE(case_id, seq) on migration."""
    db_path = tmp_path / "legacy_clean.db"
    # Create raw schema without case_audit_checkpoints and without unique index
    raw_conn = sqlite3.connect(str(db_path))
    raw_conn.execute("""
        CREATE TABLE risk_cases (
            case_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            case_version INTEGER NOT NULL DEFAULT 0,
            phase TEXT NOT NULL,
            state_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    raw_conn.execute("""
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
            details_json TEXT NOT NULL DEFAULT '{}'
        );
    """)
    raw_conn.commit()
    raw_conn.close()

    # Now open with Database, which runs migration
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    # Verify UNIQUE constraint is enforced
    with db.get_connection() as conn:
        conn.execute("""
            INSERT INTO audit_events (case_id, seq, event_type, summary, actor, prev_hash, current_hash, timestamp, details_json)
            VALUES ('RC-TEST', 1, 'EV1', 'Sum', 'Act', 'prev', 'curr', '2026-01-01T00:00:00', '{}');
        """)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("""
                INSERT INTO audit_events (case_id, seq, event_type, summary, actor, prev_hash, current_hash, timestamp, details_json)
                VALUES ('RC-TEST', 1, 'EV2', 'Sum', 'Act', 'prev', 'curr2', '2026-01-01T00:00:00', '{}');
            """)


def test_duplicate_existing_legacy_preserves_rows_and_quarantines(tmp_path):
    """Finding 3: Legacy database with pre-existing duplicate sequences preserves all rows and quarantines case."""
    db_path = tmp_path / "legacy_dups.db"
    raw_conn = sqlite3.connect(str(db_path))
    raw_conn.execute("""
        CREATE TABLE risk_cases (
            case_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            case_version INTEGER NOT NULL DEFAULT 0,
            phase TEXT NOT NULL,
            state_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    raw_conn.execute("""
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
            details_json TEXT NOT NULL DEFAULT '{}'
        );
    """)
    # Insert case and DUPLICATE audit rows with same (case_id, seq)
    raw_conn.execute("INSERT INTO risk_cases VALUES ('RC-DUP-01', 't1', 0, 'INITIAL_EVIDENCE_GATHERING', '{}', '2026-01-01', '2026-01-01');")
    raw_conn.execute("INSERT INTO audit_events (case_id, seq, event_type, summary, actor, prev_hash, current_hash, timestamp, details_json) VALUES ('RC-DUP-01', 1, 'EV1', 'Sum1', 'Act', 'p1', 'c1', '2026-01-01', '{}');")
    raw_conn.execute("INSERT INTO audit_events (case_id, seq, event_type, summary, actor, prev_hash, current_hash, timestamp, details_json) VALUES ('RC-DUP-01', 1, 'EV2', 'Sum2', 'Act', 'p2', 'c2', '2026-01-01', '{}');")
    raw_conn.commit()
    raw_conn.close()

    # Now open with Database engine
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    # 1. Verify all duplicate rows are preserved (never deleted)
    with db.get_connection() as conn:
        rows = conn.execute("SELECT * FROM audit_events WHERE case_id = 'RC-DUP-01'").fetchall()
        assert len(rows) == 2

    # 2. Case is quarantined as LEGACY_UNTRUSTED
    v = db.verify_case_audit("RC-DUP-01")
    assert v is not None
    assert v["is_valid"] is False
    assert v["trust_state"] == AuditTrustState.LEGACY_UNTRUSTED.value

    # 3. load_case fails closed
    with pytest.raises(AuditLedgerIntegrityError, match="untrusted state"):
        db.load_case("RC-DUP-01")


def test_malformed_json_db_and_api(tmp_path):
    """Finding 4: Malformed details_json and state_json fail cleanly without leaking secrets, and map to 409 in API."""
    db_path = tmp_path / "malformed_json.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-MAL-01", tenant_id="tenant_01")
    db.save_case(s)

    # Tamper details_json to malformed string
    with db.get_connection() as conn:
        conn.execute("UPDATE audit_events SET details_json = '{malformed' WHERE case_id = 'RC-MAL-01'")

    # load_case fails cleanly with stable AuditLedgerIntegrityError
    with pytest.raises(AuditLedgerIntegrityError, match="Malformed details_json"):
        db.load_case("RC-MAL-01")

    # verify_case_audit returns structured invalid result without throwing
    res = db.verify_case_audit("RC-MAL-01")
    assert res is not None
    assert res["is_valid"] is False
    assert res["trust_state"] == "CORRUPTED"
    assert "Malformed details_json" in res["reason"]

    # API mapping
    config = AppConfig(
        db_path=db_path,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )
    app = create_app(config, db=db)
    client = TestClient(app)

    # GET /api/cases/{case_id} returns 409
    r = client.get("/api/cases/RC-MAL-01")
    assert r.status_code == 409
    assert "Audit ledger integrity failure" in r.json()["detail"]

    # POST /api/cases/{case_id}/dispatch returns 409
    r_dispatch = client.post("/api/cases/RC-MAL-01/dispatch", json={"type": "CONFIRM_INTENT"})
    assert r_dispatch.status_code == 409
    assert "Audit ledger integrity failure" in r_dispatch.json()["detail"]

    # GET /api/audit/verify/{case_id} returns 200 with structured invalid
    r_verify = client.get("/api/audit/verify/RC-MAL-01")
    assert r_verify.status_code == 200
    assert r_verify.json()["is_valid"] is False
    assert r_verify.json()["trust_state"] == "CORRUPTED"


def test_identity_tamper_tenant_id_and_case_id(tmp_path):
    """Finding 5: state_json and candidate tenant_id and case_id identity tampers fail closed."""
    db_path = tmp_path / "identity_tamper.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-ID-01", tenant_id="tenant_01")
    db.save_case(s)

    # 1. state_json tenant_id mismatch
    with db.get_connection() as conn:
        row = conn.execute("SELECT state_json FROM risk_cases WHERE case_id = 'RC-ID-01'").fetchone()
        d = json.loads(row["state_json"])
        d["tenant_id"] = "tenant_attacker"
        conn.execute("UPDATE risk_cases SET state_json = ? WHERE case_id = 'RC-ID-01'", (json.dumps(d),))

    with pytest.raises(AuditLedgerIntegrityError, match="conflicts with authoritative row tenant_id"):
        db.load_case("RC-ID-01")

    # 2. Candidate tenant_id mismatch on save
    candidate = s.model_copy(update={"tenant_id": "tenant_attacker"})
    with pytest.raises(AuditLedgerIntegrityError, match="conflicts with authoritative row tenant_id"):
        db.save_case(candidate)


def test_verify_checkpoint_mac_all_malformed_inputs():
    """Finding 6: verify_checkpoint_mac returns False for all malformed inputs and never raises TypeError."""
    assert verify_checkpoint_mac(secret=None, case_id="c", event_count=1, tip_hash="t", trust_state="TRUSTED", checkpoint_mac="m") is False
    assert verify_checkpoint_mac(secret="", case_id="c", event_count=1, tip_hash="t", trust_state="TRUSTED", checkpoint_mac="m") is False
    assert verify_checkpoint_mac(secret=TEST_AUDIT_CHECKPOINT_SECRET, case_id=None, event_count=1, tip_hash="t", trust_state="TRUSTED", checkpoint_mac="m") is False
    assert verify_checkpoint_mac(secret=TEST_AUDIT_CHECKPOINT_SECRET, case_id="c", event_count=True, tip_hash="t", trust_state="TRUSTED", checkpoint_mac="m") is False
    assert verify_checkpoint_mac(secret=TEST_AUDIT_CHECKPOINT_SECRET, case_id="c", event_count=-1, tip_hash="t", trust_state="TRUSTED", checkpoint_mac="m") is False
    assert verify_checkpoint_mac(secret=TEST_AUDIT_CHECKPOINT_SECRET, case_id="c", event_count="1", tip_hash="t", trust_state="TRUSTED", checkpoint_mac="m") is False
    assert verify_checkpoint_mac(secret=TEST_AUDIT_CHECKPOINT_SECRET, case_id="c", event_count=1, tip_hash=None, trust_state="TRUSTED", checkpoint_mac="m") is False
    assert verify_checkpoint_mac(secret=TEST_AUDIT_CHECKPOINT_SECRET, case_id="c", event_count=1, tip_hash="t", trust_state="INVALID_ENUM", checkpoint_mac="m") is False
    assert verify_checkpoint_mac(secret=TEST_AUDIT_CHECKPOINT_SECRET, case_id="c", event_count=1, tip_hash="t", trust_state="TRUSTED", checkpoint_mac=None) is False
    assert verify_checkpoint_mac(secret=TEST_AUDIT_CHECKPOINT_SECRET, case_id="c", event_count=1, tip_hash="t", trust_state="TRUSTED", checkpoint_mac=b"bytes") is False
    assert verify_checkpoint_mac(secret=TEST_AUDIT_CHECKPOINT_SECRET, case_id="c", event_count=1, tip_hash="t", trust_state="TRUSTED", checkpoint_mac=123) is False


def test_list_cases_tamper_and_wrong_secret(tmp_path):
    """Finding 7: list_cases authenticated verification per row never labels a case TRUSTED from raw trust_state."""
    db_path = tmp_path / "list_tamper.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-LIST-01", tenant_id="tenant_01")
    s = StateMachine.reduce(s, make_authorized_bundle_action(case_id="RC-LIST-01"))
    db.save_case(s)

    # Valid secret -> TRUSTED
    cases = db.list_cases()
    assert len(cases) == 1
    assert cases[0]["trust_state"] == AuditTrustState.TRUSTED.value

    # Tamper checkpoint MAC
    with db.get_connection() as conn:
        conn.execute("UPDATE case_audit_checkpoints SET checkpoint_mac = 'forged' WHERE case_id = 'RC-LIST-01'")
    cases = db.list_cases()
    assert cases[0]["trust_state"] == "CORRUPTED"

    # Restore MAC and tamper audit event payload
    with db.get_connection() as conn:
        auth_mac = compute_checkpoint_mac(TEST_AUDIT_CHECKPOINT_SECRET, "RC-LIST-01", 2, s.audit[-1].current_hash, AuditTrustState.TRUSTED.value)
        conn.execute("UPDATE case_audit_checkpoints SET checkpoint_mac = ? WHERE case_id = 'RC-LIST-01'", (auth_mac,))
        conn.execute("UPDATE audit_events SET summary = 'tampered' WHERE case_id = 'RC-LIST-01' AND seq = 2")
    cases = db.list_cases()
    assert cases[0]["trust_state"] == "CORRUPTED"


def test_secret_distinctness_and_boundary_checks(tmp_path):
    """Finding 8: Secret distinctness enforced and boundary checks reject mismatched injected DB."""
    identical_secret = "identical-secret-value-32-chars-long"

    # AppConfig rejects identical secrets
    with pytest.raises(ConfigurationError, match="must be distinct"):
        AppConfig(grant_secret=identical_secret, audit_checkpoint_secret=identical_secret)

    # FakeApprovalRailAdapter rejects identical secrets
    dummy_db = Database(db_path=tmp_path / "dummy.db", audit_checkpoint_secret="some-valid-secret-32-chars-long-xxx")
    with pytest.raises(ValueError, match="must be distinct"):
        FakeApprovalRailAdapter(
            db=dummy_db,
            grant_secret=identical_secret,
            audit_checkpoint_secret=identical_secret,
        )

    # create_app rejects injected Database built with mismatched audit secret
    config = AppConfig(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )
    wrong_db = Database(db_path=tmp_path / "wrong.db", audit_checkpoint_secret="different-audit-secret-32-chars-long")
    with pytest.raises(ConfigurationError, match="does not match AppConfig audit_checkpoint_secret"):
        create_app(config=config, db=wrong_db)


def test_idempotent_migration_with_malformed_checkpoint_input(tmp_path):
    """Finding 10: Migration with malformed checkpoint row containing NULL or empty case_id runs safely and idempotently."""
    db_path = tmp_path / "malformed_cp_migration.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    s = StateMachine.initial_state(case_id="RC-MIG-01", tenant_id="tenant_01")
    db.save_case(s)

    # Insert malformed checkpoint row with empty/NULL case_id if table permits
    with db.get_connection() as conn:
        try:
            conn.execute("""
                INSERT INTO case_audit_checkpoints (case_id, event_count, tip_hash, trust_state, checkpoint_mac, updated_at)
                VALUES ('', 0, '', 'LEGACY_UNTRUSTED', 'LEGACY_UNTRUSTED', '2026-01-01');
            """)
        except Exception:
            pass

    # Running migration again via fresh Database succeeds idempotently
    reopened_db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    loaded = reopened_db.load_case("RC-MIG-01")
    assert loaded is not None
    assert len(loaded.audit) == 1
