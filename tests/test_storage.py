"""Tests for SQLite WAL persistence and case reloading."""

import pytest
import tempfile
from pathlib import Path
from payoutproof.storage.db import Database
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.core.enums import CasePhase, IntentStatus, GrantStatus


def test_sqlite_persistence_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_payoutproof.db"
        db = Database(db_path=db_path)

        # Create and step a case
        s = StateMachine.initial_state(case_id="RC-STORE-01")
        s = StateMachine.reduce(s, {"type": "ADMIT_AUTHORIZED_BUNDLE", "payload": {"case_id": "RC-STORE-01"}})
        s = StateMachine.reduce(s, {"type": "EXTRACT_INTENT", "payload": {"counterparty": "Apex Tech", "destination": "HDFC ••5544", "amount": "300000"}})
        s = StateMachine.reduce(s, {"type": "CONFIRM_INTENT"})
        s = StateMachine.reduce(s, {"type": "ADD_CALLBACK_EVIDENCE"})
        s = StateMachine.reduce(s, {"type": "ADD_DESTINATION_APPROVAL"})
        s = StateMachine.reduce(s, {"type": "EVALUATE_POLICY"})
        s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"})

        # Save to SQLite
        db.save_case(s)

        # Reload from SQLite
        reloaded = db.load_case("RC-STORE-01")
        assert reloaded is not None
        assert reloaded.case_id == "RC-STORE-01"
        assert reloaded.case_version == s.case_version
        assert reloaded.intent.counterparty == "Apex Tech"
        assert reloaded.intent.status == IntentStatus.CONFIRMED
        assert reloaded.grant is not None
        assert reloaded.grant.status == GrantStatus.ACTIVE
        assert len(reloaded.audit) == len(s.audit)

        # Check list cases
        cases = db.list_cases()
        assert len(cases) == 1
        assert cases[0]["case_id"] == "RC-STORE-01"
