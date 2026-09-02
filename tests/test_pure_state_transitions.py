"""Tests for state machine transitions, mutation invalidation, and full lifecycle."""

import pytest
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.core.enums import CasePhase, PolicyOutcome, IntentStatus, GrantStatus, HandoffStatus, DestinationStatus
from payoutproof.audit.chain import AuditChain


def test_full_happy_path_walkthrough():
    s = StateMachine.initial_state(case_id="RC-TEST-HP")
    assert s.phase == CasePhase.EVIDENCE_ADMISSION

    # 1. Admit authorized bundle
    s = StateMachine.reduce(s, {"type": "ADMIT_AUTHORIZED_BUNDLE", "payload": {"case_id": "RC-TEST-HP"}})
    assert s.phase == CasePhase.INVESTIGATION
    assert s.case_version == 1

    # 2. Extract intent
    s = StateMachine.reduce(s, {"type": "EXTRACT_INTENT", "payload": {"counterparty": "Kaveri Components", "destination": "HDFC ••4821", "amount": "425000"}})
    assert s.intent.status == IntentStatus.EXTRACTED

    # 3. Confirm intent
    s = StateMachine.reduce(s, {"type": "CONFIRM_INTENT"})
    assert s.intent.status == IntentStatus.CONFIRMED
    assert s.intent.intent_hash is not None

    # 4. Add callback
    s = StateMachine.reduce(s, {"type": "ADD_CALLBACK_EVIDENCE"})

    # 5. Add destination approval
    s = StateMachine.reduce(s, {"type": "ADD_DESTINATION_APPROVAL"})

    # 6. Evaluate policy
    s = StateMachine.reduce(s, {"type": "EVALUATE_POLICY"})
    assert s.policy.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
    assert s.phase == CasePhase.READY_FOR_HUMAN_HANDOFF

    # 7. Issue grant
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"})
    assert s.grant is not None
    assert s.grant.status == GrantStatus.ACTIVE

    # 8. Operator initiates handoff
    s = StateMachine.reduce(s, {"type": "INITIATE_HANDOFF"})
    assert s.phase == CasePhase.HANDOFF_IN_PROGRESS

    # 9. Adapter accepts handoff
    s = StateMachine.reduce(s, {"type": "HANDOFF_ACCEPTED", "payload": {"pending_item_id": "RAIL-001"}})
    assert s.phase == CasePhase.COMPLETE
    assert s.grant.status == GrantStatus.CONSUMED
    assert s.handoff.status == HandoffStatus.PENDING_IN_APPROVAL_RAIL

    # Verify audit chain integrity
    is_valid, broken_seq, _ = AuditChain.verify_chain(s.audit)
    assert is_valid


def test_material_edit_invalidates_evaluation_and_grant():
    s = StateMachine.initial_state(case_id="RC-TEST-MUT")
    s = StateMachine.reduce(s, {"type": "ADMIT_AUTHORIZED_BUNDLE"})
    s = StateMachine.reduce(s, {"type": "EXTRACT_INTENT"})
    s = StateMachine.reduce(s, {"type": "CONFIRM_INTENT"})
    s = StateMachine.reduce(s, {"type": "ADD_CALLBACK_EVIDENCE"})
    s = StateMachine.reduce(s, {"type": "ADD_DESTINATION_APPROVAL"})
    s = StateMachine.reduce(s, {"type": "EVALUATE_POLICY"})
    s = StateMachine.reduce(s, {"type": "ISSUE_GRANT"})

    assert s.policy.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
    assert s.grant.status == GrantStatus.ACTIVE

    # Material edit amount to ₹4,75,000
    s = StateMachine.reduce(s, {"type": "EDIT_AMOUNT", "payload": {"amount": "475000"}})

    assert s.intent.status == IntentStatus.INVALIDATED
    assert s.grant.status == GrantStatus.INVALIDATED
    assert s.policy.outcome == PolicyOutcome.HOLD
    assert s.phase == CasePhase.OPERATOR_INTERVENTION

    # Trying to initiate handoff with invalidated grant must be refused
    s_refused = StateMachine.reduce(s, {"type": "INITIATE_HANDOFF"})
    assert "Refused" in s_refused.last_change
    assert s_refused.handoff.status == HandoffStatus.NOT_STARTED
