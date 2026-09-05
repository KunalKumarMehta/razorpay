"""Tests for tamper-evident audit hash chain integrity and tamper detection."""

import pytest
from payoutproof.core.models import AuditEvent
from payoutproof.audit.chain import AuditChain, GENESIS_HASH


def test_audit_chain_creation_and_verification():
    events = []
    e1 = AuditChain.create_event(events, "ADMISSION_STARTED", "Evidence submitted", "Operator", "RC-001")
    events.append(e1)
    e2 = AuditChain.create_event(events, "INTENT_EXTRACTED", "Intent extracted", "Trust Agent", "RC-001")
    events.append(e2)
    e3 = AuditChain.create_event(events, "INTENT_CONFIRMED", "Intent confirmed", "Operator", "RC-001")
    events.append(e3)

    assert len(events) == 3
    assert events[0].prev_hash == GENESIS_HASH
    assert events[1].prev_hash == events[0].current_hash
    assert events[2].prev_hash == events[1].current_hash

    is_valid, broken_seq, reason = AuditChain.verify_chain(events)
    assert is_valid
    assert broken_seq is None


def test_tamper_detection_in_audit_chain():
    events = []
    e1 = AuditChain.create_event(events, "EVENT_1", "Summary 1", "Actor 1", "RC-001")
    events.append(e1)
    e2 = AuditChain.create_event(events, "EVENT_2", "Summary 2", "Actor 2", "RC-001")
    events.append(e2)

    # Tamper with event 1 summary
    tampered_e1 = e1.model_copy(update={"summary": "Tampered summary"})
    tampered_chain = [tampered_e1, e2]

    is_valid, broken_seq, reason = AuditChain.verify_chain(tampered_chain)
    assert not is_valid
    assert broken_seq == 1
    assert "Tampered event" in reason
