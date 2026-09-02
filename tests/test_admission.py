"""Tests for evidence admission and Processing Authority Record validation."""

import pytest
from payoutproof.core.models import ProcessingAuthorityRecord
from payoutproof.admission.validator import AdmissionValidator
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.core.enums import CasePhase, ProcessingAuthorityStatus


def test_missing_authority_fails_admission():
    valid, err = AdmissionValidator.validate_authority(None)
    assert not valid
    assert "Missing" in err


def test_incomplete_authority_fields_fail():
    incomplete = ProcessingAuthorityRecord(
        data_class="VOICE_NOTE",
        source="WhatsApp",
        subject_category="VENDOR",
        submitter="",  # Missing submitter
        purpose="Payment investigation",
        asserted_authority_ref="POL-2026",
    )
    valid, err = AdmissionValidator.validate_authority(incomplete)
    assert not valid
    assert "Submitter" in err


def test_valid_authority_succeeds():
    authority = ProcessingAuthorityRecord(
        data_class="VOICE_NOTE",
        source="WhatsApp",
        subject_category="VENDOR",
        submitter="Payment Operator",
        purpose="Payment intent verification",
        asserted_authority_ref="FIN-AUTH-2026-09",
    )
    valid, err = AdmissionValidator.validate_authority(authority)
    assert valid
    assert err is None


def test_admission_rejection_opens_no_risk_case():
    s0 = StateMachine.initial_state()
    s1 = StateMachine.reduce(s0, {"type": "SUBMIT_UNAUTHORIZED_BUNDLE"})

    assert s1.phase == CasePhase.ADMISSION_REJECTED
    assert s1.processing_authority == ProcessingAuthorityStatus.INCOMPLETE
    assert s1.case_id is None
    assert s1.case_version == 0
    assert len(s1.evidence) == 0
    assert s1.audit[-1].event_type == "ADMISSION_REJECTED"
