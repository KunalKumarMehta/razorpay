"""Comprehensive tests for evidence admission, Processing Authority Record validation, and fail-closed gates."""

import pytest
from payoutproof.core.models import (
    ProcessingAuthorityRecord,
    PaymentIntent,
    Finding,
    PolicyEvaluationResult,
    RiskCaseState,
)
from payoutproof.admission.validator import AdmissionValidator, MAX_TEXT_SIZE_BYTES
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.core.enums import (
    CasePhase,
    ProcessingAuthorityStatus,
    PolicyOutcome,
    TruthState,
    IntentStatus,
    DestinationStatus,
    ReasonCode,
)
from payoutproof.core.crypto import sha256_hex
from payoutproof.policy.evaluator import PolicyGate
from payoutproof.grants.issuer import GrantIssuer
from tests.helpers import TEST_GRANT_SECRET
from tests.helpers import (
    make_valid_authority_record,
    make_valid_evidence_payload,
    make_authorized_bundle_action,
    make_admitted_case_state,
)


def test_missing_authority_fails_admission():
    valid, err = AdmissionValidator.validate_authority(None)
    assert not valid
    assert "Missing" in err


def test_incomplete_authority_fields_fail():
    # Missing submitter
    incomplete = ProcessingAuthorityRecord(
        data_class="VOICE_NOTE",
        source="WhatsApp",
        subject_category="VENDOR",
        submitter="",
        purpose="Payment investigation",
        asserted_authority_ref="POL-2026",
        permitted_uses=["VERIFY_INTENT"],
        processing_route="LOCAL_ONLY",
        redaction_declaration="SYNTHETIC",
        retention_days=7,
        legal_hold=False,
        restrictions=[],
        is_valid=True,
    )
    valid, err = AdmissionValidator.validate_authority(incomplete)
    assert not valid
    assert "Submitter" in err

    # Marked invalid
    invalid_record = make_valid_authority_record(is_valid=False)
    valid, err = AdmissionValidator.validate_authority(invalid_record)
    assert not valid
    assert "marked invalid" in err


def test_missing_permitted_uses_route_and_redaction_fail():
    # Empty permitted uses
    no_uses = make_valid_authority_record(permitted_uses=[])
    valid, err = AdmissionValidator.validate_authority(no_uses)
    assert not valid
    assert "permitted uses" in err.lower()

    # Empty processing route
    no_route = make_valid_authority_record(processing_route="")
    valid, err = AdmissionValidator.validate_authority(no_route)
    assert not valid
    assert "route" in err.lower()

    # Empty redaction declaration
    no_redaction = make_valid_authority_record(redaction_declaration="")
    valid, err = AdmissionValidator.validate_authority(no_redaction)
    assert not valid
    assert "redaction" in err.lower()


def test_retention_validation():
    # Zero or negative retention via pydantic or validator
    with pytest.raises(Exception):
        make_valid_authority_record(retention_days=0)

    with pytest.raises(Exception):
        make_valid_authority_record(retention_days=-5)

    # Overly long retention (> 365 days)
    with pytest.raises(Exception):
        make_valid_authority_record(retention_days=366)

    # Valid bounded retention
    bounded = make_valid_authority_record(retention_days=30)
    valid, err = AdmissionValidator.validate_authority(bounded)
    assert valid
    assert err is None


def test_valid_authority_succeeds():
    authority = make_valid_authority_record()
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
    assert s1.policy.outcome is None
    assert s1.grant is None
    assert s1.audit[-1].event_type == "ADMISSION_REJECTED"
    assert s1.audit[-1].details["reason_code"] == ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE.value


def test_previously_reproduced_admission_without_par_ends_rejected():
    """Calling ADMIT_AUTHORIZED_BUNDLE without PAR now ends ADMISSION_REJECTED with zero evidence and policy outcome None."""
    s0 = StateMachine.initial_state(case_id="RC-PROBE-01")
    # Empty payload probe (previously defaulted)
    s1 = StateMachine.reduce(s0, {"type": "ADMIT_AUTHORIZED_BUNDLE", "payload": {}})

    assert s1.phase == CasePhase.ADMISSION_REJECTED
    assert s1.case_version == 0
    assert len(s1.evidence) == 0
    assert s1.policy.outcome is None
    assert s1.grant is None
    assert s1.processing_authority in (ProcessingAuthorityStatus.INCOMPLETE, ProcessingAuthorityStatus.REJECTED)
    assert s1.request_bundle_status == "REJECTED"
    assert s1.audit[-1].event_type == "ADMISSION_REJECTED"
    assert s1.audit[-1].details["reason_code"] == ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE.value


def test_empty_disallowed_oversized_payload_rejection():
    s0 = StateMachine.initial_state(case_id="RC-PAYLOAD-01")

    # 1. Empty payload content
    act_empty = make_authorized_bundle_action(
        case_id="RC-PAYLOAD-01",
        evidence={"content": "", "mime_type": "text/plain"},
    )
    s_empty = StateMachine.reduce(s0, act_empty)
    assert s_empty.phase == CasePhase.ADMISSION_REJECTED
    assert s_empty.audit[-1].details["reason_code"] == ReasonCode.MALFORMED_INPUT.value

    # 2. Disallowed MIME type
    act_disallowed = make_authorized_bundle_action(
        case_id="RC-PAYLOAD-01",
        evidence={"content": "malicious executable script", "mime_type": "application/x-sh"},
    )
    s_disallowed = StateMachine.reduce(s0, act_disallowed)
    assert s_disallowed.phase == CasePhase.ADMISSION_REJECTED
    assert s_disallowed.audit[-1].details["reason_code"] == ReasonCode.PROHIBITED_INPUT.value

    # 3. Oversized text payload
    huge_text = "A" * (MAX_TEXT_SIZE_BYTES + 1024)
    act_oversized = make_authorized_bundle_action(
        case_id="RC-PAYLOAD-01",
        evidence={"content": huge_text, "mime_type": "text/plain"},
    )
    s_oversized = StateMachine.reduce(s0, act_oversized)
    assert s_oversized.phase == CasePhase.ADMISSION_REJECTED
    assert s_oversized.audit[-1].details["reason_code"] == ReasonCode.MALFORMED_INPUT.value


def test_raw_content_absent_from_persisted_state_and_audit():
    """Raw evidence must never persist in RiskCaseState JSON or audit logs; only hashes and redacted metadata."""
    canary_string = "CANARY_SECRET_RAW_CONTENT_TRANSFER_INR_999999_NEVER_LOG_OR_PERSIST"
    action = make_authorized_bundle_action(
        case_id="RC-CANARY-01",
        evidence=make_valid_evidence_payload(content=canary_string),
    )

    s0 = StateMachine.initial_state(case_id="RC-CANARY-01")
    s1 = StateMachine.reduce(s0, action)

    assert s1.phase == CasePhase.INVESTIGATION
    assert s1.case_version == 1

    # Check state JSON
    state_json = s1.model_dump_json()
    assert canary_string not in state_json, "Raw evidence content was found in RiskCaseState JSON!"

    # Check evidence item
    ev = s1.evidence[0]
    expected_hash = sha256_hex(canary_string.encode("utf-8"))
    assert ev.content_hash == expected_hash
    assert canary_string not in str(ev.metadata)

    # Check audit events
    for event in s1.audit:
        event_str = str(event.model_dump())
        assert canary_string not in event_str, f"Raw evidence content was found in audit event {event.seq}!"

    # Also check rejected admission with canary
    rejected_action = make_authorized_bundle_action(
        case_id="RC-CANARY-02",
        authority=make_valid_authority_record(is_valid=False),
        evidence=make_valid_evidence_payload(content=canary_string),
    )
    s_rej = StateMachine.reduce(s0, rejected_action)
    assert s_rej.phase == CasePhase.ADMISSION_REJECTED
    rej_json = s_rej.model_dump_json()
    assert canary_string not in rej_json, "Raw evidence content found in rejected state JSON!"
    for event in s_rej.audit:
        assert canary_string not in str(event.model_dump()), "Raw evidence found in rejected audit log!"


def test_valid_admission_records_computed_hash_and_opens_case_version_1():
    content = "Legitimate payment instruction for vendor deposit INR 425000"
    expected_hash = sha256_hex(content.encode("utf-8"))

    action = make_authorized_bundle_action(
        case_id="RC-VALID-01",
        evidence=make_valid_evidence_payload(content=content),
    )
    s0 = StateMachine.initial_state(case_id="RC-VALID-01")
    s1 = StateMachine.reduce(s0, action)

    assert s1.phase == CasePhase.INVESTIGATION
    assert s1.case_version == 1
    assert s1.processing_authority == ProcessingAuthorityStatus.VALID
    assert s1.authority_record is not None
    assert s1.authority_record.processing_route == "LOCAL_ONLY_SECURE_PIPELINE"
    assert s1.request_bundle_status == "ADMITTED"
    assert len(s1.evidence) == 1
    assert s1.evidence[0].content_hash == expected_hash
    assert s1.evidence[0].metadata["size_bytes"] == len(content.encode("utf-8"))


def test_refusal_of_extract_evaluate_issue_after_rejection():
    s0 = StateMachine.initial_state(case_id="RC-REJ-REFUSE")
    s_rej = StateMachine.reduce(s0, {"type": "SUBMIT_UNAUTHORIZED_BUNDLE"})
    assert s_rej.phase == CasePhase.ADMISSION_REJECTED

    # EXTRACT_INTENT must fail closed
    s_ext = StateMachine.reduce(s_rej, {"type": "EXTRACT_INTENT"})
    assert "Refused" in s_ext.last_change
    assert s_ext.intent.status == IntentStatus.NOT_EXTRACTED

    # EVALUATE_POLICY must fail closed
    s_eval = StateMachine.reduce(s_rej, {"type": "EVALUATE_POLICY"})
    assert "Refused" in s_eval.last_change
    assert s_eval.policy.outcome is None

    # ISSUE_GRANT must fail closed
    s_grant = StateMachine.reduce(s_rej, {"type": "ISSUE_GRANT"}, grant_secret=TEST_GRANT_SECRET)
    assert "Refused" in s_grant.last_change
    assert s_grant.grant is None


def test_constructed_rejected_state_with_confirmed_intent_never_eligible():
    """Direct PolicyGate evaluation of a REJECTED state never produces ELIGIBLE_FOR_HANDOFF."""
    intent = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        destination_status=DestinationStatus.APPROVED_FOR_COUNTERPARTY,
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        status=IntentStatus.CONFIRMED,
        intent_hash="sample_intent_hash_valid",
    )
    supported_cb = Finding(name="Independent callback", truth_state=TruthState.SUPPORTED, detail="Confirmed")
    supported_da = Finding(name="Destination approval", truth_state=TruthState.SUPPORTED, detail="Approved")

    constructed_rejected_state = RiskCaseState(
        case_id="RC-FORGED-01",
        case_version=0,
        phase=CasePhase.ADMISSION_REJECTED,
        processing_authority=ProcessingAuthorityStatus.REJECTED,
        authority_record=None,
        request_bundle_status="REJECTED",
        intent=intent,
        findings=[supported_cb, supported_da],
        evidence=[],
    )

    eval_result = PolicyGate.evaluate(constructed_rejected_state)
    assert eval_result.outcome is None, f"Expected outcome None but got {eval_result.outcome}"
    assert eval_result.outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF
    assert ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE in eval_result.reasons


def test_direct_grant_issuer_rejects_invalid_authority():
    """Direct GrantIssuer call must reject invalid authority even if caller fabricates an eligible policy outcome."""
    intent = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        status=IntentStatus.CONFIRMED,
        intent_hash="sample_intent_hash_valid",
    )
    forged_eligible_policy = PolicyEvaluationResult(
        outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
        evaluated_intent_hash=intent.intent_hash,
        policy_version="PP-POLICY-V1",
    )

    # 1. State with rejected authority
    rejected_state = RiskCaseState(
        case_id="RC-FORGED-GRANT-01",
        phase=CasePhase.ADMISSION_REJECTED,
        request_bundle_status="REJECTED",
        processing_authority=ProcessingAuthorityStatus.REJECTED,
        intent=intent,
        policy=forged_eligible_policy,
        evidence=[],
    )
    with pytest.raises(ValueError, match="Cannot issue Handoff Grant without valid processing authority"):
        GrantIssuer.issue_grant(rejected_state, secret=TEST_GRANT_SECRET)

    # 2. State missing authority_record
    unadmitted_state = RiskCaseState(
        case_id="RC-FORGED-GRANT-02",
        phase=CasePhase.EVIDENCE_ADMISSION,
        request_bundle_status="NOT_ADMITTED",
        processing_authority=ProcessingAuthorityStatus.NOT_CHECKED,
        intent=intent,
        policy=forged_eligible_policy,
        evidence=[],
    )
    with pytest.raises(ValueError, match="Cannot issue Handoff Grant without valid processing authority"):
        GrantIssuer.issue_grant(unadmitted_state, secret=TEST_GRANT_SECRET)


def test_omitted_route_rejected():
    """Omitting processing_route must cause Admission Rejection without fallback defaults."""
    base_dict = {
        "data_class": "SYNTHETIC_VOICE",
        "source": "WhatsApp",
        "subject_category": "VENDOR",
        "submitter": "Payment Operator",
        "purpose": "Payment verification",
        "asserted_authority_ref": "AUTH-01",
        "permitted_uses": ["PAYMENT_INTENT_EXTRACTION"],
        # omitted processing_route
        "redaction_declaration": "SYNTHETIC_NO_PII",
        "retention_days": 7,
        "legal_hold": False,
        "restrictions": ["NO_TRAINING"],
        "is_valid": True,
    }
    action = make_authorized_bundle_action(
        case_id="RC-OMIT-ROUTE",
        authority=base_dict,
    )
    s0 = StateMachine.initial_state(case_id="RC-OMIT-ROUTE")
    s1 = StateMachine.reduce(s0, action)
    assert s1.phase == CasePhase.ADMISSION_REJECTED
    assert s1.request_bundle_status == "REJECTED"
    assert s1.case_version == 0
    assert len(s1.evidence) == 0
    assert s1.policy.outcome is None


def test_omitted_redaction_declaration_rejected():
    """Omitting redaction_declaration must cause Admission Rejection without fallback defaults."""
    base_dict = {
        "data_class": "SYNTHETIC_VOICE",
        "source": "WhatsApp",
        "subject_category": "VENDOR",
        "submitter": "Payment Operator",
        "purpose": "Payment verification",
        "asserted_authority_ref": "AUTH-01",
        "permitted_uses": ["PAYMENT_INTENT_EXTRACTION"],
        "processing_route": "LOCAL_ONLY",
        # omitted redaction_declaration
        "retention_days": 7,
        "legal_hold": False,
        "restrictions": ["NO_TRAINING"],
        "is_valid": True,
    }
    action = make_authorized_bundle_action(
        case_id="RC-OMIT-REDACTION",
        authority=base_dict,
    )
    s0 = StateMachine.initial_state(case_id="RC-OMIT-REDACTION")
    s1 = StateMachine.reduce(s0, action)
    assert s1.phase == CasePhase.ADMISSION_REJECTED
    assert s1.request_bundle_status == "REJECTED"
    assert s1.case_version == 0
    assert len(s1.evidence) == 0
    assert s1.policy.outcome is None


def test_omitted_retention_legal_hold_restrictions_is_valid_rejected():
    """Omitting any required Issue 09 authority field causes Admission Rejection."""
    base_dict = {
        "data_class": "SYNTHETIC_VOICE",
        "source": "WhatsApp",
        "subject_category": "VENDOR",
        "submitter": "Payment Operator",
        "purpose": "Payment verification",
        "asserted_authority_ref": "AUTH-01",
        "permitted_uses": ["PAYMENT_INTENT_EXTRACTION"],
        "processing_route": "LOCAL_ONLY",
        "redaction_declaration": "SYNTHETIC_NO_PII",
    }
    for omitted_field in ["retention_days", "legal_hold", "restrictions", "is_valid", "permitted_uses"]:
        d = dict(base_dict)
        if omitted_field != "retention_days":
            d["retention_days"] = 7
        if omitted_field != "legal_hold":
            d["legal_hold"] = False
        if omitted_field != "restrictions":
            d["restrictions"] = []
        if omitted_field != "is_valid":
            d["is_valid"] = True
        if omitted_field == "permitted_uses":
            del d["permitted_uses"]

        action = make_authorized_bundle_action(
            case_id=f"RC-OMIT-{omitted_field}",
            authority=d,
        )
        s0 = StateMachine.initial_state(case_id=f"RC-OMIT-{omitted_field}")
        s1 = StateMachine.reduce(s0, action)
        assert s1.phase == CasePhase.ADMISSION_REJECTED
        assert s1.request_bundle_status == "REJECTED"
        assert s1.case_version == 0
        assert len(s1.evidence) == 0
        assert s1.policy.outcome is None


def test_missing_case_id_rejected_and_no_fallback_assigned():
    """Omitting case_id on initial state and payload must reject without assigning RC-DEMO-042."""
    s0 = StateMachine.initial_state(case_id=None)
    assert s0.case_id is None

    action = {
        "type": "ADMIT_AUTHORIZED_BUNDLE",
        "payload": {
            "processing_authority": make_valid_authority_record().model_dump(),
            "evidence": make_valid_evidence_payload(),
        },
    }
    s1 = StateMachine.reduce(s0, action)
    assert s1.phase == CasePhase.ADMISSION_REJECTED
    assert s1.request_bundle_status == "REJECTED"
    assert s1.case_id is None
    assert s1.case_version == 0
    assert len(s1.evidence) == 0
    assert s1.policy.outcome is None
    assert s1.audit[-1].event_type == "ADMISSION_REJECTED"
    assert s1.audit[-1].details["reason_code"] == ReasonCode.MALFORMED_INPUT.value
    assert "RC-DEMO-042" not in s1.model_dump_json()


def test_malformed_authority_canary_not_persisted_in_state_or_audit():
    """Malformed authority values containing canaries must never leak into RiskCaseState JSON or audit logs."""
    canary = "SECRET_AUTH_CANARY_VALUE_98765"
    s0 = StateMachine.initial_state(case_id="RC-CANARY-AUTH")

    malformed_payload = {
        "data_class": "SYNTHETIC_VOICE",
        "source": "WhatsApp",
        "subject_category": "VENDOR",
        "submitter": "Payment Operator",
        "purpose": "Payment verification",
        "asserted_authority_ref": canary,
        "permitted_uses": ["PAYMENT_INTENT_EXTRACTION"],
        "processing_route": "LOCAL_ONLY",
        "redaction_declaration": "SYNTHETIC_NO_PII",
        "retention_days": "CANARY_CORRUPTED_INT",
        "legal_hold": False,
        "restrictions": [],
        "is_valid": True,
    }

    action = {
        "type": "ADMIT_AUTHORIZED_BUNDLE",
        "payload": {
            "case_id": "RC-CANARY-AUTH",
            "processing_authority": malformed_payload,
            "evidence": make_valid_evidence_payload(),
        },
    }

    s1 = StateMachine.reduce(s0, action)
    assert s1.phase == CasePhase.ADMISSION_REJECTED
    assert s1.request_bundle_status == "REJECTED"

    state_json = s1.model_dump_json()
    assert canary not in state_json, "Authority canary leaked into rejected state JSON!"
    assert "CANARY_CORRUPTED_INT" not in state_json, "Pydantic raw error value leaked into rejected state JSON!"

    for ev in s1.audit:
        ev_str = str(ev.model_dump())
        assert canary not in ev_str, f"Authority canary found in audit event {ev.seq}!"
        assert "CANARY_CORRUPTED_INT" not in ev_str, f"Pydantic error found in audit event {ev.seq}!"


def test_caller_title_and_filename_canaries_not_persisted():
    """Caller-provided title, filename, and raw content canaries must never persist in state or audit."""
    content_canary = "CANARY_EVIDENCE_BODY_SECRET_111"
    title_canary = "CANARY_CALLER_TITLE_SECRET_222"
    filename_canary = "CANARY_CALLER_FILENAME_SECRET_333.pdf"

    action = {
        "type": "ADMIT_AUTHORIZED_BUNDLE",
        "payload": {
            "case_id": "RC-SAFE-ATTRS-01",
            "processing_authority": make_valid_authority_record().model_dump(),
            "evidence": {
                "content": content_canary,
                "mime_type": "text/plain",
                "title": title_canary,
                "filename": filename_canary,
            },
            "title": title_canary,
            "filename": filename_canary,
        },
    }

    s0 = StateMachine.initial_state(case_id="RC-SAFE-ATTRS-01")
    s1 = StateMachine.reduce(s0, action)

    assert s1.phase == CasePhase.INVESTIGATION
    assert s1.case_version == 1
    assert s1.request_bundle_status == "ADMITTED"
    assert len(s1.evidence) == 1

    # Check evidence item
    ev = s1.evidence[0]
    assert ev.title == "Admitted Evidence"
    assert ev.content_hash == sha256_hex(content_canary.encode("utf-8"))
    assert "filename" not in ev.metadata

    state_json = s1.model_dump_json()
    assert content_canary not in state_json
    assert title_canary not in state_json
    assert filename_canary not in state_json

    for audit_ev in s1.audit:
        dumped = str(audit_ev.model_dump())
        assert content_canary not in dumped
        assert title_canary not in dumped
        assert filename_canary not in dumped


def test_valid_explicit_input_succeeds_fully():
    """Fully specified valid ProcessingAuthorityRecord and evidence opens case version 1."""
    auth = make_valid_authority_record(
        permitted_uses=["PAYMENT_INTENT_EXTRACTION", "POLICY_GATE_EVALUATION"],
        processing_route="LOCAL_ONLY_SECURE_PIPELINE",
        redaction_declaration="SYNTHETIC_DATA_NO_REAL_PII",
        retention_days=14,
        legal_hold=False,
        restrictions=["NO_EXTERNAL_TRANSMISSION"],
        is_valid=True,
    )
    action = make_authorized_bundle_action(
        case_id="RC-EXPLICIT-01",
        authority=auth,
        evidence=make_valid_evidence_payload(content="Valid instruction content"),
    )
    s0 = StateMachine.initial_state(case_id="RC-EXPLICIT-01")
    s1 = StateMachine.reduce(s0, action)

    assert s1.phase == CasePhase.INVESTIGATION
    assert s1.case_version == 1
    assert s1.processing_authority == ProcessingAuthorityStatus.VALID
    assert s1.authority_record is not None
    assert s1.authority_record.retention_days == 14
    assert s1.request_bundle_status == "ADMITTED"
    assert len(s1.evidence) == 1
