"""Tests for deterministic Policy Gate rules, outcomes, and fail-closed admission checks."""

import pytest
from payoutproof.core.models import (
    RiskCaseState,
    PaymentIntent,
    Finding,
    CaseInvestigation,
)
from payoutproof.core.enums import (
    PolicyOutcome,
    TruthState,
    IntentStatus,
    DestinationStatus,
    ReasonCode,
    CasePhase,
    ProcessingAuthorityStatus,
)
from payoutproof.policy.evaluator import PolicyGate
from tests.helpers import make_admitted_case_state, make_confirmed_intent
from payoutproof.core.crypto import compute_snapshot_hash


def test_contradiction_forces_hold():
    intent = make_confirmed_intent(
        counterparty="Kaveri",
        destination="HDFC ••4821",
        amount="425000",
    )
    state = make_admitted_case_state(
        case_id="RC-001",
        intent=intent,
        findings=[
            Finding(name="Destination consistency", truth_state=TruthState.CONTRADICTED, detail="Invoice mismatch"),
        ],
    )
    result = PolicyGate.evaluate(state)
    assert result.outcome == PolicyOutcome.HOLD
    assert ReasonCode.MATERIAL_EVIDENCE_CONTRADICTION in result.reasons


def test_unapproved_destination_requires_step_up():
    intent = make_confirmed_intent(
        counterparty="Kaveri",
        destination="HDFC ••4821",
        destination_status=DestinationStatus.UNAPPROVED,
        amount="425000",
    )
    state = make_admitted_case_state(
        case_id="RC-001",
        intent=intent,
        findings=[
            Finding(name="Independent callback", truth_state=TruthState.SUPPORTED, detail="Confirmed"),
        ],
    )
    result = PolicyGate.evaluate(state)
    assert result.outcome == PolicyOutcome.STEP_UP_REQUIRED
    assert ReasonCode.UNAPPROVED_DESTINATION in result.reasons


def test_full_evidence_produces_eligible():
    intent = make_confirmed_intent(
        counterparty="Kaveri",
        destination="HDFC ••4821",
        destination_status=DestinationStatus.APPROVED_FOR_COUNTERPARTY,
        amount="425000",
    )
    state = make_admitted_case_state(
        case_id="RC-001",
        intent=intent,
        findings=[
            Finding(name="Independent callback", truth_state=TruthState.SUPPORTED, detail="Confirmed"),
            Finding(name="Destination approval", truth_state=TruthState.SUPPORTED, detail="Approved"),
        ],
    )
    result = PolicyGate.evaluate(state)
    assert result.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
    assert ReasonCode.REQUIRED_EVIDENCE_SATISFIED in result.reasons
    assert ReasonCode.EXACT_INTENT_FROZEN in result.reasons
    assert result.expires_at is not None
    assert result.evaluated_snapshot_hash == compute_snapshot_hash(state)


def test_confirmed_intent_hash_mismatch_produces_protective_hold():
    """Confirmed intent whose fields differ from stored intent_hash must never be ELIGIBLE_FOR_HANDOFF."""
    intent = make_confirmed_intent(
        counterparty="Kaveri",
        destination="HDFC ••4821",
        destination_status=DestinationStatus.APPROVED_FOR_COUNTERPARTY,
        amount="425000",
    )
    # Mutate amount without updating hash
    mutated = intent.model_copy(update={"amount": "999999"})
    state = make_admitted_case_state(
        case_id="RC-001",
        intent=mutated,
        findings=[
            Finding(name="Independent callback", truth_state=TruthState.SUPPORTED, detail="Confirmed"),
            Finding(name="Destination approval", truth_state=TruthState.SUPPORTED, detail="Approved"),
        ],
    )
    result = PolicyGate.evaluate(state)
    assert result.outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF
    assert result.outcome == PolicyOutcome.HOLD
    assert ReasonCode.MATERIAL_INTENT_CHANGED in result.reasons
    assert result.evaluated_snapshot_hash is None


def test_unadmitted_or_rejected_state_evaluates_to_none():
    """PolicyGate evaluation of non-admitted/rejected/invalid authority produces outcome None, never ELIGIBLE."""
    intent = make_confirmed_intent(
        counterparty="Kaveri",
        destination="HDFC ••4821",
        destination_status=DestinationStatus.APPROVED_FOR_COUNTERPARTY,
        amount="425000",
    )
    supported_cb = Finding(name="Independent callback", truth_state=TruthState.SUPPORTED, detail="Confirmed")
    supported_da = Finding(name="Destination approval", truth_state=TruthState.SUPPORTED, detail="Approved")

    # 1. Unadmitted state
    unadmitted = RiskCaseState(
        case_id="RC-GATE-UNADMITTED",
        request_bundle_status="NOT_ADMITTED",
        intent=intent,
        findings=[supported_cb, supported_da],
    )
    res_unadmitted = PolicyGate.evaluate(unadmitted)
    assert res_unadmitted.outcome is None
    assert ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE in res_unadmitted.reasons

    # 2. Rejected state
    rejected = RiskCaseState(
        case_id="RC-GATE-REJECTED",
        phase=CasePhase.ADMISSION_REJECTED,
        processing_authority=ProcessingAuthorityStatus.REJECTED,
        request_bundle_status="REJECTED",
        intent=intent,
        findings=[supported_cb, supported_da],
    )
    res_rejected = PolicyGate.evaluate(rejected)
    assert res_rejected.outcome is None
    assert ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE in res_rejected.reasons
