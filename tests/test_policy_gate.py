"""Tests for deterministic Policy Gate rules and outcomes."""

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
)
from payoutproof.policy.evaluator import PolicyGate


def test_contradiction_forces_hold():
    intent = PaymentIntent(
        counterparty="Kaveri",
        destination="HDFC ••4821",
        amount="425000",
        status=IntentStatus.CONFIRMED,
        intent_hash="hash123",
    )
    state = RiskCaseState(
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
    intent = PaymentIntent(
        counterparty="Kaveri",
        destination="HDFC ••4821",
        destination_status=DestinationStatus.UNAPPROVED,
        amount="425000",
        status=IntentStatus.CONFIRMED,
        intent_hash="hash123",
    )
    state = RiskCaseState(
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
    intent = PaymentIntent(
        counterparty="Kaveri",
        destination="HDFC ••4821",
        destination_status=DestinationStatus.APPROVED_FOR_COUNTERPARTY,
        amount="425000",
        status=IntentStatus.CONFIRMED,
        intent_hash="hash123",
    )
    state = RiskCaseState(
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
